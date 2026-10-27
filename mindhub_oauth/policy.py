"""JSON-RPC tool scope policy and parser-differential defenses."""
from __future__ import annotations

import json
import math
import re
from typing import Any

ALLOWED_METHODS = frozenset({
    "initialize",
    "ping",
    "tools/list",
    "tools/call",
    "notifications/initialized",
    "notifications/cancelled",
})

READ_TOOLS = frozenset({
    "search_memory",
    "get_project_state",
    "get_project_state_history",
})

WRITE_TOOLS = READ_TOOLS | frozenset({
    "remember",
    "update_project_state",
})


class PolicyParseError(ValueError):
    """Raised when JSON parsing fails or duplicate keys/BOM are detected."""
    pass


class PolicyLimitExceeded(ValueError):
    """Raised when JSON depth or array length limits are exceeded."""
    pass


def _reject_constant(val: str) -> None:
    """Reject NaN, Infinity, -Infinity constants in JSON."""
    raise PolicyParseError(f"Unsupported constant: {val}")


def sanitize_echo_string(s: Any, max_len: int = 64) -> str:
    """Sanitize client-supplied string echoed in error messages.

    Limits to max_len characters and replaces non-printable and non-ASCII chars with '?'.
    """
    if not isinstance(s, str):
        s = str(s)
    clean = []
    for ch in s[:max_len]:
        if 32 <= ord(ch) <= 126:
            clean.append(ch)
        else:
            clean.append("?")
    return "".join(clean)


def _reject_duplicate_keys_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Dict constructor that rejects duplicate keys."""
    res: dict[str, Any] = {}
    for k, v in pairs:
        if k in res:
            raise PolicyParseError(f"Duplicate key detected: {k!r}")
        res[k] = v
    return res


def _check_depth_and_array_limits(
    obj: Any,
    current_depth: int = 1,
    max_depth: int = 32,
    max_array_length: int = 50,
) -> None:
    """Validate structure limits recursively."""
    if current_depth > max_depth:
        raise PolicyLimitExceeded(f"Nesting depth {current_depth} exceeds maximum of {max_depth}")

    if isinstance(obj, list):
        if len(obj) > max_array_length:
            raise PolicyLimitExceeded(
                f"Array length {len(obj)} exceeds maximum of {max_array_length}"
            )
        for item in obj:
            _check_depth_and_array_limits(
                item,
                current_depth=current_depth + 1,
                max_depth=max_depth,
                max_array_length=max_array_length,
            )
    elif isinstance(obj, dict):
        for val in obj.values():
            _check_depth_and_array_limits(
                val,
                current_depth=current_depth + 1,
                max_depth=max_depth,
                max_array_length=max_array_length,
            )


def _parse_float(s: str) -> float:
    """Parse float, raising PolicyParseError if value is non-finite."""
    val = float(s)
    if not math.isfinite(val):
        raise PolicyParseError(f"Non-finite float value: {s}")
    return val


def parse_and_validate_json(
    raw_bytes: bytes,
    max_depth: int = 32,
    max_array_length: int = 50,
) -> Any:
    """Parse JSON body with strict UTF-8, no BOM, no duplicate keys, and bounded limits."""
    # Cheap pre-scan: reject bodies with more than 64 consecutive '[' or '{' openers before json.loads
    if re.search(rb"(\[{65,}|\{{65,})", raw_bytes):
        raise PolicyLimitExceeded("More than 64 consecutive openers detected")

    # Strict UTF-8 BOM check
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise PolicyParseError("UTF-8 BOM is not permitted")

    # Strict UTF-8 decoding (no UTF-16/32 autodetection)
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyParseError(f"Invalid UTF-8 encoding: {exc}") from exc

    # Parse JSON rejecting duplicate keys and NaN/Infinity/-Infinity
    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys_hook,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
        )
    except json.JSONDecodeError as exc:
        raise PolicyParseError(f"JSON decode error: {exc}") from exc

    # Validate limits
    _check_depth_and_array_limits(
        data,
        current_depth=1,
        max_depth=max_depth,
        max_array_length=max_array_length,
    )
    return data


def evaluate_message(msg: Any, token_scopes: set[str]) -> tuple[str, Any]:
    """Evaluate a single JSON-RPC message against method allowlist and tool scope policy.

    Returns (action, payload):
    - ('allow', None): method and parameters are permitted.
    - ('error', dict): JSON-RPC error response dict.
    - ('drop_202', None): notification or client response dropped without error.
    - ('parse_error', dict): invalid JSON-RPC message format (HTTP 400).
    """
    if not isinstance(msg, dict):
        return (
            "parse_error",
            {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: message must be an object"},
            },
        )

    has_method = "method" in msg
    has_id = "id" in msg
    msg_id = msg.get("id")

    # Client responses: has result/error and no method -> drop with 202
    if not has_method:
        if "result" in msg or "error" in msg:
            return ("drop_202", None)
        if has_id:
            return (
                "error",
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32600, "message": "Invalid Request: missing method"},
                },
            )
        return ("drop_202", None)

    method = msg.get("method")
    if not isinstance(method, str):
        if has_id:
            return (
                "error",
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32600, "message": "Invalid method name"},
                },
            )
        return ("drop_202", None)

    # Method allowlist check (case-sensitive)
    if method not in ALLOWED_METHODS:
        if has_id:
            safe_method = sanitize_echo_string(method)
            return (
                "error",
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32601, "message": f"Method not found: {safe_method}"},
                },
            )
        # Notifications outside allowlist are dropped with 202
        return ("drop_202", None)

    # Allowlisted method: if tools/call, check tool scope policy
    if method == "tools/call":
        params = msg.get("params")
        if not isinstance(params, dict):
            return (
                "error",
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32001, "message": "tools/call requires params object"},
                },
            )

        tool_name = params.get("name")
        if not isinstance(tool_name, str):
            return (
                "error",
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32001, "message": "tools/call requires tool name string"},
                },
            )

        # Determine permitted tools for token scope
        if "mindhub:write" in token_scopes:
            permitted = WRITE_TOOLS
        elif "mindhub:read" in token_scopes:
            permitted = READ_TOOLS
        else:
            permitted = frozenset()

        if tool_name not in permitted:
            return (
                "error",
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32001,
                        "message": "tool not permitted for this token's scope",
                    },
                },
            )

    return ("allow", None)


def evaluate_policy(
    raw_bytes: bytes,
    token_scope: str,
) -> tuple[int, bytes | dict | list | None, str]:
    """Evaluates request body bytes against parser defenses and scope policy.

    Returns (status_code, body, action):
    - (200, reserialized_bytes, 'forward'): request is permitted and re-serialized.
    - (200, error_dict_or_list, 'respond'): policy denied tools/call or method not found.
    - (202, None, 'respond'): notification or response dropped.
    - (400, error_dict, 'respond'): parse error, duplicate keys, or depth/array limit exceeded.
    """
    try:
        data = parse_and_validate_json(raw_bytes)
    except (PolicyParseError, PolicyLimitExceeded, ValueError, RecursionError) as exc:
        err = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": f"Parse error: {sanitize_echo_string(str(exc))}"},
        }
        return (400, err, "respond")

    scopes = set(token_scope.split())

    # Batch request handling
    if isinstance(data, list):
        if not data:
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: empty batch"},
            }
            return (400, err, "respond")

        batch_errors: list[dict[str, Any]] = []
        any_denied = False
        allowed_items: list[dict[str, Any]] = []

        for item in data:
            action, payload = evaluate_message(item, scopes)
            if action == "allow":
                allowed_items.append(item)
            elif action == "drop_202":
                pass
            elif action in ("error", "parse_error"):
                any_denied = True
                batch_errors.append(payload)

        if any_denied:
            # Per §8.3 / M4-3: if any element is denied, deny the whole batch and do NOT forward.
            return (200, batch_errors, "respond")

        if not allowed_items:
            return (202, None, "respond")

        # Re-serialize clean batch containing ONLY allowed elements
        serialized = json.dumps(allowed_items, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return (200, serialized, "forward")

    # Single message handling
    elif isinstance(data, dict):
        action, payload = evaluate_message(data, scopes)
        if action == "allow":
            serialized = json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            return (200, serialized, "forward")
        elif action == "error":
            return (200, payload, "respond")
        elif action == "drop_202":
            return (202, None, "respond")
        else:  # parse_error
            return (400, payload, "respond")

    else:
        err = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request: expected object or array"},
        }
        return (400, err, "respond")
