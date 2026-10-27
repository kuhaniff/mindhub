"""Unit tests for mindhub_oauth.policy."""
from __future__ import annotations

import json
import unittest

from mindhub_oauth.policy import (
    ALLOWED_METHODS,
    evaluate_policy,
    parse_and_validate_json,
    PolicyLimitExceeded,
    PolicyParseError,
    READ_TOOLS,
    WRITE_TOOLS,
)


class TestOAuthPolicy(unittest.TestCase):
    def test_duplicate_key_json_rejected(self) -> None:
        raw = b'{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}'
        status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
        self.assertEqual(status, 400)
        self.assertEqual(action, "respond")
        self.assertIsInstance(body, dict)
        self.assertEqual(body["error"]["code"], -32700)
        self.assertIn("Duplicate key", body["error"]["message"])

    def test_duplicate_key_nested_rejected(self) -> None:
        raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_memory","name":"remember"}}'
        status, body, action = evaluate_policy(raw, token_scope="mindhub:write")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], -32700)

    def test_utf8_bom_rejected(self) -> None:
        raw = b'\xef\xbb\xbf{"jsonrpc":"2.0","id":1,"method":"ping"}'
        status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], -32700)
        self.assertIn("BOM", body["error"]["message"])

    def test_invalid_utf8_encoding_rejected(self) -> None:
        raw = b'{"jsonrpc":"2.0","id":1,"method":"\xff\xfe"}'
        status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], -32700)

    def test_nesting_depth_limit_32_rejected(self) -> None:
        # Create structure with depth > 32
        curr: dict = {"key": "leaf"}
        for _ in range(35):
            curr = {"nest": curr}
        raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": curr}).encode()
        status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], -32700)
        self.assertIn("depth", body["error"]["message"].lower())

    def test_array_length_limit_50_rejected(self) -> None:
        # Array with 51 items
        items = [{"jsonrpc": "2.0", "id": i, "method": "ping"} for i in range(51)]
        raw = json.dumps(items).encode()
        status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], -32700)
        self.assertIn("array length", body["error"]["message"].lower())

    def test_method_allowlist_permitted(self) -> None:
        for m in ["initialize", "ping", "tools/list", "notifications/initialized", "notifications/cancelled"]:
            raw = json.dumps({"jsonrpc": "2.0", "id": 1, "method": m}).encode()
            status, forward_bytes, action = evaluate_policy(raw, token_scope="mindhub:read")
            self.assertEqual(status, 200)
            self.assertEqual(action, "forward")
            self.assertIsInstance(forward_bytes, bytes)
            # Must be re-serialized clean JSON
            parsed = json.loads(forward_bytes.decode())
            self.assertEqual(parsed["method"], m)

    def test_non_allowlisted_methods_with_id_get_32601(self) -> None:
        # Per M4-2 / M4-6: resources/list, resources/read, prompts/list, prompts/get, tasks/*, completion/complete, logging/setLevel
        forbidden = [
            "resources/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
            "tasks/get",
            "tasks/create",
            "completion/complete",
            "logging/setLevel",
            "custom/method",
        ]
        for m in forbidden:
            raw = json.dumps({"jsonrpc": "2.0", "id": 42, "method": m}).encode()
            status, body, action = evaluate_policy(raw, token_scope="mindhub:write")
            self.assertEqual(status, 200)
            self.assertEqual(action, "respond")
            self.assertEqual(body["id"], 42)
            self.assertEqual(body["error"]["code"], -32601)
            self.assertIn("Method not found", body["error"]["message"])

    def test_non_allowlisted_notifications_without_id_return_202(self) -> None:
        # Notifications without id outside allowlist (e.g. notifications/progress) are dropped with 202
        forbidden_notifs = [
            "notifications/progress",
            "notifications/message",
            "notifications/roots/list_changed",
            "unknown/notification",
        ]
        for m in forbidden_notifs:
            raw = json.dumps({"jsonrpc": "2.0", "method": m}).encode()
            status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
            self.assertEqual(status, 202)
            self.assertEqual(action, "respond")
            self.assertIsNone(body)

    def test_client_response_dropped_with_202(self) -> None:
        # Message with result/error and no method
        raw1 = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"data": "test"}}).encode()
        status1, body1, action1 = evaluate_policy(raw1, token_scope="mindhub:read")
        self.assertEqual(status1, 202)
        self.assertEqual(action1, "respond")

        raw2 = json.dumps({"jsonrpc": "2.0", "id": 2, "error": {"code": -32000, "message": "fail"}}).encode()
        status2, body2, action2 = evaluate_policy(raw2, token_scope="mindhub:read")
        self.assertEqual(status2, 202)
        self.assertEqual(action2, "respond")

    def test_read_token_scope_tool_policy(self) -> None:
        # Read-only token permits search_memory, get_project_state, get_project_state_history
        for tool in ["search_memory", "get_project_state", "get_project_state_history"]:
            raw = json.dumps({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": tool, "arguments": {}},
            }).encode()
            status, forward_bytes, action = evaluate_policy(raw, token_scope="mindhub:read")
            self.assertEqual(status, 200)
            self.assertEqual(action, "forward")

        # Read-only token calling remember or update_project_state -> -32001
        for tool in ["remember", "update_project_state", "nonexistent_tool"]:
            raw = json.dumps({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": tool, "arguments": {}},
            }).encode()
            status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
            self.assertEqual(status, 200)
            self.assertEqual(action, "respond")
            self.assertEqual(body["id"], 11)
            self.assertEqual(body["error"]["code"], -32001)
            self.assertIn("not permitted", body["error"]["message"])

    def test_write_token_scope_permits_all_5_tools(self) -> None:
        all_tools = ["search_memory", "get_project_state", "get_project_state_history", "remember", "update_project_state"]
        for tool in all_tools:
            raw = json.dumps({
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {"name": tool, "arguments": {}},
            }).encode()
            status, forward_bytes, action = evaluate_policy(raw, token_scope="mindhub:read mindhub:write")
            self.assertEqual(status, 200)
            self.assertEqual(action, "forward")

    def test_batch_all_permitted_forwarded(self) -> None:
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "search_memory"}},
        ]
        raw = json.dumps(batch).encode()
        status, forward_bytes, action = evaluate_policy(raw, token_scope="mindhub:read")
        self.assertEqual(status, 200)
        self.assertEqual(action, "forward")
        parsed = json.loads(forward_bytes.decode())
        self.assertEqual(len(parsed), 2)

    def test_batch_any_denied_denies_whole_batch(self) -> None:
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "search_memory"}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "remember"}},
        ]
        raw = json.dumps(batch).encode()
        # With read-only token: remember is denied -> entire batch is denied!
        status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
        self.assertEqual(status, 200)
        self.assertEqual(action, "respond")
        self.assertIsInstance(body, list)
        self.assertTrue(any(err["id"] == 2 and err["error"]["code"] == -32001 for err in body))

    def test_reserialized_bytes_exact_format(self) -> None:
        # Non-canonical formatting with extra spaces and newlines
        messy_json = b'{\n  "jsonrpc" :  "2.0" ,\n  "id" : 100 ,\n  "method" : "ping"\n}'
        status, forward_bytes, action = evaluate_policy(messy_json, token_scope="mindhub:read")
        self.assertEqual(status, 200)
        self.assertEqual(action, "forward")
        # separators=(',', ':') with ensure_ascii=True has no whitespace
        expected = b'{"jsonrpc":"2.0","id":100,"method":"ping"}'
        self.assertEqual(forward_bytes, expected)

    def test_lone_surrogates_and_non_bmp_canonical_ascii_reserialization(self) -> None:
        # 1. Lone surrogate in string value
        raw1 = br'{"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"val": "\ud800"}}'
        status1, forward_bytes1, action1 = evaluate_policy(raw1, token_scope="mindhub:read")
        self.assertEqual(status1, 200)
        self.assertEqual(action1, "forward")
        self.assertIsInstance(forward_bytes1, bytes)
        self.assertTrue(forward_bytes1.isascii())
        self.assertEqual(forward_bytes1, b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"val":"\\ud800"}}')

        # 2. Lone surrogate in key
        raw2 = br'{"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {"\ud800": "val"}}'
        status2, forward_bytes2, action2 = evaluate_policy(raw2, token_scope="mindhub:read")
        self.assertEqual(status2, 200)
        self.assertEqual(action2, "forward")
        self.assertIsInstance(forward_bytes2, bytes)
        self.assertTrue(forward_bytes2.isascii())
        self.assertEqual(forward_bytes2, b'{"jsonrpc":"2.0","id":2,"method":"ping","params":{"\\ud800":"val"}}')

        # 3. Lone surrogate in params.name
        raw3 = br'{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "search_memory\ud800"}}'
        status3, body3, action3 = evaluate_policy(raw3, token_scope="mindhub:read")
        self.assertEqual(status3, 200)
        self.assertEqual(action3, "respond")
        self.assertEqual(body3["error"]["code"], -32001)
        self.assertIn("not permitted", body3["error"]["message"])

        # 4. Non-BMP character (e.g. emoji U+1F600)
        raw4 = br'{"jsonrpc": "2.0", "id": 4, "method": "ping", "params": {"emoji": "\ud83d\ude00"}}'
        status4, forward_bytes4, action4 = evaluate_policy(raw4, token_scope="mindhub:read")
        self.assertEqual(status4, 200)
        self.assertEqual(action4, "forward")
        self.assertIsInstance(forward_bytes4, bytes)
        self.assertTrue(forward_bytes4.isascii())
        self.assertEqual(forward_bytes4, b'{"jsonrpc":"2.0","id":4,"method":"ping","params":{"emoji":"\\ud83d\\ude00"}}')

    def test_params_name_normalized_escapes_compared_after_parsing(self) -> None:
        # Escape sequence that normalizes to allowed tool name: \u0073earch_memory -> 'search_memory'
        raw1 = br'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "\u0073earch_memory"}}'
        status1, forward_bytes1, action1 = evaluate_policy(raw1, token_scope="mindhub:read")
        self.assertEqual(status1, 200)
        self.assertEqual(action1, "forward")
        # After parsing, tool name is compared as "search_memory", so it is allowed!
        parsed = json.loads(forward_bytes1.decode("ascii"))
        self.assertEqual(parsed["params"]["name"], "search_memory")

        # Escape sequence that normalizes to denied tool name: \u0072emember -> 'remember'
        raw2 = br'{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "\u0072emember"}}'
        status2, body2, action2 = evaluate_policy(raw2, token_scope="mindhub:read")
        self.assertEqual(status2, 200)
        self.assertEqual(action2, "respond")
        # Read-only token denies 'remember' with -32001
        self.assertEqual(body2["error"]["code"], -32001)

    def test_p1_batch_rebuild_drops_non_allowed_and_never_forwards_dropped(self) -> None:
        # Batch with [ping, notification "resources/subscribe"]
        batch1 = [
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "method": "resources/subscribe", "params": {"uri": "file:///test"}},
        ]
        status1, forward_bytes1, action1 = evaluate_policy(json.dumps(batch1).encode(), token_scope="mindhub:read")
        self.assertEqual(status1, 200)
        self.assertEqual(action1, "forward")
        parsed1 = json.loads(forward_bytes1.decode("utf-8"))
        # Must contain ONLY ping
        self.assertEqual(len(parsed1), 1)
        self.assertEqual(parsed1[0]["method"], "ping")

        # Batch with [ping, client response {"id":1,"result":{}}]
        batch2 = [
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
            {"jsonrpc": "2.0", "id": 1, "result": {}},
        ]
        status2, forward_bytes2, action2 = evaluate_policy(json.dumps(batch2).encode(), token_scope="mindhub:read")
        self.assertEqual(status2, 200)
        self.assertEqual(action2, "forward")
        parsed2 = json.loads(forward_bytes2.decode("utf-8"))
        self.assertEqual(len(parsed2), 1)
        self.assertEqual(parsed2[0]["id"], 2)

        # Batch with ONLY dropped elements -> returns 202
        batch3 = [
            {"jsonrpc": "2.0", "method": "resources/subscribe"},
            {"jsonrpc": "2.0", "id": 1, "result": {}},
        ]
        status3, body3, action3 = evaluate_policy(json.dumps(batch3).encode(), token_scope="mindhub:read")
        self.assertEqual(status3, 202)
        self.assertIsNone(body3)

    def test_p2_parse_safety_integer_limit_and_recursion_limit(self) -> None:
        # 5000-digit integer causes ValueError in Python 3.11+
        raw_int = ('{"jsonrpc":"2.0","id":1,"method":"ping","params":{"big":' + ("9" * 5000) + '}}').encode()
        status1, body1, action1 = evaluate_policy(raw_int, token_scope="mindhub:read")
        self.assertEqual(status1, 400)
        self.assertEqual(body1["error"]["code"], -32700)

        # 100000 nested '[' caught by cheap pre-scan without crashing
        raw_nested = b"[" * 100000
        status2, body2, action2 = evaluate_policy(raw_nested, token_scope="mindhub:read")
        self.assertEqual(status2, 400)
        self.assertEqual(body2["error"]["code"], -32700)

    def test_p2_parse_constant_rejects_nan_and_infinity(self) -> None:
        for val in ["NaN", "Infinity", "-Infinity"]:
            raw = f'{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"x":{val}}}}}'.encode()
            status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], -32700)
            self.assertIn("Unsupported constant", body["error"]["message"])

    def test_p2_sanitized_echo_string_in_error_message(self) -> None:
        # Client method with non-printable/non-ASCII characters and > 64 chars
        malicious_method = "custom\x00\x1b\x7f\U0001f600" + ("a" * 100)
        raw = json.dumps({"jsonrpc": "2.0", "id": 42, "method": malicious_method}).encode()
        status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
        self.assertEqual(status, 200)
        err_msg = body["error"]["message"]
        # Max length of echoed method is 64 chars, non-printable and non-ASCII replaced with '?'
        self.assertNotIn("\x00", err_msg)
        self.assertNotIn("\x1b", err_msg)
        self.assertNotIn("\U0001f600", err_msg)
        self.assertIn("custom????", err_msg)

    def test_r7_non_finite_floats_rejected(self) -> None:
        for val in ["1e400", "-1e400"]:
            raw = f'{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"val":{val}}}}}'.encode()
            status, body, action = evaluate_policy(raw, token_scope="mindhub:read")
            self.assertEqual(status, 400)
            self.assertEqual(action, "respond")
            self.assertIsInstance(body, dict)
            self.assertEqual(body.get("error", {}).get("code"), -32700)
            self.assertIn("Non-finite float", body.get("error", {}).get("message"))
            # Body must not contain Infinity or NaN
            body_str = json.dumps(body)
            self.assertNotIn("Infinity", body_str)
            self.assertNotIn("NaN", body_str)


if __name__ == "__main__":
    unittest.main()
