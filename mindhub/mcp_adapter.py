"""Small dependency-free MCP Streamable HTTP client for mindhub."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class MCPError(Exception):
    """Base exception for MCP adapter failures."""


class MCPAuthenticationError(MCPError):
    """The MCP endpoint rejected authentication."""


class MCPTransportError(MCPError):
    """The MCP endpoint could not be reached or returned an invalid response."""


class MCPToolError(MCPError):
    """The MCP server returned a JSON-RPC error for a request."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MCPClientInfo:
    name: str = "mindhub"
    version: str = "0.1.0"


def extract_tool_payload(result: dict) -> object:
    """Extract and parse the inner payload from an MCP CallToolResult or direct dict.

    If the result contains structuredContent with a 'result' key, return it.
    If the result contains a standard MCP 'content' list:
      - If there are multiple text blocks, parse each as JSON if possible and return the list.
      - If there is a single text block, parse as JSON (falling back to raw string).
    If the result is already a dict without a 'content' key, return it as-is.
    """
    if not isinstance(result, dict):
        return result
    if not result.get("isError"):
        structured = result.get("structuredContent")
        if isinstance(structured, dict) and "result" in structured:
            return structured["result"]
    if "content" in result and isinstance(result["content"], list):
        text_items = [
            item.get("text", "")
            for item in result["content"]
            if isinstance(item, dict) and item.get("type") == "text"
        ]
        if not text_items:
            return None
        if len(text_items) > 1:
            parsed_items = []
            for text in text_items:
                trimmed = text.strip()
                if not trimmed:
                    continue
                try:
                    parsed_items.append(json.loads(trimmed))
                except json.JSONDecodeError:
                    parsed_items.append(trimmed)
            return parsed_items
        single = text_items[0].strip()
        if not single:
            return None
        try:
            return json.loads(single)
        except json.JSONDecodeError:
            return single
    return result


class StreamableHTTPMCPClient:
    """Minimal MCP client for the audited Streamable HTTP contract.

    The client intentionally uses Python's standard library only. It supports
    JSON responses and the JSON data frames commonly used by SSE responses,
    while leaving protocol-specific error envelopes untouched.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        api_key: str,
        timeout: float = 10.0,
        protocol_version: str = "2025-03-26",
        client_info: MCPClientInfo | None = None,
    ) -> None:
        if not endpoint.startswith(("http://", "https://")):
            raise ValueError("endpoint must use http:// or https://")
        if not api_key:
            raise ValueError("api_key is required")
        self.endpoint = endpoint
        self._api_key = api_key
        self.timeout = timeout
        self.protocol_version = protocol_version
        self.client_info = client_info or MCPClientInfo()
        self._next_id = 1
        self._initialized = False
        self._session_id: str | None = None

    @property
    def session_id(self) -> str | None:
        """The active MCP session ID, if established."""
        return self._session_id

    def initialize(self) -> dict:
        self._session_id = None
        self._initialized = False
        result = self._request(
            "initialize",
            {
                "protocolVersion": self.protocol_version,
                "capabilities": {},
                "clientInfo": {
                    "name": self.client_info.name,
                    "version": self.client_info.version,
                },
            },
        )
        if result is None:
            raise MCPTransportError("initialize response was empty")
        self._initialized = True
        self._request("notifications/initialized", {}, notification=True)
        return result

    def list_tools(self) -> list[dict]:
        result = self._request("tools/list", {})
        if result is None:
            raise MCPTransportError("tools/list response was empty")
        tools = result.get("tools")
        if not isinstance(tools, list):
            raise MCPTransportError("tools/list response did not contain a tools list")
        return tools

    def call_tool(self, name: str, arguments: dict) -> dict:
        if not name:
            raise ValueError("tool name is required")
        result = self._request(
            "tools/call",
            {"name": name, "arguments": arguments},
        )
        if not isinstance(result, dict):
            raise MCPTransportError("tools/call response was not an object")
        return result

    def call_tool_payload(self, name: str, arguments: dict) -> object:
        """Call a tool and automatically unwrap the inner payload from MCP CallToolResult."""
        result = self.call_tool(name, arguments)
        return extract_tool_payload(result)

    def search_memory(self, query: str, *, limit: int = 10) -> dict:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query cannot be empty")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
            raise ValueError("limit must be between 1 and 50")
        return self.call_tool(
            "search_memory",
            {"query": query.strip(), "limit": limit},
        )

    def remember(
        self,
        content: str,
        *,
        memory_type: str = "fact",
        source: str | None = None,
    ) -> dict:
        if not isinstance(content, str) or not content.strip():
            raise ValueError("content cannot be empty")
        if not isinstance(memory_type, str) or not memory_type.strip():
            raise ValueError("memory_type cannot be empty")
        if len(content) > 60000:
            raise ValueError("content is too long")
        if len(memory_type.strip()) > 50:
            raise ValueError("memory_type is too long")
        if source is not None and not isinstance(source, str):
            raise ValueError("source must be a string or null")
        return self.call_tool(
            "remember",
            {
                "content": content.strip(),
                "memory_type": memory_type.strip(),
                "source": source,
            },
        )

    def get_project_state(self, project_id: int, *, raw: bool = False) -> dict | object:
        self._validate_project_id(project_id)
        result = self.call_tool("get_project_state", {"project_id": project_id})
        return result if raw else extract_tool_payload(result)

    def update_project_state(self, project_id: int, state: dict, *, raw: bool = False) -> dict | object:
        self._validate_project_id(project_id)
        if not isinstance(state, dict):
            raise ValueError("state must be an object")
        result = self.call_tool(
            "update_project_state",
            {"project_id": project_id, "state": state},
        )
        return result if raw else extract_tool_payload(result)

    def get_project_state_history(self, project_id: int, *, raw: bool = False) -> dict | object:
        self._validate_project_id(project_id)
        result = self.call_tool(
            "get_project_state_history",
            {"project_id": project_id},
        )
        return result if raw else extract_tool_payload(result)

    @staticmethod
    def _validate_project_id(project_id: int) -> None:
        if isinstance(project_id, bool) or not isinstance(project_id, int) or project_id <= 0:
            raise ValueError("project_id must be greater than zero")

    def _request(
        self,
        method: str,
        params: dict,
        *,
        notification: bool = False,
    ) -> dict | None:
        request_id = None if notification else self._allocate_id()
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        if request_id is not None:
            payload["id"] = request_id
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "X-API-Key": self._api_key,
        }
        if self._initialized:
            headers["MCP-Protocol-Version"] = self.protocol_version
        if self._session_id:
            headers["MCP-Session-ID"] = self._session_id
        request = Request(self.endpoint, data=body, headers=headers, method="POST")

        try:
            with urlopen(request, timeout=self.timeout) as response:
                session_id = (
                    response.headers.get("MCP-Session-ID")
                    or response.headers.get("mcp-session-id")
                )
                if session_id:
                    self._session_id = session_id
                if notification:
                    return None
                raw = response.read()
                content_type = response.headers.get("Content-Type", "")
        except HTTPError as exc:
            if exc.code in (401, 403):
                raise MCPAuthenticationError("MCP authentication failed") from None
            raise MCPTransportError(f"MCP HTTP request failed with status {exc.code}") from None
        except (URLError, TimeoutError) as exc:
            raise MCPTransportError("MCP endpoint unavailable") from exc

        if not raw:
            raise MCPTransportError("MCP response was empty")
        response_payload = self._decode_response(raw, content_type)
        if "error" in response_payload:
            error = response_payload["error"]
            if not isinstance(error, dict):
                raise MCPTransportError("MCP error response was malformed")
            code = error.get("code", -32000)
            message = error.get("message", "MCP request failed")
            if not isinstance(message, str):
                message = "MCP request failed"
            safe_message = message.replace(self._api_key, "[REDACTED]")
            raise MCPToolError(code, safe_message)
        if "result" not in response_payload:
            raise MCPTransportError("MCP response did not contain a result")
        return response_payload["result"]

    def _allocate_id(self) -> int:
        request_id = self._next_id
        self._next_id += 1
        return request_id

    @staticmethod
    def _decode_response(raw: bytes, content_type: str) -> dict:
        if "text/event-stream" in content_type:
            data_lines = [
                line[5:].strip()
                for line in raw.decode("utf-8").splitlines()
                if line.startswith("data:")
            ]
            if not data_lines:
                raise MCPTransportError("MCP event stream contained no data")
            raw = data_lines[-1].encode("utf-8")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MCPTransportError("MCP response was not valid JSON") from exc
        if not isinstance(payload, dict):
            raise MCPTransportError("MCP response was not a JSON object")
        return payload
