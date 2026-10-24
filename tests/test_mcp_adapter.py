import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.error import URLError

from mindhub.mcp_adapter import (
    MCPAuthenticationError,
    MCPToolError,
    MCPTransportError,
    StreamableHTTPMCPClient,
    extract_tool_payload,
)
from mindhub.project_state import (
    InMemoryProjectStatePersistence,
    ProjectStateNotFoundError,
    get_project_state,
    get_project_state_history,
    update_project_state,
)


class MockMCPHandler(BaseHTTPRequestHandler):
    expected_api_key = "local-test-key"
    requests = []
    force_gateway_error = False
    gateway_error_message = "gateway unavailable"
    project_state = InMemoryProjectStatePersistence()
    session_id_to_issue = None
    require_session_id = False

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        request = json.loads(body)
        type(self).requests.append((self.path, dict(self.headers), request))

        if self.headers.get("X-API-Key") != type(self).expected_api_key:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"detail":"Unauthorized"}')
            return

        if type(self).require_session_id and request.get("method") != "initialize":
            if not self.headers.get("MCP-Session-ID"):
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Bad Request: Missing session ID"}}')
                return

        if request.get("method") == "notifications/initialized":
            self.send_response(202)
            if type(self).session_id_to_issue:
                self.send_header("MCP-Session-ID", type(self).session_id_to_issue)
            self.end_headers()
            return

        if request.get("method") == "initialize":
            result = {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ai-memory", "version": "local"},
            }
        elif request.get("method") == "tools/list":
            result = {
                "tools": [
                    {"name": "search_memory", "description": "search"},
                    {"name": "remember", "description": "save"},
                    {"name": "get_project_state", "description": "get current project state"},
                    {"name": "update_project_state", "description": "save project state snapshot"},
                    {"name": "get_project_state_history", "description": "get project state history"},
                ]
            }
        elif request.get("method") == "tools/call":
            if type(self).force_gateway_error:
                response = {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "error": {
                        "code": -32000,
                        "message": type(self).gateway_error_message,
                    },
                }
                self._write_json(response)
                return
            params = request["params"]
            if params["name"] == "get_project_state":
                try:
                    result = get_project_state(
                        type(self).project_state,
                        params["arguments"]["project_id"],
                    )
                except (ValueError, ProjectStateNotFoundError) as exc:
                    self._write_json(self._tool_error(request["id"], str(exc)))
                    return
            elif params["name"] == "update_project_state":
                try:
                    result = update_project_state(
                        type(self).project_state,
                        params["arguments"]["project_id"],
                        params["arguments"]["state"],
                    )
                except ValueError as exc:
                    self._write_json(self._tool_error(request["id"], str(exc)))
                    return
            elif params["name"] == "get_project_state_history":
                try:
                    result = {"items": get_project_state_history(
                        type(self).project_state,
                        params["arguments"]["project_id"],
                    )}
                except ValueError as exc:
                    self._write_json(self._tool_error(request["id"], str(exc)))
                    return
            elif params["name"] == "search_memory":
                result = {"content": [{"type": "text", "text": "[]"}]}
            elif params["name"] == "remember":
                result = {
                    "content": [
                        {
                            "type": "text",
                            "text": '{"id": 7, "status": "saved"}',
                        }
                    ]
                }
            else:
                self._write_json(
                    {
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "error": {"code": -32601, "message": "tool not found"},
                    }
                )
                return
        else:
            self._write_json(
                {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {"code": -32601, "message": "method not found"},
                }
            )
            return

        self._write_json({"jsonrpc": "2.0", "id": request["id"], "result": result})

    @staticmethod
    def _tool_error(request_id, message):
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32602, "message": message},
        }

    def _write_json(self, payload):
        encoded = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        if type(self).session_id_to_issue:
            self.send_header("MCP-Session-ID", type(self).session_id_to_issue)
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        pass


class MCPAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        MockMCPHandler.requests = []
        MockMCPHandler.force_gateway_error = False
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockMCPHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.endpoint = f"http://127.0.0.1:{cls.server.server_port}/mcp"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def setUp(self):
        MockMCPHandler.requests = []
        MockMCPHandler.force_gateway_error = False
        MockMCPHandler.gateway_error_message = "gateway unavailable"
        MockMCPHandler.project_state = InMemoryProjectStatePersistence()
        MockMCPHandler.session_id_to_issue = None
        MockMCPHandler.require_session_id = False

    def client(self, key="local-test-key"):
        return StreamableHTTPMCPClient(self.endpoint, api_key=key)

    def test_handshake_and_tool_discovery(self):
        client = self.client()
        initialized = client.initialize()
        tools = client.list_tools()

        self.assertEqual(initialized["serverInfo"]["name"], "ai-memory")
        self.assertEqual(
            [tool["name"] for tool in tools],
            [
                "search_memory",
                "remember",
                "get_project_state",
                "update_project_state",
                "get_project_state_history",
            ],
        )
        self.assertEqual(MockMCPHandler.requests[0][0], "/mcp")
        self.assertEqual(MockMCPHandler.requests[0][1]["X-Api-Key"], "local-test-key")

    def test_project_state_tools_are_discoverable_and_callable(self):
        client = self.client()
        client.initialize()
        names = {tool["name"] for tool in client.list_tools()}
        self.assertTrue(
            {
                "get_project_state",
                "update_project_state",
                "get_project_state_history",
            }.issubset(names)
        )

        state = {
            "current_goal": "Validate Project State",
            "status": "in_progress",
            "progress": "MCP wiring",
            "decisions": ["Use fake persistence"],
            "blockers": [],
            "next_action": "Run local tests",
        }
        first = client.update_project_state(7, state)
        second = client.update_project_state(7, {**state, "progress": "Tests pass"})
        current = client.get_project_state(7)
        history = client.get_project_state_history(7)

        self.assertEqual(first["sequence"], 1)
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(current["snapshot_id"], second["snapshot_id"])
        self.assertEqual([item["sequence"] for item in history["items"]], [1, 2])

    def test_project_state_tools_validate_and_isolate_projects(self):
        client = self.client()
        state = {
            "current_goal": "Goal",
            "status": "planned",
            "progress": "None",
            "decisions": [],
            "blockers": [],
            "next_action": "Start",
        }
        client.update_project_state(7, state)
        client.update_project_state(8, {**state, "current_goal": "Other"})
        self.assertEqual(client.get_project_state(7)["project_id"], 7)
        self.assertEqual(client.get_project_state(8)["project_id"], 8)
        with self.assertRaises(MCPToolError) as missing:
            client.get_project_state(99)
        self.assertEqual(missing.exception.code, -32602)
        with self.assertRaises(MCPToolError) as invalid:
            client.update_project_state(7, {"status": "planned"})
        self.assertEqual(invalid.exception.code, -32602)

        with self.assertRaises(MCPAuthenticationError) as caught:
            self.client("wrong-key").initialize()
        self.assertNotIn("wrong-key", str(caught.exception))

    def test_search_memory_uses_minimum_contract(self):
        result = self.client().search_memory("docker", limit=5)
        self.assertEqual(result, {"content": [{"type": "text", "text": "[]"}]})
        call = MockMCPHandler.requests[-1][2]
        self.assertEqual(call["params"], {"name": "search_memory", "arguments": {"query": "docker", "limit": 5}})

    def test_remember_uses_minimum_contract(self):
        result = self.client().remember("Use existing gateway", source="planning")
        self.assertEqual(result["content"][0]["text"], '{"id": 7, "status": "saved"}')
        call = MockMCPHandler.requests[-1][2]
        self.assertEqual(
            call["params"],
            {
                "name": "remember",
                "arguments": {
                    "content": "Use existing gateway",
                    "memory_type": "fact",
                    "source": "planning",
                },
            },
        )

    def test_local_validation_rejects_invalid_inputs(self):
        client = self.client()
        with self.assertRaises(ValueError):
            client.search_memory("", limit=10)
        with self.assertRaises(ValueError):
            client.search_memory("x", limit=51)
        with self.assertRaises(ValueError):
            client.remember(" ")
        with self.assertRaises(ValueError):
            client.remember("x", memory_type="")

    def test_input_boundaries_are_accepted_or_rejected(self):
        client = self.client()
        for limit in (1, 50):
            result = client.search_memory("x", limit=limit)
            self.assertIn("content", result)
        self.assertIn("content", client.remember("x" * 60000))
        self.assertIn("content", client.remember("x", memory_type="m" * 50))
        with self.assertRaises(ValueError):
            client.remember("x" * 60001)
        with self.assertRaises(ValueError):
            client.remember("x", memory_type="m" * 51)

    def test_unknown_tool_returns_json_rpc_tool_error(self):
        with self.assertRaises(MCPToolError) as caught:
            self.client().call_tool("missing_tool", {})
        self.assertEqual(caught.exception.code, -32601)
        self.assertEqual(str(caught.exception), "tool not found")

    def test_malformed_json_response_is_a_transport_error(self):
        response = _FakeResponse(b"not-json")
        with patch("mindhub.mcp_adapter.urlopen", return_value=response):
            with self.assertRaises(MCPTransportError) as caught:
                self.client().initialize()
        self.assertEqual(str(caught.exception), "MCP response was not valid JSON")

    def test_malformed_json_rpc_error_is_a_transport_error(self):
        response = _FakeResponse(b'{"jsonrpc":"2.0","id":1,"error":"bad"}')
        with patch("mindhub.mcp_adapter.urlopen", return_value=response):
            with self.assertRaises(MCPTransportError) as caught:
                self.client().initialize()
        self.assertEqual(str(caught.exception), "MCP error response was malformed")

    def test_timeout_and_transport_failure_are_safe(self):
        client = self.client()
        for failure in (TimeoutError(), URLError("connection refused")):
            with patch("mindhub.mcp_adapter.urlopen", side_effect=failure):
                with self.assertRaises(MCPTransportError) as caught:
                    client.initialize()
            self.assertNotIn("local-test-key", str(caught.exception))

    def test_gateway_error_does_not_echo_api_key(self):
        MockMCPHandler.force_gateway_error = True
        MockMCPHandler.gateway_error_message = "failed key=local-test-key"
        with self.assertRaises(MCPToolError) as caught:
            self.client().search_memory("docker")
        self.assertNotIn("local-test-key", str(caught.exception))

    def test_gateway_error_is_reported_without_inventing_envelope(self):
        MockMCPHandler.force_gateway_error = True
        with self.assertRaises(MCPToolError) as caught:
            self.client().search_memory("docker")
        self.assertEqual(caught.exception.code, -32000)
        self.assertEqual(str(caught.exception), "gateway unavailable")

    def test_extract_tool_payload_parses_json_content(self):
        mcp_result = {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({"status": "ok", "count": 42}),
                }
            ],
            "isError": False,
        }
        parsed = extract_tool_payload(mcp_result)
        self.assertEqual(parsed, {"status": "ok", "count": 42})

        # Structured content (FastMCP list result)
        structured_result = {
            "structuredContent": {"result": [{"seq": 1}, {"seq": 2}]},
            "isError": False,
        }
        self.assertEqual(extract_tool_payload(structured_result), [{"seq": 1}, {"seq": 2}])

        # Multiple content blocks fallback to list
        multi_content = {
            "content": [
                {"type": "text", "text": json.dumps({"seq": 1})},
                {"type": "text", "text": json.dumps({"seq": 2})},
            ],
            "isError": False,
        }
        self.assertEqual(extract_tool_payload(multi_content), [{"seq": 1}, {"seq": 2}])

    def test_extract_tool_payload_returns_text_when_not_json(self):
        mcp_result = {
            "content": [{"type": "text", "text": "simple string response"}],
            "isError": False,
        }
        self.assertEqual(extract_tool_payload(mcp_result), "simple string response")

    def test_extract_tool_payload_returns_direct_dict_when_no_content(self):
        direct = {"project_id": 7, "sequence": 1}
        self.assertEqual(extract_tool_payload(direct), direct)

    def test_call_tool_payload_and_raw_flag(self):
        client = self.client()
        # Mock remember returns {"content": [{"type": "text", "text": '{"id": 7, "status": "saved"}'}]}
        raw_res = client.remember("test memory", raw=True) if hasattr(client.remember, "raw") else client.call_tool("remember", {"content": "test memory", "memory_type": "fact", "source": None})
        self.assertIn("content", raw_res)

        payload = client.call_tool_payload("remember", {"content": "test memory", "memory_type": "fact", "source": None})
        self.assertEqual(payload, {"id": 7, "status": "saved"})

    def test_session_id_lifecycle(self):
        MockMCPHandler.session_id_to_issue = "session-xyz-123"
        MockMCPHandler.require_session_id = True

        client = self.client()
        self.assertIsNone(client.session_id)

        initialized = client.initialize()
        self.assertEqual(initialized["serverInfo"]["name"], "ai-memory")
        self.assertEqual(client.session_id, "session-xyz-123")

        # Verify notifications/initialized sent MCP-Session-ID
        init_notification_headers = {k.lower(): v for k, v in MockMCPHandler.requests[1][1].items()}
        self.assertEqual(init_notification_headers.get("mcp-session-id"), "session-xyz-123")

        # Verify subsequent requests send MCP-Session-ID
        tools = client.list_tools()
        self.assertTrue(len(tools) > 0)
        tools_headers = {k.lower(): v for k, v in MockMCPHandler.requests[2][1].items()}
        self.assertEqual(tools_headers.get("mcp-session-id"), "session-xyz-123")

class _FakeResponse:
    def __init__(self, body, content_type="application/json"):
        self._body = body
        self.headers = {"Content-Type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._body


if __name__ == "__main__":
    unittest.main()
