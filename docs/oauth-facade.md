# Mindhub OAuth 2.1 Facade

This document describes the design, configuration, operation, and security architecture of the Mindhub OAuth 2.1 Facade (`mindhub_oauth`).

---

## 1. Overview & Architecture

The OAuth facade is a lightweight Authorization Server (AS), Resource Server (RS), and streaming reverse proxy placed in front of Mindhub's standalone FastMCP server (port `8088`). Its sole purpose is to allow third-party client connectors (such as Claude web/mobile and Gemini custom connectors) to authenticate via OAuth 2.1 while preserving existing internal access controls.

The facade translates external OAuth 2.1 Bearer tokens into internal `X-API-Key` authentication. Existing tools and agents (Hermes Agent, Antigravity IDE) continue connecting directly to Mindhub on loopback or private network using their preconfigured `X-API-Key`, completely bypassing the OAuth facade.

### Architecture Diagram

```text
+-----------------------------------------------------------------------------+
| External Clients (Internet)                                                 |
| - Claude Desktop / Web / Mobile (redirect: https://claude.ai/...)           |
| - Google Gemini Custom Connector (redirect: https://*.googleusercontent.com)|
+-----------------------------------------------------------------------------+
                                       |
                                       | HTTPS (TLS)
                                       v
                        +------------------------------+
                        | Cloudflare Tunnel / Edge WAF |
                        +------------------------------+
                                       |
                                       | HTTP (Loopback Tunnel)
                                       v
+-----------------------------------------------------------------------------+
| Mindhub OAuth 2.1 Facade (127.0.0.1:8089)                                    |
|                                                                             |
|  - RFC 8414 & RFC 8707 Discovery (/.well-known/*)                           |
|  - Dynamic Client Registration (/register, RFC 7591)                        |
|  - Owner Password Authorization Consent (/authorize, /authorize/decision)   |
|  - Token Issuance & Refresh Rotation (/token, RFC 6749)                     |
|  - Scope Policy Gate (mindhub:read vs mindhub:write)                        |
|  - Token Revocation (/revoke, RFC 7009)                                     |
|  - Streaming Reverse Proxy (/mcp -> strips Bearer, injects X-API-Key)       |
+-----------------------------------------------------------------------------+
                                       |
                                       | HTTP (Loopback Only: 127.0.0.1:8088/mcp)
                                       | Injected Header: X-API-Key: <internal-key>
                                       v
+-----------------------------------------------------------------------------+
| Upstream Standalone Mindhub Server (127.0.0.1:8088)                          |
|                                                                             |
|  - FastMCP / Streamable HTTP Server                                         |
|  - SQLite Persistence (memories, project_state_snapshots)                   |
|  - Direct Clients: Hermes Agent, Antigravity IDE (via internal X-API-Key)  |
+-----------------------------------------------------------------------------+
```

---

## 2. Endpoints Table

The facade routes, HTTP methods, authentication requirements, and rate/body caps are strictly enforced by the code as follows:

| Endpoint | Methods | Auth Required | Body Format & Size Cap | Rate Limit / Quota | Purpose |
|---|---|---|---|---|---|
| `/.well-known/oauth-protected-resource` | `GET` | None | None | None (`max-age=300`) | Protected Resource Metadata (RFC 8707) |
| `/.well-known/oauth-protected-resource/mcp` | `GET` | None | None | None (`max-age=300`) | Alternate PRM path for MCP resource |
| `/.well-known/oauth-authorization-server` | `GET` | None | None | None (`max-age=300`) | Authorization Server Metadata (RFC 8414) |
| `/register` | `POST` | None (DCR) | `application/json`, max 8 KiB | 10 req / 60 s per IP; max 50 active clients | Dynamic Client Registration (RFC 7591) |
| `/authorize` | `GET` | Registered `client_id` + exact redirect URI | Query params (max 50 fields, state $\le 4096$ chars) | 30 req / 60 s per IP; max 200 pending auths | Renders HTML consent dialogue & issues CSRF cookie |
| `/authorize/decision` | `POST` | Owner password (scrypt) + CSRF double-submit | `application/x-www-form-urlencoded`, max 16 KiB | Lockout: 5 failed / 15 min per IP; 20 failed / 15 min global | Evaluates consent; single-use consumption of pending auth |
| `/token` | `POST` | PKCE S256 code verifier OR refresh token | `application/x-www-form-urlencoded`, max 16 KiB | 60 req / 60 s per IP | Issues access & refresh tokens; rotates refresh tokens |
| `/revoke` | `POST` | `client_id` matching token owner | `application/x-www-form-urlencoded`, max 16 KiB | None | Revokes token or token family (RFC 7009); returns HTTP 200 with empty body (`content=""`, `Cache-Control: no-store`) |
| `/health` | `GET` | None | None | None | Returns HTTP 200 `{"status":"ok","service":"mindhub-oauth"}` |
| `/mcp` | `POST`, `GET`, `DELETE`, `HEAD` (PUT / other methods return `405`) | `Authorization: Bearer <token>` | `application/json` (max 1 MiB) for POST; empty body for GET/DELETE/HEAD | None beyond socket timeouts | Streaming reverse proxy to upstream Mindhub with policy check; sets `X-Accel-Buffering: no` on SSE |

---

## 3. Configuration Reference

All settings are read from environment variables via `mindhub_oauth.config.Config.from_env()`. Missing required variables or non-loopback bindings fail closed at startup.

| Environment Variable | Required / Default | Meaning / Constraints |
|---|---|---|
| `FACADE_PUBLIC_URL` | **Required** | Public HTTPS base URL (e.g. `https://mcp.example.com`). Must use `https://` (unless local insecure mode enabled) and cannot contain path or trailing slash. |
| `MINDHUB_UPSTREAM_API_KEY` | **Required** | Internal API key forwarded to Mindhub upstream in the `X-API-Key` header. |
| `FACADE_OWNER_PASSWORD_HASH` | **Required** | Scrypt hash string of the owner password for consent decisions. Must satisfy `128 * r * (N + p + 2) <= 64 MiB`. |
| `FACADE_DB_PATH` | Optional (`oauth.db`) | Path to SQLite state database. Must be an **absolute path** in production mode. Created with `0600` permissions. |
| `FACADE_HOST` | Optional (`127.0.0.1`) | IP address to bind. Must resolve to a loopback address unless `FACADE_ALLOW_NON_LOOPBACK_BIND=1`. |
| `FACADE_PORT` | Optional (`8089`) | TCP port to bind (1-65535). |
| `FACADE_UPSTREAM_URL` | Optional (`http://127.0.0.1:8088/mcp`) | Upstream Mindhub endpoint. Must use `http://` and resolve to loopback. |
| `FACADE_MAX_SCOPE` | Optional (`mindhub:read`) | Space-separated list of scopes the facade is permitted to issue. Set to `mindhub:read mindhub:write` to enable write tools. |
| `FACADE_DEFAULT_SCOPE` | Optional (`mindhub:read`) | Default scope requested when client omits `scope`. Must be a subset of `FACADE_MAX_SCOPE`. |
| `FACADE_CODE_TTL_SECONDS` | Optional (`60`) | Lifetime of authorization codes in seconds (default: 60 s). Single-use. |
| `FACADE_ACCESS_TTL_SECONDS` | Optional (`900`) | Lifetime of access tokens in seconds (default: 900 s = 15 min). |
| `FACADE_REFRESH_TTL_SECONDS` | Optional (`2592000`) | Lifetime of refresh tokens in seconds (default: 2,592,000 s = 30 days). |
| `FACADE_MAX_CLIENTS` | Optional (`50`) | Maximum active registered OAuth clients allowed before DCR returns `400`. |
| `FACADE_EXTRA_REDIRECT_URIS` | Optional (`""`) | Comma-separated list of additional exact redirect URIs permitted for client registration. |
| `FACADE_TRUST_CF_HEADERS` | Optional (`true`) | When `true`, extracts client IP from `CF-Connecting-IP` ONLY if peer IP is loopback. |
| `FACADE_GOOGLE_META_REFRESH` | Optional (`true`) | When `true`, consent response for Google connector redirect URIs returns 200 meta-refresh HTML. |
| `FACADE_ALLOW_NON_LOOPBACK_BIND` | Optional (`false`) | Set `1` to override loopback bind restriction. Emits warning. |
| `FACADE_ALLOW_INSECURE_LOCAL` | Optional (`false`) | Set `1` for local unit tests without HTTPS or absolute paths. Emits warning. |

### Generating the Owner Password Hash

The entrypoint `mindhub_oauth` exposes two subcommands: `serve` (default if no subcommand is given) and `hash-password`.

The owner password hash must be generated using the project's interactive CLI helper. Passwords are never accepted as command-line arguments to prevent leakage into shell history or process tables:

```bash
.venv/bin/python -m mindhub_oauth hash-password
```

The tool will prompt twice:
```text
Enter owner password: 
Confirm owner password: 
```

Requirements & behavior:
- Minimum length: 14 characters.
- Generates a format-compatible scrypt hash: `scrypt$32768$8$1$<salt_b64>$<key_b64>`.
- Copy the printed output and assign it to `FACADE_OWNER_PASSWORD_HASH` in `/etc/mindhub-oauth/env`.

---

## 4. Token Lifetimes & Rotation

- **Authorization Code**:
  - Lifetime: **60 seconds** (`FACADE_CODE_TTL_SECONDS = 60`).
  - Single-use: Atomically consumed in database transaction upon exchange at `/token`.
  - Replay Protection: Replaying an already-used authorization code immediately revokes its entire token family.
- **Access Token**:
  - Lifetime: **15 minutes** (`FACADE_ACCESS_TTL_SECONDS = 900`).
  - Scope and resource audience bound.
- **Refresh Token**:
  - Lifetime: **30 days** (`FACADE_REFRESH_TTL_SECONDS = 2592000`).
  - Refresh Token Rotation: Every successful refresh issues a new access token and a new refresh token, atomically marking the prior refresh token as used.
  - Replay Detection: Reusing an old or used refresh token revokes the entire token family (`refresh_token_reuse`), rendering all issued access and refresh tokens in that family immediately invalid (`401 Unauthorized`).

---

## 5. Scope Policy & Tool Allowlist

The facade enforces fine-grained access control before forwarding any JSON-RPC payload upstream to Mindhub:

### Scopes
1. `mindhub:read` (Default):
   - Permits read-only inspection and query tools.
   - Allowed tools (`READ_TOOLS` in `mindhub_oauth.policy`):
     - `search_memory`
     - `get_project_state`
     - `get_project_state_history`
2. `mindhub:write`:
   - Extends access to data modification tools.
   - Allowed tools (`WRITE_TOOLS` in `mindhub_oauth.policy`):
     - `search_memory`
     - `get_project_state`
     - `get_project_state_history`
     - `remember`
     - `update_project_state`

### Method Allowlist
- Allowlisted & forwarded upstream: `initialize`, `ping`, `tools/list`, `notifications/initialized`, `notifications/cancelled`.
- Intercepted by policy engine: `tools/call`.
- Denied methods: `resources/*`, `prompts/*`, and any method outside the allowlist are denied. If a JSON-RPC `id` is present, returns an immediate JSON-RPC error `{"code": -32601, "message": "Method not found: <method>"}`; notifications without an `id` are dropped with HTTP 202.
- If `tools/call` requests a tool requiring `mindhub:write` when the token only holds `mindhub:read`, the facade intercepts the call without forwarding upstream and returns an immediate JSON-RPC error:
  ```json
  {"jsonrpc": "2.0", "id": 1, "error": {"code": -32001, "message": "tool not permitted for this token's scope"}}
  ```
- Note on `tools/list`: `tools/list` is forwarded to Mindhub, returning all 5 registered tools (`search_memory`, `get_project_state`, `get_project_state_history`, `remember`, `update_project_state`). The facade does not filter `tools/list` responses, allowing client discovery to succeed; scope restriction is enforced when `tools/call` is executed.

---

## 6. Security Model & Hardening

1. **Mandatory PKCE S256**:
   - RFC 7636 S256 code challenge is strictly required at `/authorize`. Plain PKCE (`code_challenge_method=plain`) is rejected with `invalid_request`.
2. **Resource Indicators (RFC 8707)**:
   - Resource parameter is validated at `/authorize`, verified during token exchange at `/token`, and enforced at `/mcp`. Audience mismatch returns `401 Unauthorized`.
3. **Storage Security**:
   - Secrets are never stored plaintext in SQLite. Tokens, authorization codes, request IDs, and CSRF tokens are hashed using SHA-256 (`token_hash`, `code_hash`, `request_id_hash`, `csrf_hash`).
   - Owner password verified using `hashlib.scrypt` with strictly bounded memory (`SCRYPT_MAXMEM = 64 MiB`).
4. **Constant-Time Verification**:
   - All secret comparisons (PKCE verifier, owner password hash, CSRF tokens, stored hashes) use `hmac.compare_digest`.
5. **CSRF Protection**:
   - Consent form uses double-submit cookie verification: `mh_csrf` cookie attributes are `Max-Age=600; Path=/authorize; HttpOnly; SameSite=lax; Secure` (Secure omitted in local insecure test mode). The cookie value must cryptographically match the hidden `csrf` form field.
6. **Rate Limiting & Lockouts**:
   - `/register`: 10 requests / 60 s per IP.
   - `/authorize`: 30 requests / 60 s per IP; global cap of 200 active pending authorizations.
   - `/token`: 60 requests / 60 s per IP.
   - Login attempts: Per-IP lockout after 5 failures in 15 minutes; global lockout after 20 failures across all IPs in 15 minutes.
   - `CF-Connecting-IP` trusted only when the socket connection originates from `127.0.0.1` (Cloudflare Tunnel loopback agent).
7. **HTML & Content Security Policy**:
   - All dynamic parameters rendered in consent/error HTML pages are escaped using `html.escape`.
   - Security headers set on all HTML responses (error pages, consent page, and meta-refresh redirect):
     - `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'` (contains **no** `form-action` on meta-refresh pages, and no external scripts).
     - `Cache-Control: no-store`
     - `Pragma: no-cache`
     - `X-Frame-Options: DENY`
     - `X-Content-Type-Options: nosniff`
     - `Referrer-Policy: no-referrer`
8. **File Permissions & Process Hardening**:
   - SQLite DB file created with `0600` permissions. Systemd unit runs under `UMask=0077`, `NoNewPrivileges=true`, and `ProtectSystem=strict`.
9. **Log Hygiene**:
   - Request headers, request/response bodies, tokens, API keys, and passwords are never logged at any log level (`access_log=False`).
   - Internal SQLite audit log records security events with sanitized, bounded metadata: event ($\le 64$ printable ASCII), OAuth `client_id` ($\le 64$ printable ASCII, when present), and detail ($\le 256$ printable ASCII, which records the client IP address on failed logins and lockout events).
   - Audit table automatically purges records older than 90 days and is capped to the newest 50,000 rows.

---

## 7. Client Notes & Compatibility

Conforms to OAuth 2.1 specification and documented client behavior, verified by local tests:

### Claude Web & Mobile Connector
- Client registration callback: `https://claude.ai/api/mcp/auth_callback`.
- Claude performs RFC 8707 PRM discovery on 401 challenge, fetches metadata, registers via DCR, initiates authorization with PKCE S256, and completes token exchange.
- Claude expects an HTTP `302 Found` redirect back to `https://claude.ai/...` upon consent.

### Google Gemini Custom Connector
- Gemini sends a `state` parameter longer than 512 characters (observed in testing; its exact length and content are not documented, so the facade accepts up to 4096).
- Gemini registers with up to 6 redirect URIs under `oauth-redirect.googleusercontent.com` and `oauth-redirect-sandbox.googleusercontent.com` with paths `/r/*` or `/a/*`.
- Notice on test host redirect URIs: Gemini may register redirect URIs using host `oauth-redirect-test.googleusercontent.com` (such as `https://oauth-redirect-test.googleusercontent.com/r/user_bound_custom-mcp-<id>-<host>`), which are not allowlisted by default and must be pinned exactly via `FACADE_EXTRA_REDIRECT_URIS` (format: comma-separated exact URIs).
- Gemini sends `token_endpoint_auth_method="client_secret_post"` during DCR. The facade sets this to `"none"` and issues no `client_secret` (public client model).
- Gemini webviews do not handle standard 302 redirects reliably; the facade returns an HTTP `200 OK` HTML page with `<meta http-equiv="refresh">` and a manual clickable fallback link.

### Verification Status
- **Verified by Local Tests**: Local loopback test suite with real sockets and real Mindhub upstream verifying full scripted flows for Claude and Gemini patterns.
- **NOT Verified**: Live connection from external Claude.ai production servers, live Google Gemini cloud connector, production Cloudflare Tunnel proxy buffering.

---

## 8. Operations & Maintenance

1. **Single Worker Process**:
   - In-memory rate limiters, lockout counters, and SQLite concurrency rely on a single process. Run exactly one Uvicorn worker (`workers=1`).
2. **Loopback Only**:
   - Always bind to `127.0.0.1:8089`. Never bind to `0.0.0.0` or expose the facade directly to public network interfaces.
3. **Startup Order**:
   - Mindhub standalone server (`:8088`) **must** be running before starting the OAuth facade (`:8089`). If upstream Mindhub is offline, the facade responds with HTTP 502/504.
4. **Database Backup & Maintenance**:
   - Location: `/var/lib/mindhub-oauth/oauth.db`.
   - Backup: Use SQLite online backup API or `sqlite3 /var/lib/mindhub-oauth/oauth.db ".backup /backup/oauth-$(date +%F).db"`.
   - Purge: The facade automatically purges expired codes, tokens, and rate limiter entries periodically. Never-authorized client registrations are deleted after 1 hour.
5. **Emergency Revocation Procedure (Revoke Everything)**:
   - To immediately invalidate all issued tokens and client sessions without needing to read secrets or inspect records:
     1. Stop the facade service: `sudo systemctl stop mindhub-oauth`.
     2. Delete or move the database file: `sudo rm /var/lib/mindhub-oauth/oauth.db*`.
     3. Restart the facade service: `sudo systemctl start mindhub-oauth`.
     4. A fresh database will be initialized automatically. All previous clients will need to re-register and re-authenticate.

---

## 9. Cloudflare Configuration Notes

*(To be configured during production deployment)*

1. **SSE Streaming & Buffering**:
   - Cloudflare Tunnel ingress rule routing the public hostname to `http://127.0.0.1:8089`.
   - Under Cloudflare Speed / Optimization: Disable response buffering and disable Rocket Loader / HTML minification on the `/mcp` path.
   - The facade sets `X-Accel-Buffering: no` on `text/event-stream` responses.
2. **WAF & Firewall Rules**:
   - Allow egress IP ranges for Anthropic (`160.79.104.0/21`) and Google OAuth services.
   - Ensure Bot Management / Managed Challenge does not block automated `POST /register`, `POST /token`, or `POST /mcp` requests.
3. **Caching**:
   - Create a Cache Rule setting "Bypass Cache" for `/mcp`, `/token`, `/register`, `/authorize`, and `/revoke`.

---

## 10. Deployment Checklist

*(Procedure for live rollout; NOT executed in this milestone)*

1. [ ] Generate a dedicated upstream API key for the facade:
   ```bash
   FACADE_KEY=$(openssl rand -hex 24)
   ```
2. [ ] Add `FACADE_KEY` to `MINDHUB_API_KEYS` in `/etc/mindhub/mindhub.env` and restart `mindhub.service`.
3. [ ] Generate owner password hash using `python -m mindhub_oauth hash-password`.
4. [ ] Create `/etc/mindhub-oauth/env` with `0600` permissions owned by `hermes:hermes`.
5. [ ] Copy `deploy/mindhub-oauth.service.example` to `/etc/systemd/system/mindhub-oauth.service`.
6. [ ] Reload systemd daemon: `sudo systemctl daemon-reload`.
7. [ ] Enable and start facade: `sudo systemctl enable --now mindhub-oauth`.
8. [ ] Verify service health: `curl -s http://127.0.0.1:8089/health`.
9. [ ] Add Cloudflare Tunnel public hostname pointing to `http://127.0.0.1:8089`.
10. [ ] Test Claude connector connection; complete owner consent dialog.
11. [ ] Test Gemini connector connection.
12. [ ] Rollback Plan: If issues occur, run `sudo systemctl stop mindhub-oauth` and remove Cloudflare Tunnel hostname. Upstream Mindhub (`:8088`) remains unaffected.

---

## 11. Known Limitations & Open Risks

1. **Open Dynamic Client Registration (DCR) / Slot Exhaustion**:
   - RFC 7591 DCR is unauthenticated as required by Claude and Gemini connectors. Malicious actors could exhaust the client cap (`FACADE_MAX_CLIENTS = 50`). Mitigated by IP rate limiting (10 req / 60 s per IP) and automatic purging of never-authorized clients after 1 hour, but residual Denial-of-Service risk remains if multiple IPs register clients until 50 active clients are reached.
2. **Token Revocation Propagation Latency**:
   - When a token is revoked via `/revoke` or family revocation on reuse detection, the SQLite store updates immediately (`revoked=1`). However, already-established long-running streaming HTTP/SSE proxy connections to upstream Mindhub remain open until the current response/stream finishes or the client disconnects. FastMCP sessions in flight are not terminated mid-stream by token revocation.
3. **Single-Threaded Proxy Backpressure**:
   - Uvicorn runs in a single process (`workers=1`) to maintain SQLite concurrency safety and in-memory rate limiter / lockout consistency. If slow WAN clients fail to consume streaming SSE responses or hold open connections, proxy generator backpressure and event loop scheduling could delay processing of other concurrent requests under heavy load.
4. **Cloudflare Edge SSE Response Buffering**:
   - Real-world streaming responsiveness depends on Cloudflare Tunnel preserving unbuffered chunked transfer encoding for `text/event-stream`. If Cloudflare edge buffers responses on the public hostname, SSE events will arrive in bursts rather than real time.
5. **Broad Gemini Redirect Path**:
   - By default, redirect URIs on `oauth-redirect.googleusercontent.com` accept wildcard paths matching `/r/*` and `/a/*`. Once the exact project redirect URI for Gemini is identified after first connect, consider locking down via `FACADE_EXTRA_REDIRECT_URIS`.
6. **Session ID Decoupling**:
   - In MCP FastMCP streamable HTTP, the `Mcp-Session-Id` header represents a transport connection session and is not cryptographically bound to the Bearer token.
7. **Global Consent Lockout Risk**:
   - 20 password failures across any IP within 15 minutes triggers a global lockout, temporarily preventing owner authorization for 15 minutes.
8. **Pending Authorization Cap**:
   - The pending authorizations table is capped globally at 200 records. A burst of uncompleted `/authorize` visits from multiple IPs could temporarily fill this cap.
9. **Gemini Public Client Model Untested on Production**:
   - The DCR response returning `token_endpoint_auth_method="none"` with no `client_secret` conforms to spec, but has not been verified against live Google Gemini production servers.
10. **In-Memory Rate Limiting**:
    - Rate limiters and lockout state are kept in memory and reset if the facade process is restarted.
11. **HTTP Client Library Divergence (`httpx` vs `httpx2`)**:
    - Development environment executes against `httpx2 2.16.0` via `mindhub_oauth/_http.py` fallback, while `pyproject.toml` declares standard `httpx>=0.27`. Production deployments using standard PyPI wheels will run against `httpx`.
12. **Dependency Lower Bounds & Verified Environment**:
    - Declared lower bounds in `pyproject.toml` (`starlette>=0.28.0`, `httpx>=0.27`, `fastapi>=0.100`, `uvicorn>=0.20`, `mcp>=1.30.0`) are untested minimums.
    - The actual tested and verified environment is the virtual environment (`.venv`) with the following exact packages:
      - `starlette 1.9.0`
      - `uvicorn 0.54.0`
      - `fastapi 0.159.1`
      - `mcp 2.3.0` (with `mcp-types 2.3.0` and `sse-starlette 3.5.0`)
      - `httpx2 2.16.0` (resolved through `mindhub_oauth._http`)
