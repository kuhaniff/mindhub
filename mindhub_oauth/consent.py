"""HTML rendering: consent page, error page, meta-refresh page."""
from __future__ import annotations

import html
import urllib.parse

from starlette.responses import HTMLResponse

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"
    ),
}


def render_html_error(status_code: int, title: str, description: str) -> HTMLResponse:
    """Render a standalone error page with security headers."""
    safe_title = html.escape(title, quote=True)
    safe_desc = html.escape(description, quote=True)
    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{safe_title}</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; background: #fafafa; color: #333; }}
        .card {{ background: #fff; padding: 24px; border-radius: 8px; border: 1px solid #ddd; max-width: 500px; }}
        h1 {{ font-size: 20px; color: #d32f2f; margin-top: 0; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>{safe_title}</h1>
        <p>{safe_desc}</p>
    </div>
</body>
</html>"""
    return HTMLResponse(body, status_code=status_code, headers=SECURITY_HEADERS)


def render_consent_page(
    client_name: str,
    redirect_uri: str,
    request_id: str,
    csrf: str,
    can_write: bool,
    error_message: str | None = None,
) -> HTMLResponse:
    """Render the owner login and consent HTML page."""
    safe_client_name = html.escape(client_name, quote=True)
    try:
        hostname = urllib.parse.urlsplit(redirect_uri).hostname or redirect_uri
    except Exception:
        hostname = redirect_uri
    safe_host = html.escape(hostname, quote=True)
    safe_req_id = html.escape(request_id, quote=True)
    safe_csrf = html.escape(csrf, quote=True)

    error_banner = ""
    if error_message:
        safe_err = html.escape(error_message, quote=True)
        error_banner = f"""
        <div style="background: #ffebee; border: 1px solid #ef9a9a; color: #c62828; padding: 10px 14px; border-radius: 4px; margin-bottom: 16px; font-size: 14px;">
            {safe_err}
        </div>
        """

    write_choice_html = ""
    if can_write:
        write_choice_html = """
        <label style="display:block; margin-top: 10px; cursor: pointer; min-height: 44px; font-size: 16px;">
            <input type="radio" name="scope_choice" value="readwrite" style="width: 20px; height: 20px; vertical-align: middle;">
            <strong>Read &amp; Write</strong> (search and store memories / project state)
            <div style="color: #c62828; font-size: 13px; margin-left: 28px; margin-top: 4px;">
                Warning: Grants full write access to modify memories and project state.
            </div>
        </label>
        """

    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authorize {safe_client_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f0f2f5; margin: 0; padding: 40px 20px; color: #1c1e21; }}
        .card {{ background: #fff; max-width: 480px; margin: 0 auto; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 28px; }}
        h1 {{ font-size: 22px; margin-top: 0; }}
        .meta {{ background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 12px; margin: 16px 0; font-size: 14px; }}
        .meta div {{ margin-bottom: 4px; }}
        .meta div:last-child {{ margin-bottom: 0; }}
        .btn-group {{ margin-top: 24px; display: flex; gap: 12px; }}
        button {{ flex: 1; padding: 10px 16px; border-radius: 6px; border: none; font-size: 16px; font-weight: 600; cursor: pointer; min-height: 44px; }}
        .btn-primary {{ background: #1976d2; color: #fff; }}
        .btn-primary:hover {{ background: #1565c0; }}
        .btn-deny {{ background: #e0e0e0; color: #333; }}
        .btn-deny:hover {{ background: #d5d5d5; }}
        input[type="password"] {{ width: 100%; box-sizing: border-box; padding: 10px 12px; border: 1px solid #ccc; border-radius: 4px; font-size: 16px; min-height: 44px; margin-top: 6px; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Authorize {safe_client_name}</h1>
        {error_banner}
        <div class="meta">
            <div><strong>Client:</strong> {safe_client_name}</div>
            <div><strong>Redirect Host:</strong> <code>{safe_host}</code></div>
        </div>
        <form method="POST" action="/authorize/decision">
            <input type="hidden" name="request_id" value="{safe_req_id}">
            <input type="hidden" name="csrf" value="{safe_csrf}">
            <div style="margin: 16px 0;">
                <strong>Permission Level:</strong>
                <label style="display:block; margin-top: 8px; cursor: pointer; min-height: 44px; font-size: 16px;">
                    <input type="radio" name="scope_choice" value="read" checked style="width: 20px; height: 20px; vertical-align: middle;">
                    <strong>Read-Only</strong> (search memory and read project state)
                </label>
                {write_choice_html}
            </div>
            <div style="margin: 16px 0;">
                <label for="password"><strong>Owner Password:</strong></label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <div class="btn-group">
                <button type="submit" name="action" value="allow" class="btn-primary">Allow Access</button>
                <button type="submit" name="action" value="deny" class="btn-deny">Deny</button>
            </div>
        </form>
    </div>
</body>
</html>"""
    return HTMLResponse(body, status_code=200, headers=SECURITY_HEADERS)


def render_meta_refresh_response(target_url: str) -> HTMLResponse:
    """Render an HTTP 200 meta-refresh HTML response with visible link and security headers."""
    safe_url = html.escape(target_url, quote=True)
    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="0;url={safe_url}">
    <title>Redirecting...</title>
    <style>
        body {{ font-family: sans-serif; margin: 40px; background: #fafafa; color: #333; }}
        .card {{ background: #fff; padding: 24px; border-radius: 8px; border: 1px solid #ddd; max-width: 500px; }}
        a {{ display: inline-block; min-height: 44px; line-height: 44px; font-size: 16px; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="card">
        <p>Redirecting to <a href="{safe_url}">{safe_url}</a>...</p>
    </div>
</body>
</html>"""
    return HTMLResponse(body, status_code=200, headers=SECURITY_HEADERS)
