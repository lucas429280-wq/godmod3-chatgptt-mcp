"""G0DM0D3 MCP OAuth proof-of-concept (single instance).

Uses mcp SDK OAuth routes, PKCE, dynamic client registration and RFC 9728
protected-resource discovery. Experimental: volatile in-memory OAuth sessions;
use an established identity provider before depending on this in production.
"""
from __future__ import annotations

import hmac
import html
import json
import os
import secrets
import time
from urllib.parse import urlencode

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

BASE_URL = os.environ.get("PUBLIC_URL", "https://godmod3-chatgptt-mcp-2.onrender.com").rstrip("/")
RESOURCE_URL = BASE_URL + "/mcp"
SCOPE = "godmod3:use"
ADMIN_PASSWORD = os.environ.get("OAUTH_ADMIN_PASSWORD", "")

if not BASE_URL.startswith("https://"):
    raise RuntimeError("PUBLIC_URL must be a public HTTPS URL")
if len(ADMIN_PASSWORD) < 24:
    raise RuntimeError("Set OAUTH_ADMIN_PASSWORD in Render to a strong secret of at least 24 characters")


class SingleUserOAuth(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """Single-instance demo OAuth store. Tokens invalidated by a process restart."""

    def __init__(self):
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.states: dict[str, tuple[float, OAuthClientInformationFull, AuthorizationParams]] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.tokens: dict[str, AccessToken] = {}

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            raise ValueError("client_id required")
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not params.code_challenge:
            raise HTTPException(400, "PKCE S256 is required")
        # Only permit callbacks verified by the SDK against registered client metadata.
        state_id = secrets.token_urlsafe(32)
        now = time.time()
        self.states = {k: v for k, v in self.states.items() if v[0] > now}
        self.states[state_id] = (now + 300, client, params)
        return BASE_URL + "/login?" + urlencode({"state": state_id})

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        code = self.codes.get(authorization_code)
        if code and code.expires_at > time.time() and code.client_id == client.client_id:
            return code
        return None

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        code = self.codes.pop(authorization_code.code, None)
        if code is None or code.expires_at <= time.time() or code.client_id != client.client_id:
            raise ValueError("Invalid or expired code")
        token = secrets.token_urlsafe(48)
        self.tokens[token] = AccessToken(
            token=token, client_id=client.client_id, scopes=code.scopes,
            expires_at=int(time.time()) + 3600, resource=code.resource,
            subject="owner",
        )
        return OAuthToken(access_token=token, token_type="Bearer", expires_in=3600, scope=" ".join(code.scopes))

    async def load_access_token(self, token: str) -> AccessToken | None:
        entry = self.tokens.get(token)
        if entry and entry.expires_at and entry.expires_at > time.time():
            return entry
        self.tokens.pop(token, None)
        return None

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        raise ValueError("Refresh tokens not implemented; re-authorize")

    async def revoke_token(self, token: str, token_type_hint: str | None = None) -> None:
        self.tokens.pop(token, None)


provider = SingleUserOAuth()
mcp = FastMCP(
    "godmod3-bridge",
    auth_server_provider=provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(BASE_URL),
        resource_server_url=AnyHttpUrl(RESOURCE_URL),
        required_scopes=[SCOPE],
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
        ),
    ),
    stateless_http=True,
    json_response=True,
)


@mcp.custom_route("/login", methods=["GET"])
async def login(request: Request) -> HTMLResponse:
    state_id = request.query_params.get("state", "")
    st = provider.states.get(state_id)
    if not st or st[0] <= time.time():
        raise HTTPException(400, "Authorization request expired. Restart connection in ChatGPT.")
    safe_state = html.escape(state_id, quote=True)
    page = f"""<!doctype html><html lang="pt-br"><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Autorizar GodMod3</title></head>
<body style="font:16px system-ui;max-width:420px;margin:3em auto;padding:1em"><h2>Conectar GodMod3 ao ChatGPT</h2>
<p>Insira sua senha privada de autorização (definida no Render). Nunca use sua chave OpenRouter aqui.</p>
<form method="post" action="/login"><input type="hidden" name="state" value="{safe_state}">
<label>Senha <input name="password" type="password" autocomplete="off" required></label>
<button type="submit">Autorizar conexão</button></form></body></html>"""
    return HTMLResponse(page, headers={"Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"})


@mcp.custom_route("/login", methods=["POST"])
async def login_post(request: Request):
    form = await request.form()
    state_id = form.get("state", "")
    password = form.get("password", "")
    if not isinstance(state_id, str) or not isinstance(password, str):
        raise HTTPException(400, "Invalid request")
    st = provider.states.pop(state_id, None)  # one attempt per request
    if st is None or st[0] <= time.time():
        raise HTTPException(400, "Authorization expired")
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        raise HTTPException(401, "Wrong password. Restart authorization from ChatGPT.")
    _, client, params = st
    code = secrets.token_urlsafe(32)
    provider.codes[code] = AuthorizationCode(
        code=code, client_id=client.client_id,
        redirect_uri=AnyHttpUrl(str(params.redirect_uri)),
        redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
        expires_at=time.time() + 300,
        scopes=[SCOPE], code_challenge=params.code_challenge,
        resource=params.resource, subject="owner",
    )
    uri = construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)
    return RedirectResponse(uri, status_code=303)


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "oauth": "configured", "backend_configured": bool(os.environ.get("GODMOD3_BASE_URL"))})


def backend():
    base = os.environ.get("GODMOD3_BASE_URL", "").rstrip("/")
    if not base.startswith("https://"):
        raise ValueError("GODMOD3_BASE_URL must point to the HTTPS GodMod3 API")
    headers = {}
    key = os.environ.get("GODMOD3_API_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return base, headers


@mcp.tool()
async def godmod3_models() -> str:
    """List models offered by the connected G0DM0D3 API."""
    base, headers = backend()
    async with httpx.AsyncClient(timeout=30) as client:
        res = await client.get(base + "/v1/models", headers=headers)
        res.raise_for_status()
        return json.dumps(res.json(), ensure_ascii=False)[:20000]


@mcp.tool()
async def godmod3_chat(prompt: str, model: str = "ultraplinian/fast") -> str:
    """Query G0DM0D3. This can consume OpenRouter credits."""
    base, headers = backend()
    async with httpx.AsyncClient(timeout=120) as client:
        res = await client.post(base + "/v1/chat/completions", headers=headers,
                                json={"model": model, "messages": [{"role": "user", "content": prompt}],
                                      "stream": False, "contribute_to_dataset": False})
        res.raise_for_status()
        return json.dumps(res.json(), ensure_ascii=False)[:40000]


app = mcp.streamable_http_app()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
