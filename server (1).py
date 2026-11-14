"""GodMod3 MCP OAuth bridge with signed restart-resistant OAuth state.

Personal-use implementation. DCR registrations, pending authorizations, codes,
access tokens and refresh tokens are signed and verified using the stable
OAUTH_ADMIN_PASSWORD set in Render. They survive Render process restarts.

Security limitations: revocation and strict global one-time authorization-code
redemption require a durable database; use an established OAuth provider for
production. Keep the OAuth admin password stable and secret.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import zlib
from urllib.parse import urlencode, urlparse

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import (
    AccessToken, AuthorizationCode, AuthorizationParams,
    OAuthAuthorizationServerProvider, RefreshToken, TokenError,
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
    raise RuntimeError("PUBLIC_URL must be HTTPS")
if len(ADMIN_PASSWORD) < 24:
    raise RuntimeError("Set OAUTH_ADMIN_PASSWORD (at least 24 characters) in Render")

# Signing key derived from the existing secret: no new Render setting required.
SIGNING_KEY = hmac.new(
    ADMIN_PASSWORD.encode(), b"godmod3-mcp-oauth-v2-key", hashlib.sha256
).digest()


def _mac(message: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(SIGNING_KEY, message.encode(), hashlib.sha256).digest()).decode().rstrip("=")


def _pack(kind: str, payload: dict, ttl: int | None = None) -> str:
    data = dict(payload)
    if ttl is not None:
        data["exp"] = int(time.time()) + ttl
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    packed = base64.urlsafe_b64encode(zlib.compress(raw, 9)).decode().rstrip("=")
    message = f"v2.{kind}.{packed}"
    return f"{message}.{_mac(message)}"


def _unpack(token: str, kind: str) -> dict | None:
    try:
        if len(token) > 16384:
            return None
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != "v2" or parts[1] != kind:
            return None
        message = ".".join(parts[:3])
        if not hmac.compare_digest(parts[3], _mac(message)):
            return None
        compressed = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        # zlib with bounded output to avoid decompression bombs.
        decompressor = zlib.decompressobj()
        raw = decompressor.decompress(compressed, 16384)
        if not decompressor.eof or decompressor.unconsumed_tail or len(raw) > 16000:
            return None
        data = json.loads(raw)
        if not isinstance(data, dict) or ("exp" in data and data["exp"] <= time.time()):
            return None
        return data
    except (ValueError, TypeError, KeyError, UnicodeError, zlib.error, OverflowError):
        return None


def _client_secret(client_id: str) -> str:
    # Never place the client secret inside the public client ID.
    return _mac("client-secret:" + client_id)


def _chatgpt_redirects_only(client_info: OAuthClientInformationFull) -> bool:
    uris = client_info.redirect_uris or []
    if not uris:
        return False
    for uri in uris:
        parsed = urlparse(str(uri))
        if not (parsed.scheme == "https" and parsed.hostname == "chatgpt.com"
                and parsed.path.startswith("/connector/oauth/") and not parsed.fragment):
            return False
    return True


class RestartResistantOAuth(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """Signed OAuth credentials; no volatile registration/session database."""

    def __init__(self):
        self.redeemed_codes: dict[str, float] = {}  # best-effort replay prevention per process

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not _chatgpt_redirects_only(client_info):
            from mcp.server.auth.provider import RegistrationError
            raise RegistrationError("invalid_redirect_uri", "Only ChatGPT OAuth callbacks are supported")
        metadata = client_info.model_dump(mode="json", exclude={"client_id", "client_secret"})
        # 90 days: reconnect later if the registration naturally expires.
        client_info.client_id = _pack("client", metadata, ttl=90 * 86400)
        client_info.client_secret = _client_secret(client_info.client_id)

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = _unpack(client_id, "client")
        if data is None:
            return None
        try:
            info = OAuthClientInformationFull.model_validate({
                **{k: v for k, v in data.items() if k != "exp"},
                "client_id": client_id,
                "client_secret": _client_secret(client_id),
            })
            return info if _chatgpt_redirects_only(info) else None
        except ValueError:
            return None

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if not params.code_challenge or not params.redirect_uri:
            raise HTTPException(400, "PKCE and redirect URI are required")
        state = _pack("pending", {
            "client_id": client.client_id,
            "params": params.model_dump(mode="json"),
            "nonce": secrets.token_urlsafe(16),
        }, ttl=1800)
        return BASE_URL + "/login?" + urlencode({"state": state})

    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> AuthorizationCode | None:
        data = _unpack(authorization_code, "code")
        if not data or data.get("client_id") != client.client_id:
            return None
        try:
            return AuthorizationCode.model_validate({
                **{k: v for k, v in data.items() if k != "exp"},
                "code": authorization_code,
                "expires_at": data["exp"],
            })
        except ValueError:
            return None

    def _tokens(self, client_id: str, scopes: list[str], resource: str | None) -> OAuthToken:
        actual_resource = resource or RESOURCE_URL
        access = _pack("access", {
            "client_id": client_id, "scopes": scopes,
            "resource": actual_resource, "subject": "owner",
        }, ttl=3600)
        refresh = _pack("refresh", {
            "client_id": client_id, "scopes": scopes,
            "resource": actual_resource, "subject": "owner",
            "nonce": secrets.token_urlsafe(16),
        }, ttl=30 * 86400)
        return OAuthToken(
            access_token=access, refresh_token=refresh, token_type="Bearer",
            expires_in=3600, scope=" ".join(scopes),
        )

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        code = authorization_code.code
        now = time.time()
        self.redeemed_codes = {k: v for k, v in self.redeemed_codes.items() if v > now}
        if code in self.redeemed_codes or authorization_code.expires_at <= now or authorization_code.client_id != client.client_id:
            raise TokenError("invalid_grant", "Authorization code expired or already used")
        self.redeemed_codes[code] = authorization_code.expires_at
        return self._tokens(client.client_id, authorization_code.scopes, authorization_code.resource)

    async def load_access_token(self, token: str) -> AccessToken | None:
        data = _unpack(token, "access")
        if not data:
            return None
        try:
            return AccessToken.model_validate({
                **{k: v for k, v in data.items() if k != "exp"},
                "token": token, "expires_at": data["exp"],
            })
        except ValueError:
            return None

    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> RefreshToken | None:
        data = _unpack(refresh_token, "refresh")
        if not data or data.get("client_id") != client.client_id:
            return None
        try:
            return RefreshToken.model_validate({
                **{k: v for k, v in data.items() if k not in {"exp", "nonce"}},
                "token": refresh_token, "expires_at": data["exp"],
            })
        except ValueError:
            return None

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str]) -> OAuthToken:
        if refresh_token.client_id != client.client_id or not set(scopes).issubset(refresh_token.scopes):
            raise TokenError("invalid_grant", "Invalid refresh token")
        return self._tokens(client.client_id, scopes, refresh_token.resource)

    async def revoke_token(self, token, token_type_hint=None) -> None:
        # Stateless tokens cannot be globally revoked without durable storage.
        pass


provider = RestartResistantOAuth()
mcp = FastMCP(
    "godmod3-bridge",
    auth_server_provider=provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(BASE_URL),
        resource_server_url=AnyHttpUrl(RESOURCE_URL),
        required_scopes=[SCOPE],
        validate_token_resource=True,
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE],
        ),
    ),
    stateless_http=True,
    json_response=True,
)


@mcp.custom_route("/login", methods=["GET"])
async def login(request: Request) -> HTMLResponse:
    state = request.query_params.get("state", "")
    pending = _unpack(state, "pending")
    if not pending or not await provider.get_client(pending.get("client_id", "")):
        raise HTTPException(400, "Invalid/expired login. Start a NEW connection in ChatGPT")
    safe_state = html.escape(state, quote=True)
    page = f"""<!doctype html><html lang="pt-br"><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Autorizar GodMod3</title></head>
<body style="font:16px system-ui;max-width:440px;margin:3em auto;padding:1em"><h2>Conectar GodMod3 ao ChatGPT</h2>
<p>Senha de autorização configurada como OAUTH_ADMIN_PASSWORD no Render (não use a chave OpenRouter).</p>
<form method="post" action="/login"><input type="hidden" name="state" value="{safe_state}">
<label>Senha <input name="password" type="password" autocomplete="off" required></label>
<button type="submit">Autorizar</button></form>
<p>Se voltar aqui depois de autorizar, inicie a conexão novamente pelo ChatGPT.</p></body></html>"""
    return HTMLResponse(page, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"})


@mcp.custom_route("/login", methods=["POST"])
async def login_post(request: Request):
    form = await request.form()
    state = form.get("state", "")
    password = form.get("password", "")
    if not isinstance(state, str) or not isinstance(password, str):
        raise HTTPException(400, "Invalid request")
    pending = _unpack(state, "pending")
    if not pending:
        raise HTTPException(400, "Authorization expired. Start a NEW connection in ChatGPT")
    if not hmac.compare_digest(password, ADMIN_PASSWORD):
        raise HTTPException(401, "Incorrect password. Go back to the form; it remains valid")
    client = await provider.get_client(pending.get("client_id", ""))
    if not client:
        raise HTTPException(400, "Client invalid. Start a NEW connection in ChatGPT")
    params = AuthorizationParams.model_validate(pending["params"])
    # Always use the SDK-verified redirect URL from the signed authorization state.
    code = _pack("code", {
        "client_id": client.client_id,
        "redirect_uri": str(params.redirect_uri),
        "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
        "scopes": params.scopes or [SCOPE],
        "code_challenge": params.code_challenge,
        "resource": params.resource or RESOURCE_URL,
        "subject": "owner", "nonce": secrets.token_urlsafe(16),
    }, ttl=300)
    uri = construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)
    return RedirectResponse(uri, status_code=303)


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "ok", "oauth": "signed-state-v2",
        "backend_configured": bool(os.environ.get("GODMOD3_BASE_URL")),
        "backend_key_configured": bool(os.environ.get("GODMOD3_API_KEY")),
    })


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
    """List available models from GodMod3 API."""
    base, headers = backend()
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.get(base + "/v1/models", headers=headers)
        response.raise_for_status()
        return json.dumps(response.json(), ensure_ascii=False)[:20000]


@mcp.tool()
async def godmod3_chat(prompt: str, model: str = "ultraplinian/fast") -> str:
    """Ask GodMod3 to respond. May consume OpenRouter credits."""
    base, headers = backend()
    async with httpx.AsyncClient(timeout=120) as client:
        response = await client.post(base + "/v1/chat/completions", headers=headers,
            json={"model": model, "messages": [{"role": "user", "content": prompt}],
                  "stream": False, "contribute_to_dataset": False})
        response.raise_for_status()
        return json.dumps(response.json(), ensure_ascii=False)[:40000]


app = mcp.streamable_http_app()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))
