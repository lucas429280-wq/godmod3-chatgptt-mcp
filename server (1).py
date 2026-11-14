"""GodMod3 MCP bridge without a client password or API key.

The MCP endpoint is public by the owner's request. Backend credentials remain
private server-side environment variables and are not returned to MCP clients.
"""
from __future__ import annotations

import json
import logging
import os
from urllib.parse import urlparse

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

BASE_URL = os.environ.get("PUBLIC_URL", "https://godmod3-chatgptt-mcp-2.onrender.com").rstrip("/")
if not BASE_URL.startswith("https://"):
    raise RuntimeError("PUBLIC_URL must be HTTPS")

mcp = FastMCP(
    "godmod3-bridge",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[urlparse(BASE_URL).netloc, urlparse(BASE_URL).hostname + ":443",
                       "localhost:*", "127.0.0.1:*"],
        allowed_origins=[BASE_URL, "https://chatgpt.com"],
    ),
    stateless_http=True,
    json_response=True,
)


@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> JSONResponse:
    return JSONResponse({
        "status": "ok", "auth": "none", "version": "public-mcp-v1",
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
    logging.getLogger("httpx").setLevel(logging.WARNING)
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), access_log=False)
