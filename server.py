"""Experimental authenticated HTTP MCP bridge for self-hosted G0DM0D3."""
import hmac
import json
import os

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("godmod3-bridge", stateless_http=True, json_response=True)


def config():
    base = os.environ.get("GODMOD3_BASE_URL", "").rstrip("/")
    if not base.startswith("https://") and not base.startswith("http://"):
        raise ValueError("Configure GODMOD3_BASE_URL com a URL da API G0DM0D3.")
    headers = {}
    key = os.environ.get("GODMOD3_API_KEY", "")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    return base, headers


@mcp.tool()
async def godmod3_models() -> str:
    """Lista modelos disponíveis na API G0DM0D3 configurada."""
    base, headers = config()
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(base + "/v1/models", headers=headers)
        resp.raise_for_status()
        return json.dumps(resp.json(), ensure_ascii=False)[:20000]


@mcp.tool()
async def godmod3_chat(prompt: str, model: str = "ultraplinian/fast") -> str:
    """Consulta G0DM0D3. Pode consumir créditos de modelos no OpenRouter."""
    base, headers = config()
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.post(base + "/v1/chat/completions", headers=headers, json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "contribute_to_dataset": False,
        })
        resp.raise_for_status()
        return json.dumps(resp.json(), ensure_ascii=False)[:40000]


inner = mcp.streamable_http_app()


async def app(scope, receive, send):
    if scope["type"] != "http":
        await inner(scope, receive, send)
        return

    if scope.get("path") == "/health":
        data = json.dumps({"ok": True, "backend_configured": bool(os.getenv("GODMOD3_BASE_URL"))}).encode()
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": data})
        return

    token = os.getenv("MCP_ACCESS_TOKEN", "")
    auth = next((v.decode("latin1") for k, v in scope.get("headers", []) if k.lower() == b"authorization"), "")
    if not token or not hmac.compare_digest(auth, "Bearer " + token):
        await send({"type": "http.response.start", "status": 401,
                    "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")]})
        await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
        return
    await inner(scope, receive, send)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
