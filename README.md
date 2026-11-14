# Ponte MCP experimental GodMod3 → ChatGPT

Código inicial para um servidor MCP Streamable HTTP com duas ferramentas (`godmod3_models` e `godmod3_chat`). Não inclui a própria API G0DM0D3.

## Pré-requisitos

1. Uma API G0DM0D3 **hospedada**, não `localhost` no seu próprio computador.
2. Uma chave para a API (caso protegida) e, se necessário, uma chave OpenRouter configurada **no servidor da API**, não no GitHub.
3. Um token aleatório longo para proteger esta ponte.

## Render

- Runtime: Python
- Build command: `pip install -r requirements.txt`
- Start command: `python server.py`
- Plan: Free (se disponível)
- Variáveis de ambiente no painel do Render: `GODMOD3_BASE_URL`, `GODMOD3_API_KEY`, `MCP_ACCESS_TOKEN`.
- `GET /health`: verificação pública básica; `POST /mcp`: protocolo MCP com token Bearer.

⚠️ **Atenção:** esse exemplo usa um token estático, **não OAuth**. Pode não ser aceito como conector personalizado do ChatGPT. A integração ainda não está concluída. Não compartilhe chaves e não desative a autenticação para tentar contornar isso.

API do projeto original: https://github.com/elder-plinius/G0DM0D3/blob/main/API.md
