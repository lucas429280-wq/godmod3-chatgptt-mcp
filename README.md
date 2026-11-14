# GodMod3 → ChatGPT: MCP sem login

O endpoint MCP não exige senha, API key, token Bearer nem OAuth do cliente,
conforme solicitado pelo proprietário. A API GodMod3 mantém sua própria chave
privada no Render; a ponte continua enviando essa chave para o backend.

## Adicionar ao ChatGPT

- URL: `https://godmod3-chatgptt-mcp-2.onrender.com/mcp`
- Autenticação: **Nenhuma / None / No authentication**
- Não preencher senha, API key, Client ID nem Client Secret.

Se a conexão existente estiver salva como OAuth, edite a autenticação para
Nenhuma ou remova a conexão antiga e adicione novamente. Retirar OAuth do
servidor não altera a configuração já salva na interface do ChatGPT.

As ferramentas continuam sendo `godmod3_models` e `godmod3_chat`.

## Configuração privada no Render

Serviço Python `godmod3-chatgptt-mcp-2`:

- Build: `pip install -r requirements.txt`
- Start: `python "server (1).py"` (mantido)
- `PUBLIC_URL=https://godmod3-chatgptt-mcp-2.onrender.com`
- `GODMOD3_BASE_URL=https://godmod3-chatgptt-mcp-1.onrender.com`
- `GODMOD3_API_KEY`: segredo privado equivalente ao `GODMODE_API_KEY` da API.

`OAUTH_ADMIN_PASSWORD` e `MCP_ACCESS_TOKEN` não são utilizados. Não há mais
endpoints de login, registro de cliente ou emissão de tokens.

Não remova `GODMODE_API_KEY`/`OPENROUTER_API_KEY` da API para configurar o plugin.
Esses mecanismos são independentes. O código da API e o Dockerfile não mudaram.

## Verificação

`GET /health` retorna `auth: none`, `version: public-mcp-v1`.
Requisições MCP `initialize`, `tools/list` e `tools/call` funcionam sem o
cabeçalho Authorization. A proteção de Host/Origin continua habilitada.

O endpoint MCP é público: quem conhece a URL pode chamar suas ferramentas.
`godmod3_chat` pode consumir créditos do provedor configurado no backend.
Nenhum segredo do backend é devolvido ao cliente pelo código da ponte.
