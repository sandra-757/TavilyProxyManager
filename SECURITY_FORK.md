# Security hardening fork — what changed vs upstream

Branch `security/p0-hardening` of the fork `sandra-757/TavilyProxyManager`.
Scope: the four P0 findings from the 2026-11-16 review of upstream
`xuncv/TavilyProxyManager` @ 672f3a0. P1/P2 items (credit-accurate
accounting, cache-key completeness, WAL mode, metrics) are intentionally
not in this branch.

## 1. Secrets are encrypted at rest

- Tavily API keys and both access tokens are stored in SQLite only as
  `enc:v1:` AES-256-GCM ciphertext (`server/internal/secretbox`).
- The data-encryption key comes from `TPM_ENCRYPTION_KEY` (base64, 32
  bytes) or from a key file: `TPM_ENCRYPTION_KEY_FILE`, defaulting to
  `encryption.key` next to the database. The file is created with 0600
  permissions on first run. **Losing it makes stored keys unreadable;
  back it up separately from the database.**
- Existing plaintext rows are migrated automatically at startup
  (API keys via `EncryptAllPlaintext`, token settings on load).
- Because ciphertext is randomised, duplicate API keys are now detected
  by an explicit plaintext comparison on create.

## 2. Tokens are never logged

- Upstream printed the generated master key to stdout (`docker logs`
  leak). Now a newly generated token is written once to
  `initial-admin-key.txt` / `initial-proxy-key.txt` (0600) in the data
  directory; the log only records the file path. Retrieve the value,
  store it in a password manager, then delete the file.

## 3. Two token tiers

- **Admin key** (formerly "master key"): the only token accepted by the
  `/api` management plane, including key export and raw-key reads.
- **Proxy key** (new): accepted only by the Tavily proxy endpoints and
  the `/mcp` endpoint. It gets 401 on every `/api` route. The admin key
  also works on the proxy surface (superset).
- Manage it via `GET /api/settings/proxy-key` and
  `POST /api/settings/proxy-key/reset` (admin auth required).
- Give the proxy key to search clients (Claude Code, MCP configs, SDKs);
  keep the admin key for the dashboard only.
- The web UI now keeps the admin key in `sessionStorage` instead of
  `localStorage`, so it is dropped when the tab closes.

## 4. Abuse limits

- Request bodies are capped (`MAX_REQUEST_BODY_BYTES`, default 10 MiB,
  413 on excess) and upstream response bodies are capped
  (`MAX_RESPONSE_BODY_BYTES`, default 50 MiB) instead of being buffered
  without limit.
- The HTTP server sets `ReadHeaderTimeout` (10s), `ReadTimeout` (60s),
  `IdleTimeout` (120s) and `MaxHeaderBytes` (1 MiB).
- Failed token authentication is rate-limited per client: 20 failures
  within 5 minutes blocks that client for 5 minutes (429), on the admin
  API, the proxy surface and MCP. A successful auth clears the history.
- **Breaking change:** `?api_key=...` in the URL query string is no
  longer accepted as a credential (URLs end up in logs). The parameter
  is still stripped before forwarding upstream. Use the
  `Authorization: Bearer` header or the JSON body field.
- The Docker image now runs as a non-root user on a pinned Alpine base,
  and the compose file binds 127.0.0.1 by default.

## Tests

New/updated coverage: `secretbox` round-trip and wrong-key failure,
encryption-at-rest for keys and tokens, token-tier separation at the
service and HTTP layers, auth limiter threshold behaviour, and the
query-string credential removal (updated legacy test).
