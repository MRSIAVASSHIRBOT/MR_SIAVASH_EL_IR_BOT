# Cloudflare webhook deployment

This directory contains the Cloudflare Workers webhook runtime for the standalone Telegram bot. It is separate from the legacy bot_server.py and never imports or executes that file.

## Architecture

Telegram Bot API -> Cloudflare Worker -> D1 (encrypted scoped Hub credentials) -> MR_SIAVASH_HUB_AI through a controlled HTTPS tunnel.

The Worker supports /start, /help, /id, /pair CODE, /status, and /tasks in private chats. Only the configured owner Telegram ID is accepted. /tasks requires the explicitly granted tasks:read scope; the default Hub scope should remain status:read.

No task creation, shell execution, arbitrary tool invocation, model execution, or public Hub access is enabled.

## Cloudflare resources

1. Create a D1 database named mr-siavash-el-ir-bot-state and execute schema.sql.
2. Deploy worker.js as a module Worker named mr-siavash-el-ir-bot.
3. Bind the D1 database as DB.
4. Add a daily Cron Trigger such as 17 3 * * * to prune old webhook idempotency records.

Non-secret Worker variables:
- ALLOWED_TELEGRAM_USER_ID: owner's numeric Telegram user ID.
- HUB_API_BASE_URL: HTTPS origin of the Hub API, without a path.
- HUB_CLIENT_ID: 3a1c9d72-6f84-4b35-9e21-7d0c8a6f4b52

Worker secrets (never commit or paste into chat):
- TELEGRAM_BOT_TOKEN: token from BotFather.
- TELEGRAM_WEBHOOK_SECRET: random 32-64 character value using only letters, digits, underscore, and hyphen. It must match the local webhook registration setting.
- SESSION_ENCRYPTION_KEY: base64url encoding of 32 cryptographically random bytes, without padding. It encrypts Hub access and refresh credentials before D1 storage.

Generate the encryption key locally:

```powershell
py -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"
```

## Hub connectivity

The Hub already provides one-time Telegram pairing, short-lived access credentials, refresh credentials, revocation, audit events, and per-client scopes.

Keep the Hub local-first. Do not bind it to 0.0.0.0 or expose port 8000 directly. Use a controlled HTTPS Cloudflare Tunnel origin and, where available, an Access service-token policy. Route only to the Hub API and keep its own authentication and Telegram scoped-token checks enabled. A temporary Quick Tunnel is for short tests only.

The Worker calls only POST /integrations/telegram/exchange, POST /integrations/telegram/refresh, GET /integrations/telegram/status, and GET /integrations/telegram/tasks?limit=10.

Create the pairing challenge from an authenticated Hub owner session, bound to the exact Telegram user ID and client ID. The code expires after five minutes and can be used once.

Example PowerShell request after the Hub is running and the owner has logged in:

```powershell
$telegramUserId = 123456789
$clientId = "3a1c9d72-6f84-4b35-9e21-7d0c8a6f4b52"
$body = @{ telegram_user_id = $telegramUserId; client_id = $clientId; label = "MR_SIAVASH_EL_IR_BOT"; scopes = @("status:read") } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "$HubBaseUrl/integrations/telegram/pairing-challenges" -Headers @{ Authorization = "Bearer $HubOwnerAccessToken" } -ContentType "application/json" -Body $body
```

Send the returned pairing_code only to your own bot in a private chat using /pair CODE. Do not put it in GitHub or a public chat.

## Register the Telegram webhook

After deployment and secret configuration, add these values to the local ignored .env file:

```dotenv
TELEGRAM_WEBHOOK_URL=https://YOUR-WORKER.workers.dev/telegram/webhook
TELEGRAM_WEBHOOK_SECRET=the_same_secret_configured_in_cloudflare
```

Run locally from the repository root:

```powershell
python scripts/register_webhook.py
```

The helper reads TELEGRAM_BOT_TOKEN from local .env, checks the current webhook, refuses to replace a different webhook unless explicitly confirmed, registers the Worker URL, and verifies it with a read-back. It never prints the token.

If replacing a different webhook is intended, inspect it first, then set CONFIRM_REPLACE_WEBHOOK=true only for that one registration run.

## Verification

- GET /health returns status ok.
- Requests without the Telegram secret-token header are rejected.
- Messages from non-owner IDs are ignored.
- /id returns the configured numeric ID.
- A one-time pairing code succeeds exactly once.
- /status returns the Hub's authenticated scoped status.
- /tasks is denied unless tasks:read was explicitly granted.
- D1 stores encrypted credentials; logs contain no tokens or message contents.

## Operational limits

Cloudflare Workers Free has usage limits; check current quota before relying on high-volume traffic. Hub commands are unavailable while the local machine, Hub API, or tunnel is offline. The webhook can remain online during a Hub outage, but it must report the outage rather than bypass Hub policy. A successful Worker deployment is not a verified Telegram webhook; test a real private-chat round trip before calling it live.