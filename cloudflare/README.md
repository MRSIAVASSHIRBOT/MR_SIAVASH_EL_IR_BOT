# Cloudflare Worker + Local Bridge

## Architecture

```text
Telegram
   │ HTTPS webhook
   ▼
Cloudflare Worker ── encrypted command jobs ──► D1
   ▲                                         │
   │ signed completion / reply               │ outbound polling
   │                                         ▼
Telegram ◄── sendMessage                 Local Bridge
                                               │ loopback only
                                               ▼
                                      MR_SIAVASH_HUB_AI
                                      http://127.0.0.1:8000
```

The Worker is the always-on Telegram edge and can run the bot's cloud-native commands without the user's computer. It does **not** connect to the Hub, store Hub access tokens, or expose the local Hub. The Local Bridge is an optional integration: when enabled, it initiates outbound HTTPS requests to the Worker, then calls only the Hub's dedicated Telegram integration endpoints over loopback. Missing Bridge configuration does not prevent the Telegram edge from becoming ready or serving cloud-native commands.

Bridge requests use HMAC-SHA256 signatures bound to timestamp, nonce, HTTP method, path, and body digest. D1 stores nonce hashes to reject replay. Pairing commands are encrypted with AES-256-GCM before being stored in D1. Hub access and refresh credentials are stored by the local Bridge in the operating-system credential store through Python Keyring; there is no plaintext-file fallback.

## Cloudflare resources

- Worker: `mr-siavash-el-ir-bot`
- D1: `mr-siavash-el-ir-bot-state`
- D1 binding: `DB`
- Daily cleanup Cron: `17 3 * * *` UTC

Apply `schema.sql` to the D1 database. It is safe to reapply because the statements use `IF NOT EXISTS`.

## Worker variables and secrets

Non-secret Worker variables:
- `ALLOWED_TELEGRAM_USER_ID`: owner's numeric Telegram ID.
- `HUB_CLIENT_ID`: stable UUID for this Telegram client; defaults to `3a1c9d72-6f84-4b35-9e21-7d0c8a6f4b52`.

Worker secrets (never commit or paste into chat):
- `TELEGRAM_BOT_TOKEN`: required for the cloud bot.
- `TELEGRAM_WEBHOOK_SECRET`: required for Telegram webhook authentication.
- `QUEUE_ENCRYPTION_KEY`: optional HUB-Bridge integration; base64url-encoded 32 cryptographically random bytes, without padding. <configured in Cloudflare>
- `BRIDGE_SHARED_SECRET`: optional HUB-Bridge integration; at least 32 random characters, shared only between Worker and the local Bridge.

Only the Telegram token, webhook secret, owner ID, and D1 binding are required for the always-on cloud bot. The queue key and Bridge shared secret are required only for the optional local-HUB command queue.

Generate values locally with Python:

```powershell
py -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"
py -c "import secrets; print(secrets.token_urlsafe(48))"
```

The first command generates the queue encryption key; the second generates a bridge shared secret. Enter them directly into the Cloudflare Worker secret store. Do not put them in Git, Telegram, or this conversation.

## Bootstrap the Telegram owner ID

The Worker intentionally requires the owner ID before accepting webhook updates. If you do not know the numeric ID yet, obtain it before registering the webhook:

1. Put the bot token in the ignored local .env file and leave ALLOWED_USER_IDS empty.
2. Run python bot.py and send /id in a private chat with the bot.
3. Stop the local polling process with Ctrl+C.
4. Set the returned number as ALLOWED_TELEGRAM_USER_ID in the Worker configuration and as TELEGRAM_OWNER_ID in the local Bridge .env file.

This is a one-time bootstrap step. Do not run bot.py while the webhook is active; it intentionally refuses to switch update modes or delete an existing webhook.

## Optional Local Bridge configuration

1. Start MR_SIAVASH_HUB_AI locally. Keep its API bound to `127.0.0.1:8000`.
2. In this repository, create the local environment file:

```powershell
Copy-Item .env.example .env
```

3. Set `TELEGRAM_OWNER_ID`, `BRIDGE_BASE_URL`, `HUB_API_BASE_URL`, and `HUB_CLIENT_ID` in `.env`. Keep `HUB_API_BASE_URL=http://127.0.0.1:8000`.
4. Install dependencies and securely store the shared secret in the OS credential store:

```powershell
python -m pip install -r requirements.txt
python bridge.py --init-secret
```

Paste the same `BRIDGE_SHARED_SECRET` configured in Cloudflare into the hidden prompt. Python Keyring must select a working OS credential-store backend. If no trusted backend is available, the Bridge fails closed; it does not write credentials to a plaintext file.
5. Start the Bridge:

```powershell
python bridge.py
```

The Bridge makes outbound HTTPS requests only. It does not open a listening port, create a tunnel, or bind the Hub to a public interface.

## Pairing and permissions

1. Send `/pairinfo` to the bot in a private Telegram chat to obtain the exact Telegram numeric ID and client UUID.
2. In the authenticated local Hub owner UI, create a pairing challenge for those exact values and label `MR_SIAVASH_EL_IR_BOT`.
3. Keep the initial scope to `status:read`. Do not grant task, memory, or write scopes unless a separate review explicitly requires them.
4. Send the one-time code to the bot using `/pair CODE`. The Bridge exchanges it with the local Hub and stores the resulting credentials in OS Keyring.
5. Use `/status`. `/tasks` remains unavailable unless the owner explicitly grants `tasks:read`.

Hub access tokens expire after 15 minutes; refresh credentials expire after 30 days. The Bridge refreshes access credentials and preserves the refresh credential in the OS credential store. The Hub remains authoritative for scopes and revocation.

## Telegram commands

- `/start`, `/help`, `/id`, `/pairinfo`: handled at the Worker edge and work without a running local Bridge.
- `/pair CODE`, `/status`, `/tasks`: encrypted/queued for the optional local Bridge. If Bridge configuration is absent, the bot responds that HUB integration is not configured instead of failing the webhook.
- No arbitrary shell execution, tool invocation, task creation, agent execution, approval decisions, or content publishing is exposed.

## Webhook registration

After Worker secrets and owner ID are configured, set these values in the ignored local `.env`:

```dotenv
TELEGRAM_WEBHOOK_URL=https://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev/telegram/webhook
TELEGRAM_WEBHOOK_SECRET=the_same_secret_configured_in_cloudflare
```

Run:

```powershell
python scripts/register_webhook.py
```

The helper checks the existing webhook and refuses to replace a different one unless `CONFIRM_REPLACE_WEBHOOK=true` is explicitly set for that registration run.

## Preferred one-time cloud registration (no local bot token)

The bot token does not need to be copied into the local `.env` file. Store it once as a Cloudflare Worker secret, together with `TELEGRAM_WEBHOOK_SECRET`. Set `ALLOWED_TELEGRAM_USER_ID` as a Worker variable. For the one-time registration operation, also create a temporary `WEBHOOK_SETUP_SECRET` Worker secret (at least 32 random characters).

Generate the temporary setup secret locally:

```powershell
py -c "import secrets; print(secrets.token_urlsafe(48))"
```

After adding it as `WEBHOOK_SETUP_SECRET` in Cloudflare, run this PowerShell command. It prompts for the setup secret without echoing it and does not ask for the bot token:

```powershell
$secure = Read-Host "Temporary webhook setup secret" -AsSecureString
$setupSecret = [System.Net.NetworkCredential]::new("", $secure).Password
try {
  Invoke-RestMethod -Method Post -Uri "https://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev/admin/register-webhook" -Headers @{ Authorization = "Bearer $setupSecret" }
} finally {
  $setupSecret = $null
  $secure.Dispose()
}
```

The Worker registers only its own pinned HTTPS webhook URL, keeps pending Telegram updates, and verifies the result with `getWebhookInfo`. The endpoint cannot set an arbitrary URL or call arbitrary Telegram methods. After a successful response, remove `WEBHOOK_SETUP_SECRET` from Worker secrets; it is no longer needed. Keep `TELEGRAM_WEBHOOK_SECRET` in Cloudflare because Telegram must send it with every webhook update.

## Operational behavior and verification

- If the local machine or Hub is offline, queued Hub commands wait in D1 until the Bridge reconnects.
- Telegram's webhook edge can remain available independently of the local Hub.
- The Worker authenticates the Telegram webhook secret and restricts processing to the configured owner in private chats.
- Bridge HMAC authentication uses short timestamp windows and one-time nonces.
- D1 stores encrypted command payloads, hashed nonces, and hashed lease tokens.
- Delivery is at-least-once across network failure windows; an ambiguous Telegram timeout can cause a repeated reply. Update IDs and job leases prevent ordinary duplicate processing.
- A deployed Worker is not the same as a configured bot. Verify webhook registration, local Keyring availability, owner pairing, and a real private-chat round trip before calling the service live.

## Health and readiness probes

- `GET /health` is a liveness probe only. It confirms that the currently deployed Worker can answer requests; it does not prove that Telegram or the Bridge is configured.
- `GET /ready` reports readiness of the Telegram cloud edge. It requires the Telegram bot token, webhook secret, owner ID, and D1 binding; it does not require the optional Bridge secrets.
- `POST /admin/register-webhook` is a one-time setup endpoint protected by the temporary `WEBHOOK_SETUP_SECRET`. It registers only the pinned Worker URL and verifies the result. Remove the temporary secret after successful registration.
- Readiness does not verify Telegram webhook registration, the optional local Bridge process, OS Keyring availability, Hub pairing, or a complete Telegram-to-Hub round trip. Those remain separate acceptance checks.

## Current provisioning status

The Worker subdomain, D1 database, binding, schema, observability, and cleanup Cron are provisioned. The cloud-first Worker source is deployed. `QUEUE_ENCRYPTION_KEY` is configured in Cloudflare. `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET`, the owner ID, and webhook registration remain required for live Telegram operation. `BRIDGE_SHARED_SECRET` is optional and is needed only if local-HUB integration is enabled. No live Telegram webhook or end-to-end round trip is claimed.
