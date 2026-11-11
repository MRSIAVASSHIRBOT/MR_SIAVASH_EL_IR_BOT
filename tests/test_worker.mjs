import test from "node:test";
import assert from "node:assert/strict";
import worker, {
  constantTimeEqual,
  parseTelegramCommand,
  safeHubBaseUrl,
} from "../cloudflare/worker.js";

test("accepts only HTTPS Hub origins", () => {
  assert.equal(safeHubBaseUrl("https://hub.example.com"), "https://hub.example.com");
  assert.equal(safeHubBaseUrl("https://hub.example.com/"), "https://hub.example.com");
  assert.equal(safeHubBaseUrl("http://hub.example.com"), null);
  assert.equal(safeHubBaseUrl("https://user:pass@hub.example.com"), null);
  assert.equal(safeHubBaseUrl("https://hub.example.com/private"), null);
  assert.equal(safeHubBaseUrl("https://hub.example.com/?token=x"), null);
});

test("compares webhook secrets without ordinary string equality", () => {
  assert.equal(constantTimeEqual("secret-value", "secret-value"), true);
  assert.equal(constantTimeEqual("secret-value", "secret-valuf"), false);
  assert.equal(constantTimeEqual("", ""), true);
  assert.equal(constantTimeEqual("a", "longer"), false);
});

test("parses Telegram bot commands and bot suffixes", () => {
  assert.deepEqual(parseTelegramCommand("/status@my_bot"), { command: "/status", args: [] });
  assert.deepEqual(parseTelegramCommand("/pair abc def"), { command: "/pair", args: ["abc", "def"] });
  assert.deepEqual(parseTelegramCommand("ordinary message"), { command: "", args: [] });
  assert.deepEqual(parseTelegramCommand(""), { command: "", args: [] });
});

test("health endpoint returns a minimal non-sensitive response", async () => {
  const response = await worker.fetch(new Request("https://worker.example/health"), {});
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    status: "ok",
    service: "mr-siavash-el-ir-bot-edge",
  });
});

test("webhook rejects requests with an invalid secret token", async () => {
  const env = {
    TELEGRAM_BOT_TOKEN: "test-token",
    TELEGRAM_WEBHOOK_SECRET: "expected-secret",
    SESSION_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ALLOWED_TELEGRAM_USER_ID: "123456789",
    HUB_CLIENT_ID: "3a1c9d72-6f84-4b35-9e21-7d0c8a6f4b52",
    HUB_API_BASE_URL: "https://hub.example.com",
    DB: { prepare() { throw new Error("DB must not be accessed before webhook authentication"); } },
  };
  const response = await worker.fetch(new Request("https://worker.example/telegram/webhook", {
    method: "POST",
    headers: { "content-type": "application/json", "X-Telegram-Bot-Api-Secret-Token": "wrong-secret" },
    body: JSON.stringify({ update_id: 1, message: { text: "/start" } }),
  }), env);
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: "unauthorized" });
});
