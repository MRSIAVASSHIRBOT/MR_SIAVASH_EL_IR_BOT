import test from "node:test";
import assert from "node:assert/strict";
import worker, {
  constantTimeEqual,
  parseTelegramCommand,
} from "../cloudflare/worker.js";

const bridgeEnv = {
  TELEGRAM_BOT_TOKEN: "test-token",
  TELEGRAM_WEBHOOK_SECRET: "expected-secret-value-with-at-least-32-chars",
  QUEUE_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  BRIDGE_SHARED_SECRET: "this-is-a-test-bridge-secret-with-more-than-32-chars",
  ALLOWED_TELEGRAM_USER_ID: "123456789",
  HUB_CLIENT_ID: "3a1c9d72-6f84-4b35-9e21-7d0c8a6f4b52",
  DB: { prepare() { throw new Error("DB must not be accessed before bridge authentication"); } },
};

test("compares webhook secrets without ordinary string equality", () => {
  assert.equal(constantTimeEqual("secret-value", "secret-value"), true);
  assert.equal(constantTimeEqual("secret-value", "secret-valuf"), false);
  assert.equal(constantTimeEqual("", ""), true);
  assert.equal(constantTimeEqual("a", "longer"), false);
});

test("parses Telegram commands and bot suffixes", () => {
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

test("webhook rejects requests with an invalid Telegram secret token", async () => {
  const response = await worker.fetch(new Request("https://worker.example/telegram/webhook", {
    method: "POST",
    headers: { "content-type": "application/json", "X-Telegram-Bot-Api-Secret-Token": "wrong-secret" },
    body: JSON.stringify({ update_id: 1, message: { text: "/start" } }),
  }), bridgeEnv);
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: "unauthorized" });
});

test("bridge endpoints reject unsigned requests before touching D1", async () => {
  const response = await worker.fetch(new Request("https://worker.example/bridge/pull", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  }), bridgeEnv);
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "unauthorized" });
});

test("webhook fails closed while required secrets are missing", async () => {
  const response = await worker.fetch(new Request("https://worker.example/telegram/webhook", {
    method: "POST",
    headers: { "content-type": "application/json", "X-Telegram-Bot-Api-Secret-Token": "expected-secret-value-with-at-least-32-chars" },
    body: JSON.stringify({ update_id: 2, message: { text: "/start" } }),
  }), { ...bridgeEnv, QUEUE_ENCRYPTION_KEY: undefined });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "service_not_configured" });
});
