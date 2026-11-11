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

function updateOnlyDb() {
  return {
    prepare(sql) {
      return {
        bind(...values) {
          return {
            first: async () => sql.includes("INSERT INTO telegram_processed_updates")
              ? { update_id: values[0] }
              : null,
            run: async () => ({ success: true }),
          };
        },
      };
    },
  };
}

function telegramOnlyEnv() {
  return {
    TELEGRAM_BOT_TOKEN: "test-token",
    TELEGRAM_WEBHOOK_SECRET: bridgeEnv.TELEGRAM_WEBHOOK_SECRET,
    ALLOWED_TELEGRAM_USER_ID: "123456789",
    DB: updateOnlyDb(),
  };
}

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

test("webhook fails closed when Telegram credentials are missing", async () => {
  const response = await worker.fetch(new Request("https://worker.example/telegram/webhook", {
    method: "POST",
    headers: { "content-type": "application/json", "X-Telegram-Bot-Api-Secret-Token": "expected-secret-value-with-at-least-32-chars" },
    body: JSON.stringify({ update_id: 2, message: { text: "/start" } }),
  }), { ...bridgeEnv, TELEGRAM_BOT_TOKEN: undefined });
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "service_not_configured" });
});

test("cloud Telegram commands work without any local Bridge secrets", async () => {
  const previousFetch = globalThis.fetch;
  let sentMessage = null;
  globalThis.fetch = async (_url, options) => {
    sentMessage = JSON.parse(options.body);
    return new Response(JSON.stringify({ ok: true, result: {} }), { status: 200 });
  };
  try {
    const response = await worker.fetch(new Request("https://worker.example/telegram/webhook", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": bridgeEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify({
        update_id: 3,
        message: {
          from: { id: 123456789 },
          chat: { id: 123456789, type: "private" },
          text: "/start",
        },
      }),
    }), telegramOnlyEnv());
    assert.equal(response.status, 200);
    assert.match(sentMessage.text, /ربات MR_SIAVASH_EL_IR_BOT آماده است/);
  } finally {
    globalThis.fetch = previousFetch;
  }
});

test("Hub commands fail gracefully when the optional Bridge is offline or unconfigured", async () => {
  const previousFetch = globalThis.fetch;
  let sentMessage = null;
  globalThis.fetch = async (_url, options) => {
    sentMessage = JSON.parse(options.body);
    return new Response(JSON.stringify({ ok: true, result: {} }), { status: 200 });
  };
  try {
    const response = await worker.fetch(new Request("https://worker.example/telegram/webhook", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": bridgeEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify({
        update_id: 4,
        message: {
          from: { id: 123456789 },
          chat: { id: 123456789, type: "private" },
          text: "/status",
        },
      }),
    }), telegramOnlyEnv());
    assert.equal(response.status, 200);
    assert.match(sentMessage.text, /اتصال HUB هنوز پیکربندی نشده است/);
  } finally {
    globalThis.fetch = previousFetch;
  }
});


test("/pairinfo formats the Telegram identity details as separate lines", async () => {
  const previousFetch = globalThis.fetch;
  let sentMessage = null;
  globalThis.fetch = async (_url, options) => {
    sentMessage = JSON.parse(options.body);
    return new Response(JSON.stringify({ ok: true, result: {} }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const env = {
    ...bridgeEnv,
    DB: {
      prepare() {
        return {
          bind(...values) {
            return {
              first: async () => ({ update_id: values[0] }),
              run: async () => ({ success: true }),
            };
          },
        };
      },
    },
  };
  try {
    const response = await worker.fetch(new Request("https://worker.example/telegram/webhook", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": bridgeEnv.TELEGRAM_WEBHOOK_SECRET,
      },
      body: JSON.stringify({
        update_id: 99,
        message: {
          from: { id: 123456789 },
          chat: { id: 123456789, type: "private" },
          text: "/pairinfo",
        },
      }),
    }), env);
    assert.equal(response.status, 200);
    assert.ok(sentMessage);
    assert.match(sentMessage.text, /\n/);
    assert.equal(sentMessage.text.includes("\\n"), false);
  } finally {
    globalThis.fetch = previousFetch;
  }
});


test("/ready checks Telegram edge readiness without requiring the optional Bridge", async () => {
  const live = await worker.fetch(new Request("https://worker.example/health"), {});
  assert.equal(live.status, 200);
  const unconfigured = await worker.fetch(new Request("https://worker.example/ready"), {});
  assert.equal(unconfigured.status, 503);
  assert.deepEqual(await unconfigured.json(), {
    status: "not_ready",
    service: "mr-siavash-el-ir-bot-edge",
  });
  const ready = await worker.fetch(new Request("https://worker.example/ready"), telegramOnlyEnv());
  assert.equal(ready.status, 200);
  assert.deepEqual(await ready.json(), {
    status: "ready",
    service: "mr-siavash-el-ir-bot-edge",
  });
});

test("Telegram edge readiness is unaffected by malformed optional Bridge configuration", async () => {
  const response = await worker.fetch(new Request("https://worker.example/ready"), {
    ...telegramOnlyEnv(),
    QUEUE_ENCRYPTION_KEY: "not-a-valid-32-byte-base64url-key",
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    status: "ready",
    service: "mr-siavash-el-ir-bot-edge",
  });
});
