const MAX_BODY_BYTES = 64 * 1024;
const HUB_TIMEOUT_MS = 8000;
const TELEGRAM_TIMEOUT_MS = 8000;
const CLIENT_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

export function safeHubBaseUrl(value) {
  if (typeof value !== "string" || value.length > 500) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) return null;
    if (url.pathname !== "/" && url.pathname !== "") return null;
    return url.origin;
  } catch {
    return null;
  }
}

export function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    difference |= (a[i % (a.length || 1)] || 0) ^ (b[i % (b.length || 1)] || 0);
  }
  return difference === 0;
}

export function parseTelegramCommand(text) {
  if (typeof text !== "string") return { command: "", args: [] };
  const parts = text.trim().split(/\s+/);
  const first = parts.shift() || "";
  if (!first.startsWith("/")) return { command: "", args: [] };
  return {
    command: first.split("@", 1)[0].toLowerCase(),
    args: parts,
  };
}

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function encryptionKey(env) {
  if (typeof env.SESSION_ENCRYPTION_KEY !== "string") throw new Error("session encryption is not configured");
  const raw = base64UrlToBytes(env.SESSION_ENCRYPTION_KEY);
  if (raw.byteLength !== 32) throw new Error("session encryption key must be 32 bytes");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encryptSession(value, env) {
  const key = await encryptionKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return JSON.stringify({
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(ciphertext)),
  });
}

async function decryptSession(value, env) {
  const record = JSON.parse(value);
  if (!Array.isArray(record.iv) || record.iv.length !== 12 || !Array.isArray(record.ciphertext)) {
    throw new Error("stored credential record is invalid");
  }
  const key = await encryptionKey(env);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(record.iv) },
    key,
    new Uint8Array(record.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function readBoundedJson(request) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > MAX_BODY_BYTES) return { ok: false, status: 413 };
  if (!request.body) return { ok: false, status: 400 };
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        return { ok: false, status: 413 };
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return value && typeof value === "object" && !Array.isArray(value)
      ? { ok: true, value }
      : { ok: false, status: 400 };
  } catch {
    return { ok: false, status: 400 };
  }
}

async function telegramCall(env, method, payload) {
  const response = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(TELEGRAM_TIMEOUT_MS),
  });
  const data = await response.json().catch(() => null);
  if (!response.ok || !data?.ok) throw new Error("Telegram API request failed");
  return data.result;
}

async function sendMessage(env, chatId, text) {
  await telegramCall(env, "sendMessage", {
    chat_id: chatId,
    text: String(text).slice(0, 4000),
    disable_web_page_preview: true,
  });
}

function validateEnvironment(env) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_WEBHOOK_SECRET || !env.SESSION_ENCRYPTION_KEY) {
    return "Telegram or session secrets are missing";
  }
  if (!env.DB || typeof env.DB.prepare !== "function") return "D1 database binding is missing";
  if (!/^\d{1,20}$/.test(String(env.ALLOWED_TELEGRAM_USER_ID || ""))) return "Owner Telegram ID is invalid";
  if (!CLIENT_ID_PATTERN.test(String(env.HUB_CLIENT_ID || ""))) return "Hub client ID is invalid";
  if (!safeHubBaseUrl(env.HUB_API_BASE_URL)) return "Hub API base URL must be an HTTPS origin";
  if (Boolean(env.CF_ACCESS_CLIENT_ID) !== Boolean(env.CF_ACCESS_CLIENT_SECRET)) return "Both Cloudflare Access service-token values must be configured together";
  return null;
}

async function hubRequest(env, path, init = {}) {
  const base = safeHubBaseUrl(env.HUB_API_BASE_URL);
  if (!base) throw new Error("Hub API URL is not configured safely");
  return fetch(new URL(path, base), {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(env.CF_ACCESS_CLIENT_ID ? { "CF-Access-Client-Id": env.CF_ACCESS_CLIENT_ID, "CF-Access-Client-Secret": env.CF_ACCESS_CLIENT_SECRET } : {}),
      ...(init.headers || {}),
    },
    signal: AbortSignal.timeout(HUB_TIMEOUT_MS),
    redirect: "error",
  });
}

async function saveSession(env, session) {
  const encrypted = await encryptSession({
    access_token: session.access_token,
    refresh_token: session.refresh_token,
  }, env);
  await env.DB.prepare(
    "INSERT INTO telegram_sessions (client_id, telegram_user_id, credential_ciphertext, access_expires_at, scopes_json, updated_at) VALUES (?, ?, ?, ?, ?, unixepoch()) ON CONFLICT(client_id) DO UPDATE SET telegram_user_id=excluded.telegram_user_id, credential_ciphertext=excluded.credential_ciphertext, access_expires_at=excluded.access_expires_at, scopes_json=excluded.scopes_json, updated_at=unixepoch()",
  ).bind(
    env.HUB_CLIENT_ID,
    Number(env.ALLOWED_TELEGRAM_USER_ID),
    encrypted,
    Math.floor(Date.now() / 1000) + Number(session.expires_in || 900),
    JSON.stringify(session.scopes || []),
  ).run();
}

async function loadSession(env) {
  const row = await env.DB.prepare(
    "SELECT credential_ciphertext, access_expires_at, scopes_json FROM telegram_sessions WHERE client_id = ? AND telegram_user_id = ?",
  ).bind(env.HUB_CLIENT_ID, Number(env.ALLOWED_TELEGRAM_USER_ID)).first();
  if (!row) return null;
  const credentials = await decryptSession(row.credential_ciphertext, env);
  return {
    ...credentials,
    access_expires_at: Number(row.access_expires_at),
    scopes: JSON.parse(row.scopes_json || "[]"),
  };
}

async function refreshSession(env, session) {
  const response = await hubRequest(env, "/integrations/telegram/refresh", {
    method: "POST",
    body: JSON.stringify({
      refresh_token: session.refresh_token,
      telegram_user_id: Number(env.ALLOWED_TELEGRAM_USER_ID),
    }),
  });
  if (!response.ok) throw new Error("Hub session refresh failed");
  const result = await response.json();
  const refreshed = {
    access_token: result.access_token,
    refresh_token: session.refresh_token,
    expires_in: result.expires_in,
    scopes: result.scopes || session.scopes,
  };
  await saveSession(env, refreshed);
  return { ...refreshed, access_expires_at: Math.floor(Date.now() / 1000) + Number(refreshed.expires_in) };
}

async function authenticatedHubRequest(env, path, session, init = {}) {
  let current = session;
  if (current.access_expires_at <= Math.floor(Date.now() / 1000) + 30) {
    current = await refreshSession(env, current);
  }
  const headers = {
    authorization: `Bearer ${current.access_token}`,
    "x-telegram-user-id": String(env.ALLOWED_TELEGRAM_USER_ID),
    ...(init.headers || {}),
  };
  let response = await hubRequest(env, path, { ...init, headers });
  if (response.status === 401) {
    current = await refreshSession(env, current);
    response = await hubRequest(env, path, {
      ...init,
      headers: {
        authorization: `Bearer ${current.access_token}`,
        "x-telegram-user-id": String(env.ALLOWED_TELEGRAM_USER_ID),
        ...(init.headers || {}),
      },
    });
  }
  return response;
}

async function pairHub(env, pairingCode) {
  const response = await hubRequest(env, "/integrations/telegram/exchange", {
    method: "POST",
    body: JSON.stringify({
      pairing_code: pairingCode,
      telegram_user_id: Number(env.ALLOWED_TELEGRAM_USER_ID),
      client_id: env.HUB_CLIENT_ID,
    }),
  });
  if (!response.ok) throw new Error("Hub pairing was rejected");
  const session = await response.json();
  if (!session.access_token || !session.refresh_token) throw new Error("Hub pairing response is incomplete");
  await saveSession(env, session);
}

async function processMessage(env, message) {
  const userId = Number(message.from?.id);
  const chatId = Number(message.chat?.id);
  const text = typeof message.text === "string" ? message.text : "";
  if (message.chat?.type !== "private" || userId !== Number(env.ALLOWED_TELEGRAM_USER_ID) || !chatId) {
    return null;
  }

  const { command, args } = parseTelegramCommand(text);
  if (command === "/id") return `شناسهٔ عددی تلگرام شما: ${userId}`;
  if (command === "/start") {
    return "سلام ✨ ربات امن MR_SIAVASH_EL_IR_BOT فعال است. برای اتصال به HUB، کد یک‌بارمصرف جفت‌سازی را با /pair CODE ارسال کن.";
  }
  if (command === "/help") {
    return "فرمان‌ها:\n/start — شروع\n/id — شناسه تلگرام\n/pair CODE — اتصال امن به MR_SIAVASH_HUB_AI\n/status — وضعیت اتصال به HUB\n/tasks — فهرست کارهای مجاز";
  }
  if (command === "/pair") {
    if (args.length !== 1 || args[0].length < 32 || args[0].length > 128) {
      return "فرمت صحیح: /pair کد_یک‌بارمصرف";
    }
    if (await loadSession(env)) return "این ربات قبلاً به HUB متصل شده است. برای بررسی اتصال /status را بفرست.";
    await pairHub(env, args[0]);
    return "اتصال امن به MR_SIAVASH_HUB_AI برقرار شد. ✨";
  }
  if (command === "/status") {
    const session = await loadSession(env);
    if (!session) return "هنوز به HUB متصل نشده‌ای. ابتدا کد جفت‌سازی را با /pair ارسال کن.";
    const response = await authenticatedHubRequest(env, "/integrations/telegram/status", session);
    if (!response.ok) throw new Error("Hub status request failed");
    const status = await response.json();
    return `اتصال HUB: ${status.status === "authenticated" ? "فعال" : "نامشخص"}\nسطوح دسترسی: ${(status.scopes || []).join(", ") || "بدون دسترسی"}`;
  }
  if (command === "/tasks") {
    const session = await loadSession(env);
    if (!session) return "ابتدا ربات را با HUB جفت‌سازی کن: /pair CODE";
    if (!session.scopes.includes("tasks:read")) return "مجوز tasks:read برای این ربات صادر نشده است. دسترسی‌ها را از پنل HUB مدیریت کن.";
    const response = await authenticatedHubRequest(env, "/integrations/telegram/tasks?limit=10", session);
    if (!response.ok) throw new Error("Hub tasks request failed");
    const result = await response.json();
    const tasks = Array.isArray(result.tasks) ? result.tasks : [];
    if (!tasks.length) return "در حال حاضر کاری برای نمایش وجود ندارد.";
    return tasks.slice(0, 10).map((task, index) => `${index + 1}. ${String(task.description || task.task_type || "کار").slice(0, 160)} — ${task.status || "نامشخص"}`).join("\n");
  }
  if (!text.trim()) return null;
  return "پیامت دریافت شد. برای مشاهده قابلیت‌های فعال /help را بفرست.";
}

async function claimUpdate(env, updateId) {
  const result = await env.DB.prepare(
    "INSERT INTO telegram_processed_updates (update_id, state, lease_until, processed_at) VALUES (?, 'processing', unixepoch()+15, NULL) ON CONFLICT(update_id) DO UPDATE SET state='processing', lease_until=unixepoch()+15 WHERE telegram_processed_updates.state != 'done' AND telegram_processed_updates.lease_until < unixepoch() RETURNING update_id",
  ).bind(updateId).first();
  if (result) return "claimed";
  const existing = await env.DB.prepare(
    "SELECT state FROM telegram_processed_updates WHERE update_id = ?",
  ).bind(updateId).first();
  return existing?.state === "done" ? "done" : "busy";
}

async function completeUpdate(env, updateId) {
  await env.DB.prepare(
    "UPDATE telegram_processed_updates SET state='done', lease_until=0, processed_at=unixepoch() WHERE update_id=?",
  ).bind(updateId).run();
}

async function releaseUpdate(env, updateId) {
  await env.DB.prepare(
    "UPDATE telegram_processed_updates SET state='retry', lease_until=unixepoch() WHERE update_id=? AND state='processing'",
  ).bind(updateId).run();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return json({ status: "ok", service: "mr-siavash-el-ir-bot-edge" });
    }
    if (url.pathname !== "/telegram/webhook") return json({ error: "not_found" }, 404);
    if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);

    const configError = validateEnvironment(env);
    if (configError) return json({ error: "service_not_configured" }, 503);
    const receivedSecret = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
    if (!constantTimeEqual(receivedSecret, env.TELEGRAM_WEBHOOK_SECRET)) {
      return json({ error: "unauthorized" }, 403);
    }

    const parsed = await readBoundedJson(request);
    if (!parsed.ok) return json({ error: "invalid_payload" }, parsed.status);
    const update = parsed.value;
    if (!Number.isSafeInteger(update.update_id) || update.update_id < 0) return json({ ok: true });
    const message = update.message;
    if (!message || typeof message !== "object") return json({ ok: true });

    let claim;
    try {
      claim = await claimUpdate(env, update.update_id);
      if (claim === "done") return json({ ok: true, duplicate: true });
      if (claim === "busy") return json({ error: "update_in_progress" }, 503);
      const reply = await processMessage(env, message);
      if (reply !== null) await sendMessage(env, Number(message.chat.id), reply);
      await completeUpdate(env, update.update_id);
      return json({ ok: true });
    } catch (error) {
      if (claim === "claimed") {
        try { await releaseUpdate(env, update.update_id); } catch { /* retry lease expires */ }
      }
      console.error(JSON.stringify({ event: "telegram_update_failed", update_id: update.update_id, reason: String(error?.message || "unknown").slice(0, 120) }));
      return json({ error: "temporary_failure" }, 503);
    }
  },

  async scheduled(_event, env) {
    if (env.DB) {
      await env.DB.prepare(
        "DELETE FROM telegram_processed_updates WHERE state='done' AND processed_at < unixepoch()-604800",
      ).run();
    }
  },
};
