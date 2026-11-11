const MAX_BODY_BYTES = 64 * 1024;
const TELEGRAM_TIMEOUT_MS = 8000;
const HUB_CLIENT_ID_DEFAULT = "3a1c9d72-6f84-4b35-9e21-7d0c8a6f4b52";
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

export function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    difference |= (a[i] || 0) ^ (b[i] || 0);
  }
  return difference === 0;
}

export function parseTelegramCommand(text) {
  if (typeof text !== "string") return { command: "", args: [] };
  const parts = text.trim().split(/\s+/);
  const first = parts.shift() || "";
  if (!first.startsWith("/")) return { command: "", args: [] };
  return { command: first.split("@", 1)[0].toLowerCase(), args: parts };
}

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - (normalized.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function queueKey(env) {
  if (typeof env.QUEUE_ENCRYPTION_KEY !== "string") throw new Error("queue encryption is not configured");
  const raw = base64UrlToBytes(env.QUEUE_ENCRYPTION_KEY);
  if (raw.byteLength !== 32) throw new Error("queue encryption key must be 32 bytes");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function encryptPayload(value, env) {
  const key = await queueKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return JSON.stringify({ iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(ciphertext)) });
}

async function decryptPayload(value, env) {
  const record = JSON.parse(value);
  if (!Array.isArray(record.iv) || record.iv.length !== 12 || !Array.isArray(record.ciphertext)) {
    throw new Error("queued payload is invalid");
  }
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(record.iv) },
    await queueKey(env),
    new Uint8Array(record.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function readBoundedJson(request) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > MAX_BODY_BYTES || !request.body) return { ok: false, status: declared > MAX_BODY_BYTES ? 413 : 400 };
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
      ? { ok: true, value, bytes }
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
    redirect: "error",
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
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_WEBHOOK_SECRET || !env.QUEUE_ENCRYPTION_KEY || !env.BRIDGE_SHARED_SECRET) {
    return "Required service secrets are missing";
  }
  if (!env.DB || typeof env.DB.prepare !== "function") return "D1 database binding is missing";
  if (!/^\d{1,20}$/.test(String(env.ALLOWED_TELEGRAM_USER_ID || ""))) return "Owner Telegram ID is invalid";
  if (String(env.BRIDGE_SHARED_SECRET).length < 32) return "Bridge shared secret is too short";
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(String(env.TELEGRAM_WEBHOOK_SECRET))) return "Telegram webhook secret format is invalid";
  return null;
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

async function enqueueJob(env, updateId, chatId, userId, payload) {
  const encrypted = await encryptPayload(payload, env);
  const jobId = crypto.randomUUID();
  const inserted = await env.DB.prepare(
    "INSERT OR IGNORE INTO telegram_jobs (job_id, update_id, chat_id, telegram_user_id, payload_ciphertext, state, lease_until, lease_token_hash, attempts, created_at, updated_at) SELECT ?, ?, ?, ?, ?, 'pending', 0, NULL, 0, unixepoch(), unixepoch() WHERE (SELECT COUNT(*) FROM telegram_jobs WHERE state IN ('pending','leased','sending')) < 1000",
  ).bind(jobId, updateId, chatId, userId, encrypted).run();
  if (Number(inserted.meta?.changes || 0) > 0) return true;
  const existing = await env.DB.prepare("SELECT job_id FROM telegram_jobs WHERE update_id = ?").bind(updateId).first();
  return Boolean(existing);
}

async function handleTelegramMessage(env, update) {
  const message = update.message;
  if (!message || typeof message !== "object") return;
  const userId = Number(message.from?.id);
  const chatId = Number(message.chat?.id);
  if (message.chat?.type !== "private" || userId !== Number(env.ALLOWED_TELEGRAM_USER_ID) || !Number.isSafeInteger(chatId)) {
    return;
  }
  const text = typeof message.text === "string" ? message.text.trim() : "";
  const { command, args } = parseTelegramCommand(text);
  if (command === "/start") {
    await sendMessage(env, chatId, "سلام ✨ ربات MR_SIAVASH_EL_IR_BOT آماده است. برای اطلاعات جفت‌سازی /pairinfo و برای اتصال /pair CODE را بفرست.");
    return;
  }
  if (command === "/help") {
    await sendMessage(env, chatId, "فرمان‌ها:\n/start — شروع\n/help — راهنما\n/id — شناسه تلگرام\n/pairinfo — اطلاعات جفت‌سازی\n/pair CODE — جفت‌سازی با HUB محلی\n/status — وضعیت HUB\n/tasks — فهرست کارها (در صورت داشتن مجوز)");
    return;
  }
  if (command === "/id") {
    await sendMessage(env, chatId, `شناسهٔ عددی تلگرام شما: ${userId}`);
    return;
  }
  if (command === "/pairinfo") {
    const clientId = String(env.HUB_CLIENT_ID || HUB_CLIENT_ID_DEFAULT);
    if (!CLIENT_ID_PATTERN.test(clientId)) {
      await sendMessage(env, chatId, "شناسهٔ کلاینت در Worker معتبر نیست؛ تنظیمات سرویس را بررسی کن.");
      return;
    }
    await sendMessage(env, chatId, `شناسه تلگرام: ${userId}\\nشناسه کلاینت HUB: ${clientId}\\nسطح دسترسی پیشنهادی: status:read`);
    return;
  }
  if (command === "/pair") {
    if (args.length !== 1 || args[0].length < 32 || args[0].length > 128) {
      await sendMessage(env, chatId, "فرمت صحیح: /pair کد_یک‌بارمصرف");
      return;
    }
    const queued = await enqueueJob(env, update.update_id, chatId, userId, { command: "pair", pairing_code: args[0] });
    if (!queued) await sendMessage(env, chatId, "صف درخواست‌ها موقتاً پر است؛ کمی بعد دوباره تلاش کن.");
    return;
  }
  if (command === "/status" || command === "/tasks") {
    const queued = await enqueueJob(env, update.update_id, chatId, userId, { command: command.slice(1) });
    if (!queued) await sendMessage(env, chatId, "صف درخواست‌ها موقتاً پر است؛ کمی بعد دوباره تلاش کن.");
    return;
  }
  await sendMessage(env, chatId, "این فرمان در نسخه فعلی پشتیبانی نمی‌شود. برای راهنما /help را بفرست.");
}

async function bridgeSignatureValid(request, bodyBytes, env) {
  const timestamp = request.headers.get("X-Bridge-Timestamp") || "";
  const nonce = request.headers.get("X-Bridge-Nonce") || "";
  const supplied = request.headers.get("X-Bridge-Signature") || "";
  if (!/^\d{10}$/.test(timestamp) || !/^[A-Za-z0-9_-]{20,80}$/.test(nonce) || !/^[a-f0-9]{64}$/i.test(supplied)) {
    return false;
  }
  if (Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp)) > 60) return false;
  const bodyHash = await sha256Hex(new TextDecoder().decode(bodyBytes));
  const message = [timestamp, nonce, request.method, new URL(request.url).pathname, bodyHash].join("\n");
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.BRIDGE_SHARED_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signatureBytes = Uint8Array.from(supplied.match(/.{2}/g), (part) => parseInt(part, 16));
  const valid = await crypto.subtle.verify("HMAC", key, signatureBytes, new TextEncoder().encode(message));
  if (!valid) return false;
  const nonceHash = await sha256Hex(nonce);
  const inserted = await env.DB.prepare(
    "INSERT INTO bridge_nonces (nonce_hash, expires_at) VALUES (?, unixepoch()+120) ON CONFLICT(nonce_hash) DO NOTHING RETURNING nonce_hash",
  ).bind(nonceHash).first();
  return Boolean(inserted);
}

async function bridgePull(env) {
  const leaseToken = Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const leaseHash = await sha256Hex(leaseToken);
  const job = await env.DB.prepare(
    "UPDATE telegram_jobs SET state='leased', lease_until=unixepoch()+60, lease_token_hash=?, attempts=attempts+1, updated_at=unixepoch() WHERE job_id=(SELECT job_id FROM telegram_jobs WHERE state='pending' OR (state IN ('leased','sending') AND lease_until < unixepoch()) ORDER BY created_at LIMIT 1) RETURNING job_id, chat_id, telegram_user_id, payload_ciphertext, attempts",
  ).bind(leaseHash).first();
  if (!job) return { job: null };
  try {
    const payload = await decryptPayload(job.payload_ciphertext, env);
    return {
      job: {
        job_id: job.job_id,
        chat_id: Number(job.chat_id),
        telegram_user_id: Number(job.telegram_user_id),
        payload,
        attempts: Number(job.attempts),
        lease_token: leaseToken,
      },
    };
  } catch {
    await env.DB.prepare(
      "UPDATE telegram_jobs SET state='pending', lease_until=0, lease_token_hash=NULL, updated_at=unixepoch() WHERE job_id=?",
    ).bind(job.job_id).run();
    throw new Error("queued payload could not be decrypted");
  }
}

async function bridgeComplete(env, payload) {
  const jobId = typeof payload.job_id === "string" ? payload.job_id : "";
  const leaseToken = typeof payload.lease_token === "string" ? payload.lease_token : "";
  const reply = typeof payload.reply === "string" ? payload.reply.slice(0, 4000) : "";
  if (!jobId || leaseToken.length < 32 || !reply) return json({ error: "invalid_completion" }, 400);
  const leaseHash = await sha256Hex(leaseToken);
  const claimed = await env.DB.prepare(
    "UPDATE telegram_jobs SET state='sending', updated_at=unixepoch() WHERE job_id=? AND state='leased' AND lease_token_hash=? AND lease_until >= unixepoch() RETURNING chat_id",
  ).bind(jobId, leaseHash).first();
  if (!claimed) return json({ error: "lease_not_valid" }, 409);
  try {
    await sendMessage(env, Number(claimed.chat_id), reply);
  } catch {
    await env.DB.prepare(
      "UPDATE telegram_jobs SET state='pending', lease_until=0, lease_token_hash=NULL, updated_at=unixepoch() WHERE job_id=? AND state='sending' AND lease_token_hash=?",
    ).bind(jobId, leaseHash).run();
    return json({ error: "telegram_delivery_failed" }, 503);
  }
  await env.DB.prepare(
    "UPDATE telegram_jobs SET state='done', lease_until=0, lease_token_hash=NULL, updated_at=unixepoch() WHERE job_id=? AND state='sending' AND lease_token_hash=?",
  ).bind(jobId, leaseHash).run();
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return json({ status: "ok", service: "mr-siavash-el-ir-bot-edge" });
    }

    if (url.pathname === "/telegram/webhook") {
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
      let claim;
      try {
        claim = await claimUpdate(env, update.update_id);
        if (claim === "done") return json({ ok: true, duplicate: true });
        if (claim === "busy") return json({ error: "update_in_progress" }, 503);
        await handleTelegramMessage(env, update);
        await completeUpdate(env, update.update_id);
        return json({ ok: true });
      } catch (error) {
        if (claim === "claimed") {
          try { await releaseUpdate(env, update.update_id); } catch { /* lease expires */ }
        }
        console.error(JSON.stringify({ event: "telegram_update_failed", update_id: update.update_id, reason: String(error?.message || "unknown").slice(0, 100) }));
        return json({ error: "temporary_failure" }, 503);
      }
    }

    if (url.pathname === "/bridge/pull" || url.pathname === "/bridge/complete") {
      if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405);
      if (!env.DB || !env.BRIDGE_SHARED_SECRET || !env.QUEUE_ENCRYPTION_KEY) {
        return json({ error: "service_not_configured" }, 503);
      }
      const parsed = await readBoundedJson(request);
      if (!parsed.ok) return json({ error: "invalid_payload" }, parsed.status);
      try {
        if (!(await bridgeSignatureValid(request, parsed.bytes, env))) return json({ error: "unauthorized" }, 401);
        if (url.pathname === "/bridge/pull") return json(await bridgePull(env));
        return await bridgeComplete(env, parsed.value);
      } catch (error) {
        console.error(JSON.stringify({ event: "bridge_request_failed", route: url.pathname, reason: String(error?.message || "unknown").slice(0, 100) }));
        return json({ error: "temporary_failure" }, 503);
      }
    }

    return json({ error: "not_found" }, 404);
  },

  async scheduled(_event, env) {
    if (!env.DB) return;
    await Promise.all([
      env.DB.prepare("DELETE FROM telegram_processed_updates WHERE state='done' AND processed_at < unixepoch()-604800").run(),
      env.DB.prepare("DELETE FROM telegram_jobs WHERE state='done' AND updated_at < unixepoch()-604800").run(),
      env.DB.prepare("DELETE FROM bridge_nonces WHERE expires_at < unixepoch()").run(),
    ]);
  },
};
