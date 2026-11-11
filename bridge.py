#!/usr/bin/env python3
"""Outbound-only bridge between Cloudflare Worker and the loopback-only Hub."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

LOGGER = logging.getLogger("mr_siavash_bridge")
SERVICE_NAME = "MR_SIAVASH_EL_IR_BOT"
BRIDGE_SECRET_ACCOUNT = "bridge-shared-secret"
HUB_CLIENT_ID_DEFAULT = "3a1c9d72-6f84-4b35-9e21-7d0c8a6f4b52"
DEFAULT_WORKER_URL = "https://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev"
MAX_RESPONSE_BYTES = 64 * 1024


class BridgeError(RuntimeError):
    """A safe, user-displayable bridge failure."""


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def load_local_env(path: str = ".env") -> None:
    env_file = Path(path)
    if not env_file.is_file():
        return
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key.replace("_", "").isalnum():
            os.environ.setdefault(key, value)


def validate_worker_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise BridgeError("BRIDGE_BASE_URL must be an HTTPS origin without credentials or a path.")
    return f"https://{parsed.netloc}"


def validate_hub_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise BridgeError("HUB_API_BASE_URL must point to the local loopback Hub only.")
    return f"http://{parsed.netloc}"


def signing_message(timestamp: str, nonce: str, method: str, path: str, body: bytes) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return "\n".join((timestamp, nonce, method.upper(), path, digest)).encode("utf-8")


def sign_request(secret: str, timestamp: str, nonce: str, method: str, path: str, body: bytes) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        signing_message(timestamp, nonce, method, path, body),
        hashlib.sha256,
    ).hexdigest()


def _keyring_module():
    try:
        import keyring
    except ImportError as exc:
        raise BridgeError("The keyring package is missing. Install requirements.txt first.") from exc
    try:
        backend = keyring.get_keyring()
        if float(getattr(backend, "priority", 0)) <= 0:
            raise BridgeError("No trusted operating-system credential store is available; refusing plaintext fallback.")
    except BridgeError:
        raise
    except Exception as exc:
        raise BridgeError("The operating-system credential store is unavailable.") from exc
    return keyring


def store_bridge_secret(secret: str) -> None:
    if len(secret) < 32:
        raise BridgeError("The bridge shared secret must contain at least 32 characters.")
    keyring = _keyring_module()
    try:
        keyring.set_password(SERVICE_NAME, BRIDGE_SECRET_ACCOUNT, secret)
    except Exception as exc:
        raise BridgeError("Could not store the bridge secret in the operating-system credential store.") from exc


def load_bridge_secret() -> str:
    keyring = _keyring_module()
    try:
        secret = keyring.get_password(SERVICE_NAME, BRIDGE_SECRET_ACCOUNT)
        if not secret:
            supplied = os.getenv("BRIDGE_SHARED_SECRET", "").strip()
            if supplied:
                keyring.set_password(SERVICE_NAME, BRIDGE_SECRET_ACCOUNT, supplied)
                secret = supplied
    except Exception as exc:
        raise BridgeError("Could not read the bridge secret from the operating-system credential store.") from exc
    if not secret or len(secret) < 32:
        raise BridgeError("Bridge secret is not configured. Run: python bridge.py --init-secret")
    return secret


@dataclass(frozen=True)
class BridgeConfig:
    worker_base_url: str
    hub_base_url: str
    client_id: str
    telegram_owner_id: int
    shared_secret: str

    @classmethod
    def from_env(cls) -> "BridgeConfig":
        worker = validate_worker_url(os.getenv("BRIDGE_BASE_URL", DEFAULT_WORKER_URL).strip())
        hub = validate_hub_url(os.getenv("HUB_API_BASE_URL", "http://127.0.0.1:8000").strip())
        client_id = os.getenv("HUB_CLIENT_ID", HUB_CLIENT_ID_DEFAULT).strip()
        if len(client_id) != 36 or client_id.count("-") != 4:
            raise BridgeError("HUB_CLIENT_ID is invalid.")
        raw_owner = os.getenv("TELEGRAM_OWNER_ID", "").strip()
        if not raw_owner.isdigit() or int(raw_owner) <= 0:
            raise BridgeError("TELEGRAM_OWNER_ID must be the owner's positive numeric Telegram ID.")
        return cls(
            worker_base_url=worker,
            hub_base_url=hub,
            client_id=client_id,
            telegram_owner_id=int(raw_owner),
            shared_secret=load_bridge_secret(),
        )


def request_json(url: str, method: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    request = Request(
        url,
        data=body,
        headers={"Accept": "application/json", **(headers or {})},
        method=method,
    )
    opener = build_opener(NoRedirectHandler())
    try:
        with opener.open(request, timeout=10) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise BridgeError("A remote response exceeded the configured size limit.")
            result = json.loads(raw.decode("utf-8"))
    except HTTPError as exc:
        raise BridgeError(f"Service request failed with HTTP {exc.code}.") from None
    except (URLError, TimeoutError, OSError):
        raise BridgeError("A required service is unavailable or unreachable.") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BridgeError("A service returned an invalid response.") from None
    if not isinstance(result, dict):
        raise BridgeError("A service returned an unexpected response.")
    return result


class LocalBridge:
    def __init__(self, config: BridgeConfig, keyring_module=None) -> None:
        self.config = config
        self.keyring = keyring_module or _keyring_module()

    def _credential_account(self) -> str:
        return f"hub-client:{self.config.client_id}:{self.config.telegram_owner_id}"

    def _load_hub_session(self) -> dict[str, Any] | None:
        try:
            raw = self.keyring.get_password(SERVICE_NAME, self._credential_account())
            if not raw:
                return None
            session = json.loads(raw)
        except Exception as exc:
            raise BridgeError("Could not read the paired Hub credentials from the OS credential store.") from exc
        if not isinstance(session, dict) or not session.get("refresh_token"):
            raise BridgeError("Stored Hub credentials are invalid; revoke and pair the client again.")
        return session

    def _save_hub_session(self, session: dict[str, Any]) -> None:
        safe = {
            "access_token": session["access_token"],
            "refresh_token": session["refresh_token"],
            "access_expires_at": int(session["access_expires_at"]),
            "scopes": list(session.get("scopes", [])),
        }
        try:
            self.keyring.set_password(
                SERVICE_NAME,
                self._credential_account(),
                json.dumps(safe, separators=(",", ":")),
            )
        except Exception as exc:
            raise BridgeError("Could not securely store Hub credentials in the OS credential store.") from exc

    def _hub_request(self, path: str, method: str = "GET", payload: dict[str, Any] | None = None,
                     access_token: str | None = None) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
            headers["X-Telegram-User-Id"] = str(self.config.telegram_owner_id)
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
        return request_json(self.config.hub_base_url + path, method, body, headers)

    def _pair(self, pairing_code: str) -> str:
        if self._load_hub_session():
            return "این کلاینت قبلاً جفت‌سازی شده است. برای بررسی اتصال /status را بفرست."
        result = self._hub_request(
            "/integrations/telegram/exchange",
            "POST",
            {
                "pairing_code": pairing_code,
                "telegram_user_id": self.config.telegram_owner_id,
                "client_id": self.config.client_id,
            },
        )
        if not result.get("access_token") or not result.get("refresh_token"):
            raise BridgeError("پاسخ جفت‌سازی HUB کامل نیست.")
        self._save_hub_session({
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "access_expires_at": int(time.time()) + int(result.get("expires_in", 900)),
            "scopes": result.get("scopes", ["status:read"]),
        })
        return "اتصال امن به HUB محلی برقرار شد. اعتبارنامه‌ها فقط در OS Keyring ذخیره شدند. ✨"

    def _session(self) -> dict[str, Any] | None:
        session = self._load_hub_session()
        if not session:
            return None
        if int(session.get("access_expires_at", 0)) <= int(time.time()) + 30:
            refreshed = self._hub_request(
                "/integrations/telegram/refresh",
                "POST",
                {
                    "refresh_token": session["refresh_token"],
                    "telegram_user_id": self.config.telegram_owner_id,
                },
            )
            if not refreshed.get("access_token"):
                raise BridgeError("HUB نتوانست نشست کلاینت را تمدید کند؛ اتصال را بررسی یا دوباره جفت‌سازی کن.")
            session["access_token"] = refreshed["access_token"]
            session["access_expires_at"] = int(time.time()) + int(refreshed.get("expires_in", 900))
            session["scopes"] = refreshed.get("scopes", session.get("scopes", []))
            self._save_hub_session(session)
        return session

    def _signed_worker_post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(24)
        signature = sign_request(self.config.shared_secret, timestamp, nonce, "POST", path, body)
        return request_json(
            self.config.worker_base_url + path,
            "POST",
            body,
            {
                "Content-Type": "application/json",
                "X-Bridge-Timestamp": timestamp,
                "X-Bridge-Nonce": nonce,
                "X-Bridge-Signature": signature,
            },
        )

    def pull_one(self) -> dict[str, Any] | None:
        result = self._signed_worker_post("/bridge/pull", {})
        job = result.get("job")
        return job if isinstance(job, dict) else None

    def process_job(self, job: dict[str, Any]) -> str:
        payload = job.get("payload")
        if not isinstance(payload, dict):
            return "درخواست دریافتی معتبر نبود."
        command = payload.get("command")
        try:
            if command == "pair":
                code = payload.get("pairing_code")
                if not isinstance(code, str) or not 32 <= len(code) <= 128:
                    return "کد جفت‌سازی معتبر نیست."
                return self._pair(code)
            session = self._session()
            if not session:
                return "هنوز به HUB متصل نشده‌ای. ابتدا از پنل محلی HUB کد یک‌بارمصرف بساز و سپس /pair CODE را ارسال کن."
            headers_token = session["access_token"]
            if command == "status":
                status = self._hub_request(
                    "/integrations/telegram/status",
                    access_token=headers_token,
                )
                scopes = status.get("scopes", [])
                return (
                    "وضعیت HUB: متصل و احراز هویت‌شده ✨\n"
                    f"شناسه کلاینت: {status.get('client_id', self.config.client_id)}\n"
                    f"مجوزها: {', '.join(scopes) if scopes else 'بدون مجوز'}"
                )
            if command == "tasks":
                if "tasks:read" not in session.get("scopes", []):
                    return "مجوز tasks:read برای این ربات صادر نشده است. سطح دسترسی را از پنل HUB مدیریت کن."
                result = self._hub_request(
                    "/integrations/telegram/tasks?limit=10",
                    access_token=headers_token,
                )
                tasks = result.get("tasks", [])
                if not tasks:
                    return "در حال حاضر کاری برای نمایش وجود ندارد."
                lines = []
                for index, task in enumerate(tasks[:10], 1):
                    description = str(task.get("description") or task.get("task_type") or "کار")[:160]
                    lines.append(f"{index}. {description} — {task.get('status', 'نامشخص')}")
                return "\n".join(lines)
            return "این فرمان در Bridge تعریف نشده است."
        except BridgeError as exc:
            return str(exc)

    def complete(self, job: dict[str, Any], reply: str) -> None:
        self._signed_worker_post(
            "/bridge/complete",
            {
                "job_id": job.get("job_id"),
                "lease_token": job.get("lease_token"),
                "reply": reply[:4000],
            },
        )

    def run_once(self) -> bool:
        job = self.pull_one()
        if not job:
            return False
        reply = self.process_job(job)
        self.complete(job, reply)
        return True

    def run(self) -> None:
        LOGGER.info("Local Bridge started. Hub access is restricted to loopback.")
        backoff = 2
        while True:
            try:
                processed = self.run_once()
                backoff = 2
                if not processed:
                    time.sleep(2)
            except KeyboardInterrupt:
                LOGGER.info("Shutdown requested.")
                return
            except BridgeError as exc:
                LOGGER.warning("Bridge cycle unavailable: %s", exc)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
            except Exception:
                LOGGER.exception("Unexpected bridge failure; retrying safely.")
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)


def main() -> int:
    parser = argparse.ArgumentParser(description="Outbound-only Telegram to local Hub bridge")
    parser.add_argument("--init-secret", action="store_true", help="Store the Cloudflare bridge secret in the OS credential store")
    args = parser.parse_args()
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    load_local_env()
    try:
        if args.init_secret:
            secret = getpass("Paste the Cloudflare BRIDGE_SHARED_SECRET (input hidden): ").strip()
            store_bridge_secret(secret)
            LOGGER.info("Bridge secret stored in the operating-system credential store.")
            return 0
        config = BridgeConfig.from_env()
        LocalBridge(config).run()
    except BridgeError as exc:
        LOGGER.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        LOGGER.info("Shutdown requested.")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
