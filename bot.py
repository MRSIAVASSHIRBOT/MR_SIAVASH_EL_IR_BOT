#!/usr/bin/env python3
"""Minimal, allowlist-aware Telegram bot using only the Python standard library."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

LOGGER = logging.getLogger("mr_siavash_bot")
MAX_MESSAGE_LENGTH = 4096
MAX_API_RESPONSE_BYTES = 1_048_576


class BotConfigurationError(RuntimeError):
    """Raised when required runtime configuration is missing or invalid."""


class TelegramAPIError(RuntimeError):
    """Raised for Telegram API or network failures without exposing credentials."""


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent a token-bearing Telegram API URL from following redirects."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def telegram_opener():
    """Build an opener that refuses HTTP redirects for token-bearing API URLs."""
    return build_opener(NoRedirectHandler())


def load_local_env(path: str = ".env") -> None:
    """Load simple KEY=VALUE pairs without overriding existing environment values."""
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


def parse_user_ids(raw: str) -> frozenset[int]:
    ids: set[int] = set()
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if not item.isdigit() or int(item) <= 0:
            raise BotConfigurationError("ALLOWED_USER_IDS must contain positive numeric Telegram user IDs.")
        ids.add(int(item))
    return frozenset(ids)


@dataclass(frozen=True)
class Config:
    token: str
    allowed_user_ids: frozenset[int]
    poll_timeout: int = 30

    @classmethod
    def from_env(cls) -> "Config":
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token or token == "replace_with_your_token":
            raise BotConfigurationError("TELEGRAM_BOT_TOKEN is not configured.")
        try:
            poll_timeout = int(os.getenv("POLL_TIMEOUT", "30"))
        except ValueError:
            raise BotConfigurationError("POLL_TIMEOUT must be an integer.") from None
        if not 1 <= poll_timeout <= 50:
            raise BotConfigurationError("POLL_TIMEOUT must be between 1 and 50 seconds.")
        allowed = parse_user_ids(os.getenv("ALLOWED_USER_IDS", ""))
        return cls(token=token, allowed_user_ids=allowed, poll_timeout=poll_timeout)


class TelegramAPI:
    def __init__(self, token: str, request_timeout: int = 40) -> None:
        self._base_url = f"https://api.telegram.org/bot{token}/"
        self._request_timeout = request_timeout
        self._opener = telegram_opener()

    def call(self, method: str, payload: dict[str, Any] | None = None) -> Any:
        body = json.dumps(payload or {}).encode("utf-8")
        request = Request(
            self._base_url + method,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self._request_timeout) as response:
                raw = response.read(MAX_API_RESPONSE_BYTES + 1)
                if len(raw) > MAX_API_RESPONSE_BYTES:
                    raise TelegramAPIError("Telegram API response exceeded the configured size limit.")
                result = json.loads(raw.decode("utf-8"))
        except HTTPError as error:
            raise TelegramAPIError(f"Telegram API returned HTTP {error.code}.") from None
        except (URLError, TimeoutError, OSError):
            raise TelegramAPIError("Could not reach the Telegram API.") from None
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise TelegramAPIError("Telegram API returned an unreadable response.") from None

        if not isinstance(result, dict) or not result.get("ok"):
            description = result.get("description", "Unknown Telegram API error") if isinstance(result, dict) else "Invalid API response"
            raise TelegramAPIError(str(description)[:240])
        return result.get("result")

    def get_me(self) -> dict[str, Any]:
        return self.call("getMe")

    def get_webhook_info(self) -> dict[str, Any]:
        return self.call("getWebhookInfo")

    def set_commands(self) -> None:
        self.call("setMyCommands", {"commands": [
            {"command": "start", "description": "شروع"},
            {"command": "help", "description": "راهنما"},
            {"command": "id", "description": "نمایش شناسه تلگرام"},
            {"command": "status", "description": "وضعیت ربات"},
        ]})

    def get_updates(self, offset: int | None, timeout: int) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"timeout": timeout, "allowed_updates": ["message"]}
        if offset is not None:
            payload["offset"] = offset
        return self.call("getUpdates", payload)

    def send_message(self, chat_id: int, text: str) -> None:
        self.call("sendMessage", {
            "chat_id": chat_id,
            "text": text[:MAX_MESSAGE_LENGTH],
            "disable_web_page_preview": True,
        })


def command_name(text: str) -> str:
    first = text.strip().split(maxsplit=1)[0] if text.strip() else ""
    if not first.startswith("/"):
        return ""
    return first.split("@", 1)[0].lower()


def make_reply(text: str, user_id: int, allowed_user_ids: frozenset[int]) -> str | None:
    """Return a safe reply, or None when the sender must be ignored."""
    if allowed_user_ids and user_id not in allowed_user_ids:
        return None

    command = command_name(text)
    if command == "/id":
        return f"شناسهٔ عددی تلگرام شما: {user_id}"
    if command == "/start":
        if not allowed_user_ids:
            return (
                "سلام ✨\n"
                "ربات با موفقیت اجرا شده است.\n"
                "برای فعال‌سازی دسترسی شخصی، ابتدا /id را بفرستید و شناسهٔ خود را "
                "در ALLOWED_USER_IDS در فایل محلی .env قرار دهید."
            )
        return "سلام ✨ ربات آمادهٔ دریافت پیام است. برای راهنما /help را بفرستید."
    if command == "/help":
        return (
            "راهنمای ربات\n"
            "/start — شروع\n"
            "/id — شناسهٔ تلگرام\n"
            "/status — وضعیت اجرا\n"
            "/help — راهنما"
        )
    if not allowed_user_ids:
        return "برای فعال‌شدن دسترسی، ابتدا شناسهٔ خود را با /id دریافت و در ALLOWED_USER_IDS تنظیم کنید."
    if command == "/status":
        return "وضعیت: فعال و در حال دریافت پیام‌ها از تلگرام ✨"
    if command:
        return "این فرمان در نسخهٔ فعلی تعریف نشده است. /help"
    return "پیامت دریافت شد ✨ اتصال قابلیت‌های هوش مصنوعی در مرحلهٔ بعد اضافه می‌شود."


class TelegramBot:
    def __init__(self, config: Config, api: TelegramAPI | None = None) -> None:
        self.config = config
        self.api = api or TelegramAPI(config.token)

    def handle_update(self, update: dict[str, Any]) -> None:
        message = update.get("message")
        if not isinstance(message, dict):
            return
        chat = message.get("chat") or {}
        sender = message.get("from") or {}
        text = message.get("text")
        if chat.get("type") != "private" or not isinstance(text, str):
            return
        user_id = sender.get("id")
        chat_id = chat.get("id")
        if not isinstance(user_id, int) or not isinstance(chat_id, int):
            return
        reply = make_reply(text, user_id, self.config.allowed_user_ids)
        if reply is not None:
            self.api.send_message(chat_id, reply)

    def run(self) -> None:
        me = self.api.get_me()
        webhook = self.api.get_webhook_info()
        if webhook.get("url"):
            raise BotConfigurationError(
                "A webhook is already configured for this bot. Polling was not started and the webhook was not changed. "
                "Confirm the migration before switching update modes."
            )
        self.api.set_commands()
        LOGGER.info("Bot initialized as @%s. Polling is active.", me.get("username", "unknown"))
        if not self.config.allowed_user_ids:
            LOGGER.warning("Owner allowlist is empty: onboarding mode is active; only setup commands are available.")

        offset: int | None = None
        backoff = 1
        while True:
            try:
                updates = self.api.get_updates(offset, self.config.poll_timeout)
                backoff = 1
                for update in updates:
                    try:
                        self.handle_update(update)
                    except TelegramAPIError:
                        LOGGER.error("A message could not be answered because the Telegram API request failed.")
                    except Exception:
                        LOGGER.exception("An update could not be processed.")
                    update_id = update.get("update_id")
                    if isinstance(update_id, int):
                        offset = update_id + 1
            except TelegramAPIError:
                LOGGER.warning("Telegram connection failed; retrying in %s second(s).", backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)


def main() -> int:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    load_local_env()
    try:
        config = Config.from_env()
        TelegramBot(config).run()
    except BotConfigurationError as error:
        LOGGER.error("%s", error)
        return 2
    except TelegramAPIError:
        LOGGER.error("Startup failed while contacting Telegram. Check network access and the configured token.")
        return 3
    except KeyboardInterrupt:
        LOGGER.info("Shutdown requested.")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
