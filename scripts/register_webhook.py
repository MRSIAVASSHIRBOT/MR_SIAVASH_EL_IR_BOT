#!/usr/bin/env python3
"""Register the Cloudflare Worker as Telegram's webhook without exposing the bot token."""

from __future__ import annotations

import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from bot import load_local_env


def telegram_call(token: str, method: str, payload: dict | None = None):
    request = Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=json.dumps(payload or {}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError):
        raise RuntimeError("Telegram API request failed; check network access and local configuration.") from None
    if not isinstance(result, dict) or not result.get("ok"):
        raise RuntimeError("Telegram rejected the webhook configuration.")
    return result.get("result")


def main() -> int:
    load_local_env()
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    webhook_url = os.getenv("TELEGRAM_WEBHOOK_URL", "").strip()
    secret = os.getenv("TELEGRAM_WEBHOOK_SECRET", "").strip()

    if not token or token == "replace_with_your_token":
        print("TELEGRAM_BOT_TOKEN is missing from the local .env file.", file=sys.stderr)
        return 2
    if not re.fullmatch(r"https://[^/]+/telegram/webhook", webhook_url):
        print("TELEGRAM_WEBHOOK_URL must be the exact HTTPS Worker URL ending in /telegram/webhook.", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", secret):
        print("TELEGRAM_WEBHOOK_SECRET must use 1-256 letters, digits, underscores, or hyphens.", file=sys.stderr)
        return 2

    try:
        current = telegram_call(token, "getWebhookInfo") or {}
        current_url = current.get("url", "")
        if current_url and current_url != webhook_url and os.getenv("CONFIRM_REPLACE_WEBHOOK") != "true":
            print("A different webhook is already configured. It was not changed.")
            print("Review the current webhook in Bot API settings. Only set CONFIRM_REPLACE_WEBHOOK=true after confirming migration.")
            return 3

        result = telegram_call(token, "setWebhook", {
            "url": webhook_url,
            "secret_token": secret,
            "allowed_updates": ["message"],
            "drop_pending_updates": False,
        })
        if result is not True:
            print("Telegram did not confirm webhook registration.", file=sys.stderr)
            return 4
        verified = telegram_call(token, "getWebhookInfo") or {}
        if verified.get("url") != webhook_url:
            print("Webhook read-back did not match the requested URL.", file=sys.stderr)
            return 5
        print("Webhook registered and verified. The bot token was not displayed.")
        return 0
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 6


if __name__ == "__main__":
    raise SystemExit(main())
