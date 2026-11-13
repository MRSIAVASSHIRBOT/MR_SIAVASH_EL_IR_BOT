import os
import unittest
from unittest.mock import patch

from bot import (
    BotConfigurationError,
    Config,
    NoRedirectHandler,
    TelegramAPI,
    TelegramAPIError,
    command_name,
    make_reply,
    parse_user_ids,
)


class ConfigTests(unittest.TestCase):
    def test_parse_user_ids(self):
        self.assertEqual(parse_user_ids("123, 456,123"), frozenset({123, 456}))

    def test_reject_invalid_user_ids(self):
        with self.assertRaises(BotConfigurationError):
            parse_user_ids("123,not-a-number")

    def test_config_requires_token(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "", "ALLOWED_USER_IDS": ""}, clear=True):
            with self.assertRaises(BotConfigurationError):
                Config.from_env()

    def test_config_validates_poll_timeout(self):
        env = {"TELEGRAM_BOT_TOKEN": "test-token", "POLL_TIMEOUT": "90"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(BotConfigurationError):
                Config.from_env()


class HandlerPolicyTests(unittest.TestCase):
    def test_command_name_ignores_bot_suffix(self):
        self.assertEqual(command_name("/start@sample_bot"), "/start")

    def test_onboarding_allows_id_command(self):
        self.assertIn("12345", make_reply("/id", 12345, frozenset()))

    def test_onboarding_does_not_enable_general_chat(self):
        self.assertIn("ALLOWED_USER_IDS", make_reply("hello", 12345, frozenset()))

    def test_allowlist_blocks_other_users(self):
        self.assertIsNone(make_reply("/start", 999, frozenset({123})))

    def test_allowed_user_gets_status(self):
        self.assertIn("فعال", make_reply("/status", 123, frozenset({123})))



class TelegramTransportTests(unittest.TestCase):
    def test_token_bearing_api_requests_do_not_follow_redirects(self):
        from urllib.request import Request

        handler = NoRedirectHandler()
        request = Request("https://api.telegram.org/botplaceholder/getMe")
        self.assertIsNone(
            handler.redirect_request(
                request, None, 302, "Found", {}, "https://attacker.invalid/collect"
            )
        )

    def test_oversized_api_response_is_rejected(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self, limit):
                return b"x" * limit

        class FakeOpener:
            def open(self, request, timeout):
                return FakeResponse()

        with patch("bot.telegram_opener", return_value=FakeOpener()):
            api = TelegramAPI("placeholder-token")
            with self.assertRaisesRegex(TelegramAPIError, "size limit"):
                api.call("getMe")


if __name__ == "__main__":
    unittest.main()
