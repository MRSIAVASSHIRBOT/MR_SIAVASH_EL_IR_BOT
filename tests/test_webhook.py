import unittest

from scripts.register_webhook import EXPECTED_WEBHOOK_HOST, validate_webhook_url


class WebhookUrlPolicyTests(unittest.TestCase):
    def test_accepts_only_the_expected_worker_webhook(self):
        self.assertTrue(
            validate_webhook_url(
                f"https://{EXPECTED_WEBHOOK_HOST}/telegram/webhook"
            )
        )

    def test_rejects_other_hosts_and_unsafe_url_parts(self):
        for value in (
            "http://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev/telegram/webhook",
            "https://attacker.example/telegram/webhook",
            "https://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev.evil.example/telegram/webhook",
            "https://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev/telegram/webhook?token=x",
            "https://user:pass@mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev/telegram/webhook",
            "https://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev/other",
        ):
            with self.subTest(value=value):
                self.assertFalse(validate_webhook_url(value))


if __name__ == "__main__":
    unittest.main()
