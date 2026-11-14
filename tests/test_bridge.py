import json
import unittest

from bridge import (
    BridgeError,
    LocalBridge,
    sign_request,
    signing_message,
    validate_hub_url,
    validate_worker_url,
)


class FakeKeyring:
    def __init__(self):
        self.values = {}

    def get_password(self, service, username):
        return self.values.get((service, username))

    def set_password(self, service, username, value):
        self.values[(service, username)] = value


class UrlPolicyTests(unittest.TestCase):
    def test_accepts_worker_https_origin(self):
        self.assertEqual(
            validate_worker_url("https://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev"),
            "https://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev",
        )

    def test_rejects_non_https_or_path_worker_url(self):
        for value in (
            "http://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev",
            "https://worker.example",
            "https://mr-siavash-el-ir-bot.mrsiavashirbot.workers.dev/api",
            "https://user:pass@worker.example",
            "https://worker.example/?token=x",
        ):
            with self.subTest(value=value), self.assertRaises(BridgeError):
                validate_worker_url(value)

    def test_accepts_only_loopback_hub(self):
        self.assertEqual(validate_hub_url("http://127.0.0.1:8000"), "http://127.0.0.1:8000")

    def test_rejects_remote_hub_addresses(self):
        for value in (
            "https://hub.example.com",
            "http://localhost:8000",
            "http://192.168.1.20:8000",
            "http://0.0.0.0:8000",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8000/private",
            "http://user:pass@127.0.0.1:8000",
        ):
            with self.subTest(value=value), self.assertRaises(BridgeError):
                validate_hub_url(value)


class RequestSigningTests(unittest.TestCase):
    def test_signing_message_binds_timestamp_nonce_method_path_and_body(self):
        body = b'{"job":1}'
        message = signing_message("1794400000", "nonce-value", "POST", "/bridge/pull", body)
        self.assertIn(b"1794400000\nnonce-value\nPOST\n/bridge/pull\n", message)
        self.assertTrue(message.endswith(__import__("hashlib").sha256(body).hexdigest().encode()))

    def test_signature_changes_when_path_or_body_changes(self):
        secret = "test-secret-that-is-longer-than-thirty-two-characters"
        first = sign_request(secret, "1794400000", "nonce-value", "POST", "/bridge/pull", b"{}")
        changed_path = sign_request(secret, "1794400000", "nonce-value", "POST", "/bridge/complete", b"{}")
        changed_body = sign_request(secret, "1794400000", "nonce-value", "POST", "/bridge/pull", b'{"x":1}')
        self.assertNotEqual(first, changed_path)
        self.assertNotEqual(first, changed_body)


class OwnerBoundaryTests(unittest.TestCase):
    def test_bridge_rejects_job_for_another_telegram_identity(self):
        bridge = LocalBridge.__new__(LocalBridge)
        bridge.config = type("Config", (), {"telegram_owner_id": 123456789})()
        reply = bridge.process_job({
            "telegram_user_id": 999999999,
            "chat_id": 999999999,
            "payload": {"command": "status"},
        })
        self.assertIn("عدم تطابق", reply)


class CredentialStoreTests(unittest.TestCase):
    def test_hub_credentials_are_written_to_keyring_and_read_back(self):
        keyring = FakeKeyring()
        bridge = LocalBridge.__new__(LocalBridge)
        bridge.config = type("Config", (), {
            "client_id": "3a1c9d72-6f84-4b35-9e21-7d0c8a6f4b52",
            "telegram_owner_id": 123456789,
        })()
        bridge.keyring = keyring
        session = {
            "access_token": "access-secret",
            "refresh_token": "refresh-secret",
            "access_expires_at": 1794400900,
            "scopes": ["status:read"],
            "untrusted_extra": "must-not-be-stored",
        }
        bridge._save_hub_session(session)
        loaded = bridge._load_hub_session()
        self.assertEqual(loaded["access_token"], "access-secret")
        self.assertEqual(loaded["refresh_token"], "refresh-secret")
        stored = next(iter(keyring.values.values()))
        self.assertNotIn("untrusted_extra", stored)
        self.assertEqual(json.loads(stored)["scopes"], ["status:read"])


if __name__ == "__main__":
    unittest.main()
