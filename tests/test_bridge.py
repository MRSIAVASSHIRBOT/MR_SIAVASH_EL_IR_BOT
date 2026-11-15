import json
import unittest
from unittest.mock import patch
from uuid import UUID

from bridge import (
    BridgeError,
    LocalBridge,
    request_json,
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


class TaskSubmissionTests(unittest.TestCase):
    def _bridge(self, scopes):
        bridge = LocalBridge.__new__(LocalBridge)
        bridge.config = type("Config", (), {"telegram_owner_id": 123456789})()
        bridge._session = lambda: {"access_token": "access-secret", "scopes": scopes}
        return bridge

    def _job(self, **overrides):
        payload = {
            "command": "task",
            "task_type": "analysis.summarize",
            "description": "Summarize the project status",
            "idempotency_key": "telegram-update-12345",
        }
        payload.update(overrides)
        return {
            "telegram_user_id": 123456789,
            "chat_id": 123456789,
            "payload": payload,
        }

    def test_task_submission_uses_hub_policy_endpoint_and_idempotency(self):
        bridge = self._bridge(["status:read", "tasks:create"])
        calls = []

        def hub_request(path, method="GET", payload=None, access_token=None, extra_headers=None):
            calls.append((path, method, payload, access_token, extra_headers))
            return {
                "task_id": "c9d78b6a-18c8-4e76-a8b1-49f09a9ec1e2",
                "status": "waiting_approval",
                "risk_class": "high",
            }

        bridge._hub_request = hub_request
        reply = bridge.process_job(self._job())
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "/integrations/telegram/tasks")
        self.assertEqual(calls[0][1], "POST")
        self.assertEqual(calls[0][2], {
            "task_type": "analysis.summarize",
            "description": "Summarize the project status",
        })
        self.assertEqual(calls[0][3], "access-secret")
        self.assertEqual(calls[0][4], {"Idempotency-Key": "telegram-update-12345"})
        self.assertIn("تأیید مالک", reply)
        self.assertNotIn("access-secret", reply)

    def test_task_submission_requires_explicit_scope(self):
        bridge = self._bridge(["status:read"])
        calls = []
        bridge._hub_request = lambda *args, **kwargs: calls.append((args, kwargs))
        reply = bridge.process_job(self._job())
        self.assertIn("tasks:create", reply)
        self.assertEqual(calls, [])

    def test_task_submission_rejects_invalid_payload_before_hub_request(self):
        bridge = self._bridge(["tasks:create"])
        calls = []
        bridge._hub_request = lambda *args, **kwargs: calls.append((args, kwargs))
        reply = bridge.process_job(self._job(idempotency_key="short"))
        self.assertIn("شناسه یکتای درخواست", reply)
        self.assertEqual(calls, [])


class TaskResultTests(unittest.TestCase):
    def _bridge(self, scopes):
        bridge = LocalBridge.__new__(LocalBridge)
        bridge.config = type("Config", (), {"telegram_owner_id": 123456789})()
        bridge._session = lambda: {"access_token": "access-secret", "scopes": scopes}
        return bridge

    def _job(self, task_id):
        return {
            "telegram_user_id": 123456789,
            "chat_id": 123456789,
            "payload": {"command": "task_result", "task_id": task_id},
        }

    def test_task_result_requires_scope_and_reads_only_the_owned_result_endpoint(self):
        task_id = "c9d78b6a-18c8-4e76-a8b1-49f09a9ec1e2"
        bridge = self._bridge(["tasks:result"])
        calls = []

        def hub_request(path, method="GET", payload=None, access_token=None, extra_headers=None):
            calls.append((path, method, access_token))
            return {"result": {"message": "completed"}, "error_code": None, "attempt_count": 1}

        bridge._hub_request = hub_request
        reply = bridge.process_job(self._job(task_id))
        self.assertEqual(calls, [(
            f"/integrations/telegram/tasks/{task_id}/result", "GET", "access-secret"
        )])
        self.assertIn("completed", reply)
        self.assertNotIn("access-secret", reply)

    def test_task_result_denies_missing_scope_and_invalid_ids(self):
        task_id = "c9d78b6a-18c8-4e76-a8b1-49f09a9ec1e2"
        denied_bridge = self._bridge(["status:read"])
        calls = []
        denied_bridge._hub_request = lambda *args, **kwargs: calls.append((args, kwargs))
        denied = denied_bridge.process_job(self._job(task_id))

        scoped_bridge = self._bridge(["tasks:result"])
        scoped_bridge._hub_request = lambda *args, **kwargs: calls.append((args, kwargs))
        invalid = scoped_bridge.process_job(self._job("../../private"))

        self.assertIn("tasks:result", denied)
        self.assertIn("شناسه کار معتبر نیست", invalid)
        self.assertEqual(calls, [])



class HubRequestCorrelationTests(unittest.TestCase):
    def test_hub_request_sends_a_fresh_canonical_uuid_request_id(self):
        bridge = LocalBridge.__new__(LocalBridge)
        bridge.config = type("Config", (), {
            "hub_base_url": "http://127.0.0.1:8000",
            "telegram_owner_id": 123456789,
        })()
        calls = []

        def capture(url, method, body, headers, **kwargs):
            calls.append((url, method, body, headers, kwargs))
            return {"ok": True}

        with patch("bridge.request_json", side_effect=capture):
            first = bridge._hub_request(
                "/integrations/telegram/tasks/c9d78b6a-18c8-4e76-a8b1-49f09a9ec1e2/result"
            )
            second = bridge._hub_request("/integrations/telegram/status")

        self.assertEqual(first, {"ok": True})
        self.assertEqual(second, {"ok": True})
        self.assertEqual(len(calls), 2)
        first_id = calls[0][3]["X-Request-ID"]
        second_id = calls[1][3]["X-Request-ID"]
        self.assertEqual(str(UUID(first_id)), first_id)
        self.assertEqual(str(UUID(second_id)), second_id)
        self.assertNotEqual(first_id, second_id)
        self.assertEqual(
            calls[0][0],
            "http://127.0.0.1:8000/integrations/telegram/tasks/"
            "c9d78b6a-18c8-4e76-a8b1-49f09a9ec1e2/result",
        )
        self.assertEqual(calls[0][1], "GET")
        self.assertEqual(calls[0][4]["request_id"], first_id)
        self.assertEqual(
            calls[0][4]["route_template"],
            "/integrations/telegram/tasks/{task_id}/result",
        )


class HubRequestLoggingTests(unittest.TestCase):
    def test_request_log_uses_safe_route_template_and_outcome_fields(self):
        class FakeResponse:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'{"accepted":true}'

        class FakeOpener:
            def open(self, _request, timeout):
                self.timeout = timeout
                return FakeResponse()

        request_id = "c9d78b6a-18c8-4e76-a8b1-49f09a9ec1e2"
        opener = FakeOpener()
        with patch("bridge.build_opener", return_value=opener), self.assertLogs(
            "mr_siavash_bridge", level="INFO"
        ) as captured:
            result = request_json(
                "http://127.0.0.1:8000/integrations/telegram/tasks/"
                "c9d78b6a-18c8-4e76-a8b1-49f09a9ec1e2/result",
                "GET",
                headers={"X-Request-ID": request_id},
                request_id=request_id,
                route_template="/integrations/telegram/tasks/{task_id}/result",
            )

        self.assertEqual(result, {"accepted": True})
        self.assertIn(f"request_id={request_id}", captured.output[0])
        self.assertIn("method=GET", captured.output[0])
        self.assertIn("status_code=201", captured.output[0])
        self.assertIn("outcome=success", captured.output[0])
        self.assertIn(
            "route_template=/integrations/telegram/tasks/{task_id}/result",
            captured.output[0],
        )
        self.assertNotIn(
            "c9d78b6a-18c8-4e76-a8b1-49f09a9ec1e2/result",
            captured.output[0],
        )


if __name__ == "__main__":
    unittest.main()
