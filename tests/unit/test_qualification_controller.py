from __future__ import annotations

import datetime as dt
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "qualification_controller", ROOT / "qualification" / "controller.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("qualification controller could not be imported")
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


class QualificationControllerTests(unittest.TestCase):
    def test_background_processes_start_in_an_owned_session(self):
        process = mock.Mock()
        with mock.patch.object(
            CONTROLLER.subprocess, "Popen", return_value=process
        ) as popen:
            self.assertIs(CONTROLLER.CommandRunner().popen(["owned-command"]), process)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_owned_process_cleanup_terminates_and_then_kills_the_whole_group(self):
        process = mock.Mock()
        process.pid = 4242
        process.poll.return_value = None
        process.communicate.side_effect = [
            subprocess.TimeoutExpired("owned-command", 1),
            ("", ""),
        ]
        with mock.patch.object(CONTROLLER.os, "killpg") as killpg:
            self.assertEqual(
                CONTROLLER.terminate_owned_process(process, timeout=1), ("", "")
            )
        self.assertEqual(
            killpg.call_args_list,
            [
                mock.call(4242, CONTROLLER.signal.SIGTERM),
                mock.call(4242, CONTROLLER.signal.SIGKILL),
            ],
        )
        process.terminate.assert_not_called()
        process.kill.assert_not_called()

    def test_lost_assistant_response_adapter_commits_once_then_fails_once(self):
        class Delegate:
            def __init__(self):
                self.creates = 0

            def create(self, resource, payload):
                self.creates += 1
                return {"id": "assistant_1234"}

        delegate = Delegate()
        client = CONTROLLER.LostAssistantCreateResponseClient(delegate)
        with self.assertRaises(CONTROLLER.ProvisioningAmbiguousWriteError):
            client.create("assistant", {"name": "owned"})
        self.assertEqual(delegate.creates, 1)
        self.assertTrue(client.injected)
        self.assertEqual(
            client.create("assistant", {"name": "owned"}),
            {"id": "assistant_1234"},
        )
        self.assertEqual(delegate.creates, 2)

    def test_live_vapi_resilience_deletes_reconciles_and_recreates(self):
        def result(prefix):
            assistant_id = f"assistant_{prefix}"
            tool_id = f"tool_{prefix}"
            credential_id = f"credential_{prefix}"
            return SimpleNamespace(
                assistant_id=assistant_id,
                prepare_tool_id=tool_id,
                webhook_credential_id=credential_id,
                physical_id=(
                    f"bridgefu-vapi-v2:{assistant_id}:{tool_id}:{credential_id}"
                ),
            )

        first = result("first")
        second = result("second")
        client = mock.Mock()
        client.get.return_value = None
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace()
        setattr(controller.args, "vapi_secret_arn", "arn:secret")
        controller.aws = mock.Mock()
        controller.aws.secret.return_value = "vapi-private-key-value-1234567890"
        controller.outputs = {
            "VapiAssistantId": "assistant_old",
            "VapiPrepareToolId": "tool_old",
            "VapiWebhookCredentialId": "credential_old",
        }
        controller.temp_phone_id = None
        controller.temp_phone_intent = None
        controller.direct_assistant_overlay_installed = False
        controller.direct_tool_id = None
        controller.web_runtime_cleanup_required = False
        controller.vapi_provisioning_resilience_evidence = None
        config = mock.Mock()

        create_results = iter((first, first, second, second))

        def create_side_effect(api, desired):
            self.assertIs(desired, config)
            value = next(create_results)
            if isinstance(api, CONTROLLER.LostAssistantCreateResponseClient):
                api.injected = True
            return value

        with (
            mock.patch.object(controller, "provisioning_config", return_value=config),
            mock.patch.object(CONTROLLER, "VapiHttpClient", return_value=client),
            mock.patch.object(
                CONTROLLER, "provision_create", side_effect=create_side_effect
            ) as create,
            mock.patch.object(CONTROLLER, "provision_delete") as delete,
        ):
            controller.vapi_provisioning_resilience()

        self.assertEqual(create.call_count, 4)
        self.assertEqual(delete.call_count, 2)
        self.assertEqual(
            delete.call_args_list[0].args[2],
            "bridgefu-vapi-v2:assistant_old:tool_old:credential_old",
        )
        self.assertEqual(delete.call_args_list[1].args[2], first.physical_id)
        self.assertEqual(controller.outputs["VapiAssistantId"], second.assistant_id)
        self.assertEqual(
            controller.outputs["VapiPrepareToolId"], second.prepare_tool_id
        )
        self.assertEqual(
            controller.outputs["VapiWebhookCredentialId"],
            second.webhook_credential_id,
        )
        self.assertEqual(
            controller.vapi_provisioning_resilience_evidence,
            {
                "schema_version": 1,
                "producer": "bridgefu-vapi-provisioning-resilience@1",
                "ambiguous_create_reconciled": True,
                "first_cycle_deleted": True,
                "second_cycle_recreated": True,
                "exact_owner_resources_present": True,
                "redacted": True,
                "passed": True,
            },
        )
        self.assertTrue(controller.vapi_provisioning_cleanup_required)

    def test_vapi_resilience_cleanup_reconciles_and_deletes_exact_owner(self):
        current = SimpleNamespace(
            assistant_id="assistant_current",
            prepare_tool_id="tool_current",
            webhook_credential_id="credential_current",
            physical_id=(
                "bridgefu-vapi-v2:assistant_current:tool_current:credential_current"
            ),
        )
        client = mock.Mock()
        client.get.return_value = None
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace()
        setattr(controller.args, "vapi_secret_arn", "arn:secret")
        controller.aws = mock.Mock()
        controller.aws.secret.return_value = "vapi-private-key-value-1234567890"
        controller.outputs = {}
        controller.vapi_provisioning_cleanup_required = True
        config = mock.Mock()

        with (
            mock.patch.object(controller, "provisioning_config", return_value=config),
            mock.patch.object(CONTROLLER, "VapiHttpClient", return_value=client),
            mock.patch.object(CONTROLLER, "provision_create", return_value=current),
            mock.patch.object(CONTROLLER, "provision_delete") as delete,
        ):
            errors = controller.cleanup_vapi_provisioning_resilience()

        self.assertEqual(errors, [])
        delete.assert_called_once_with(client, config, current.physical_id)
        self.assertFalse(controller.vapi_provisioning_cleanup_required)
        self.assertEqual(controller.outputs["VapiAssistantId"], current.assistant_id)
        self.assertEqual(
            controller.outputs["VapiPrepareToolId"], current.prepare_tool_id
        )
        self.assertEqual(
            controller.outputs["VapiWebhookCredentialId"],
            current.webhook_credential_id,
        )

    def test_vapi_resilience_cleanup_failure_remains_recovery_required(self):
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace()
        setattr(controller.args, "vapi_secret_arn", "arn:secret")
        controller.aws = mock.Mock()
        controller.aws.secret.return_value = "vapi-private-key-value-1234567890"
        controller.outputs = {}
        controller.vapi_provisioning_cleanup_required = True

        with (
            mock.patch.object(
                controller, "provisioning_config", return_value=mock.Mock()
            ),
            mock.patch.object(
                CONTROLLER,
                "VapiHttpClient",
                side_effect=CONTROLLER.VapiProvisioningError("failed"),
            ),
        ):
            errors = controller.cleanup_vapi_provisioning_resilience()

        self.assertEqual(errors, ["Vapi provisioning resilience cleanup failed"])
        self.assertTrue(controller.vapi_provisioning_cleanup_required)

    def test_command_failure_retains_bounded_sanitized_stderr(self):
        completed = subprocess.CompletedProcess(
            ["aws", "cloudformation"],
            255,
            "",
            "ValidationError: nested stack failed password=do-not-retain " + "x" * 5000,
        )
        with mock.patch.object(CONTROLLER.subprocess, "run", return_value=completed):
            with self.assertRaises(CONTROLLER.QualificationError) as raised:
                CONTROLLER.CommandRunner().run(["aws", "cloudformation"])
        message = str(raised.exception)
        self.assertIn("ValidationError: nested stack failed", message)
        self.assertIn("password=[REDACTED]", message)
        self.assertNotIn("do-not-retain", message)
        self.assertLessEqual(len(message), CONTROLLER.DIAGNOSTIC_LIMIT + 64)

    def test_ssm_polling_outlives_the_cli_waiter_and_fails_closed(self):
        class FakeAws:
            def __init__(self, statuses):
                self.statuses = iter(statuses)

            def json(self, arguments):
                self.arguments = arguments
                return {"Status": next(self.statuses)}

        success = FakeAws(["Pending", "InProgress", "Success"])
        CONTROLLER.wait_for_ssm_command(
            success, "command-id", "i-1234", timeout=1, poll_seconds=0
        )
        self.assertEqual(success.arguments[0:2], ["ssm", "get-command-invocation"])

        failed = FakeAws(["Failed"])
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.wait_for_ssm_command(
                failed, "command-id", "i-1234", timeout=1, poll_seconds=0
            )

        class EventuallyVisibleAws:
            def __init__(self):
                self.calls = 0

            def json(self, arguments):
                self.calls += 1
                if self.calls == 1:
                    raise CONTROLLER.QualificationError(
                        "command failed: aws ssm: InvocationDoesNotExist"
                    )
                return {"Status": "Success"}

        eventually_visible = EventuallyVisibleAws()
        CONTROLLER.wait_for_ssm_command(
            eventually_visible,
            "command-id",
            "i-1234",
            timeout=1,
            poll_seconds=0,
        )
        self.assertEqual(eventually_visible.calls, 2)

    def test_vapi_list_uses_a_bounded_explicit_limit(self):
        class FakeVapi(CONTROLLER.Vapi):
            def __init__(self):
                super().__init__("private-test-key")
                self.path = None

            def request(self, method, path, payload=None, *, allow_missing=False):
                self.path = path
                return []

        client = FakeVapi()
        self.assertEqual(client.list("call", limit=20), [])
        self.assertEqual(client.path, "/call?limit=20")
        for invalid in (0, 101):
            with self.assertRaises(CONTROLLER.QualificationError):
                client.list("call", limit=invalid)

    def test_vapi_call_discovery_uses_exact_server_side_filters(self):
        class FakeVapi(CONTROLLER.Vapi):
            def __init__(self):
                super().__init__("private-test-key")
                self.path = None

            def request(self, method, path, payload=None, *, allow_missing=False):
                self.path = path
                return []

        client = FakeVapi()
        client.list_calls(
            assistant_id="assistant_1234",
            created_at_ge=dt.datetime(2026, 8, 11, 4, 20, tzinfo=dt.UTC),
            phone_number_id="phone_1234",
            call_id="call_1234",
        )
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(client.path).query)
        self.assertEqual(query["assistantId"], ["assistant_1234"])
        self.assertEqual(query["phoneNumberId"], ["phone_1234"])
        self.assertEqual(query["id"], ["call_1234"])
        self.assertEqual(query["createdAtGe"], ["2026-08-11T04:20:00Z"])
        self.assertEqual(query["limit"], ["20"])

    def test_vapi_sip_phone_uses_explicit_digest_authentication(self):
        class FakeVapi(CONTROLLER.Vapi):
            def __init__(self):
                super().__init__("private-test-key")
                self.observed = None

            def request(self, method, path, payload=None, *, allow_missing=False):
                self.observed = (method, path, payload, allow_missing)
                if method == "GET":
                    return []
                return {
                    "id": "phone_1234",
                    "provider": "vapi",
                    "name": payload["name"],
                    "assistantId": payload["assistantId"],
                    "status": "active",
                    "sipUri": payload["sipUri"],
                    "authentication": {
                        "realm": payload["authentication"]["realm"],
                        "username": payload["authentication"]["username"],
                    },
                }

        authentication = {
            "realm": "sip.vapi.ai",
            "username": "bfq_0123456789abcdef",
            "password": "0123456789abcdef0123456789abcdef",
        }
        client = FakeVapi()
        phone = client.create_phone(
            "bfq-test1234",
            "assistant_1234",
            authentication,
        )
        self.assertEqual(phone["status"], "active")
        self.assertEqual(client.observed[0:2], ("POST", "/phone-number"))
        payload = client.observed[2]
        self.assertEqual(payload["sipUri"], "sip:bfq_0123456789abcdef@sip.vapi.ai")
        self.assertEqual(payload["authentication"], authentication)
        self.assertLessEqual(len(payload["name"]), 40)

        with self.assertRaises(CONTROLLER.QualificationError):
            client.create_phone(
                "bfq-test1234",
                "assistant_1234",
                {**authentication, "password": "too-short"},
            )

    def test_vapi_sip_phone_lost_create_response_reconciles_exact_owner(self):
        authentication = {
            "realm": "sip.vapi.ai",
            "username": "bfq_0123456789abcdef",
            "password": "0123456789abcdef0123456789abcdef",
        }
        intent = CONTROLLER.vapi_phone_intent(
            "bfq-test1234", "assistant_1234", authentication
        )
        owned = {
            "id": "phone_1234",
            "provider": "vapi",
            "name": intent["name"],
            "assistantId": intent["assistant_id"],
            "sipUri": intent["sip_uri"],
            "authentication": {
                "realm": "sip.vapi.ai",
                "username": "bfq_0123456789abcdef",
            },
        }

        class FakeVapi(CONTROLLER.Vapi):
            def __init__(self):
                super().__init__("private-test-key")
                self.listings = iter([[], [owned]])
                self.posts = 0

            def list(self, resource, *, limit=100):
                self.asserted = (resource, limit)
                return next(self.listings)

            def request(self, method, path, payload=None, *, allow_missing=False):
                self.posts += 1
                raise CONTROLLER.VapiAmbiguousWriteError("response lost")

        client = FakeVapi()
        phone = client.create_phone(
            "bfq-test1234",
            "assistant_1234",
            authentication,
            reconcile_timeout=0,
            poll_seconds=0,
        )
        self.assertEqual(phone["id"], "phone_1234")
        self.assertEqual(client.posts, 1)
        self.assertEqual(client.asserted, ("phone-number", 100))

    def test_vapi_sip_phone_reconciliation_fails_closed_on_name_collision(self):
        authentication = {
            "realm": "sip.vapi.ai",
            "username": "bfq_0123456789abcdef",
            "password": "0123456789abcdef0123456789abcdef",
        }
        name = CONTROLLER.vapi_phone_owned_name("bfq-test1234")

        class FakeVapi(CONTROLLER.Vapi):
            def __init__(self):
                super().__init__("private-test-key")
                self.posted = False

            def list(self, resource, *, limit=100):
                return [
                    {
                        "id": "customer_phone",
                        "provider": "vapi",
                        "name": name,
                        "assistantId": "assistant_customer",
                        "sipUri": "sip:customer@sip.vapi.ai",
                    }
                ]

            def request(self, method, path, payload=None, *, allow_missing=False):
                self.posted = True
                raise AssertionError("a colliding intent must not be created")

        client = FakeVapi()
        with self.assertRaisesRegex(CONTROLLER.QualificationError, "already in use"):
            client.create_phone("bfq-test1234", "assistant_1234", authentication)
        self.assertFalse(client.posted)

    def test_vapi_sip_phone_activation_is_bounded_and_exact(self):
        class FakeVapi:
            def __init__(self, statuses):
                self.statuses = iter(statuses)

            def get(self, resource, resource_id):
                self.observed = (resource, resource_id)
                status = next(self.statuses)
                return {
                    "id": "phone_1234",
                    "sipUri": "sip:bfq_0123456789abcdef@sip.vapi.ai",
                    "assistantId": "assistant_1234",
                    "status": status,
                }

        client = FakeVapi(["pending", "provisioning", "active"])
        active = CONTROLLER.wait_for_vapi_phone_active(
            client,
            "phone_1234",
            "sip:bfq_0123456789abcdef@sip.vapi.ai",
            "assistant_1234",
            timeout=1,
            poll_seconds=0,
        )
        self.assertEqual(active["status"], "active")
        self.assertEqual(client.observed, ("phone-number", "phone_1234"))

        with self.assertRaisesRegex(CONTROLLER.QualificationError, "terminal status"):
            CONTROLLER.wait_for_vapi_phone_active(
                FakeVapi(["failed"]),
                "phone_1234",
                "sip:bfq_0123456789abcdef@sip.vapi.ai",
                "assistant_1234",
                timeout=1,
                poll_seconds=0,
            )

    def test_vapi_generic_deletion_targets_and_verifies_one_exact_id(self):
        class FakeVapi(CONTROLLER.Vapi):
            def __init__(self):
                super().__init__("private-test-key")
                self.values = iter(
                    [
                        {"id": "tool_1234"},
                        {"id": "tool_1234"},
                        None,
                    ]
                )
                self.deleted = None

            def get(self, resource, resource_id):
                self.observed = (resource, resource_id)
                return next(self.values)

            def request(self, method, path, payload=None, *, allow_missing=False):
                self.deleted = (method, path, allow_missing)
                return None

        client = FakeVapi()
        client.delete("tool", "tool_1234", timeout=1, poll_seconds=0)
        self.assertEqual(client.observed, ("tool", "tool_1234"))
        self.assertEqual(client.deleted, ("DELETE", "/tool/tool_1234", True))

    def test_vapi_generic_delete_refuses_phone_without_ownership_intent(self):
        client = CONTROLLER.Vapi("private-test-key")
        with self.assertRaisesRegex(
            CONTROLLER.QualificationError, "exact ownership intent"
        ):
            client.delete("phone-number", "phone_1234")

    def test_direct_vapi_tool_creation_and_deletion_bind_exact_stack_endpoint(self):
        desired = CONTROLLER.bridgefu_web_handoff.direct_tool_payload(
            endpoint_url="https://direct.example.test/v1/direct-handoff",
            credential_id="credential_1234",
            field_schema={
                "type": "object",
                "additionalProperties": False,
                "properties": {"intent": {"type": "string", "maxLength": 256}},
                "required": ["intent"],
            },
            execution_id="bfq-test1234",
        )
        remote = {"id": "tool_1234", **desired}

        class FakeVapi(CONTROLLER.Vapi):
            def __init__(self):
                super().__init__("private-test-key")
                self.tools = []
                self.deleted = False

            def list(self, resource, *, limit=100):
                return list(self.tools)

            def get(self, resource, resource_id):
                return next(
                    (item for item in self.tools if item.get("id") == resource_id),
                    None,
                )

            def request(self, method, path, payload=None, *, allow_missing=False):
                if method == "POST":
                    self.tools = [remote]
                    return remote
                if method == "DELETE":
                    self.deleted = True
                    self.tools = []
                    return None
                raise AssertionError("unexpected direct-tool request")

        client = FakeVapi()
        created = client.create_direct_tool(
            execution_id="bfq-test1234",
            endpoint_url="https://direct.example.test/v1/direct-handoff",
            credential_id="credential_1234",
            desired=desired,
        )
        self.assertEqual(created["id"], "tool_1234")
        client.delete_direct_tool(
            "tool_1234",
            execution_id="bfq-test1234",
            endpoint_url="https://direct.example.test/v1/direct-handoff",
            credential_id="credential_1234",
        )
        self.assertTrue(client.deleted)

    def test_vapi_assistant_model_patch_requires_exact_reread(self):
        model = {"provider": "openai", "model": "gpt-4.1", "toolIds": ["tool_1"]}

        class FakeVapi(CONTROLLER.Vapi):
            def __init__(self, accepted):
                super().__init__("private-test-key")
                self.accepted = accepted
                self.payload = None

            def request(self, method, path, payload=None, *, allow_missing=False):
                self.payload = payload
                return {"id": "assistant_1234"}

            def get(self, resource, resource_id):
                return {
                    "id": resource_id,
                    "model": model if self.accepted else {"provider": "openai"},
                }

        accepted = FakeVapi(True)
        accepted.patch_assistant_model("assistant_1234", model)
        self.assertEqual(accepted.payload, {"model": model})
        with self.assertRaisesRegex(CONTROLLER.QualificationError, "not verified"):
            FakeVapi(False).patch_assistant_model("assistant_1234", model)

    def test_vapi_phone_delete_refuses_foreign_exact_id(self):
        authentication = {
            "realm": "sip.vapi.ai",
            "username": "bfq_0123456789abcdef",
            "password": "0123456789abcdef0123456789abcdef",
        }
        intent = CONTROLLER.vapi_phone_intent(
            "bfq-test1234", "assistant_1234", authentication
        )

        class FakeVapi(CONTROLLER.Vapi):
            def __init__(self, foreign):
                super().__init__("private-test-key")
                self.foreign = foreign
                self.deleted = False

            def get(self, resource, resource_id):
                return self.foreign

            def request(self, method, path, payload=None, *, allow_missing=False):
                self.deleted = True
                raise AssertionError("foreign phone must not be deleted")

        owned_shape = {
            "id": "phone_1234",
            "provider": "vapi",
            "name": intent["name"],
            "assistantId": intent["assistant_id"],
            "sipUri": intent["sip_uri"],
        }
        for changed in (
            {**owned_shape, "name": "Customer phone"},
            {**owned_shape, "assistantId": "assistant_customer"},
            {**owned_shape, "sipUri": "sip:customer@sip.vapi.ai"},
        ):
            with self.subTest(changed=changed):
                client = FakeVapi(changed)
                with self.assertRaisesRegex(CONTROLLER.QualificationError, "not owned"):
                    client.delete_phone("phone_1234", intent)
                self.assertFalse(client.deleted)

    def test_vapi_phone_ownership_journal_is_strict_hashed_and_non_secret(self):
        journal = CONTROLLER.vapi_phone_ownership_journal(
            "bfq-test1234",
            "us-west-2",
            "phone_1234",
            "assistant_1234",
            created_at="2026-08-11T04:20:00Z",
        )
        self.assertEqual(journal["owned_name"], "BFQ bfq-test1234 SIP smoke")
        self.assertEqual(journal["resource_type"], "phone-number")
        serialized = json.dumps(journal)
        for forbidden in ("sip:", "password", "authentication", "api.vapi.ai"):
            self.assertNotIn(forbidden, serialized)
        CONTROLLER.validate_vapi_phone_ownership_journal(journal)
        for field, replacement in (
            ("phone_id", "phone_other"),
            ("assistant_id", "assistant_other"),
            ("owned_name", "customer phone"),
            ("ownership_sha256", "0" * 64),
        ):
            changed = dict(journal)
            changed[field] = replacement
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.validate_vapi_phone_ownership_journal(changed)

    def test_vapi_phone_intent_journal_is_strict_hashed_and_non_secret(self):
        authentication = {
            "realm": "sip.vapi.ai",
            "username": "bfq_0123456789abcdef",
            "password": "not-retained-password-value",
        }
        intent = CONTROLLER.vapi_phone_intent(
            "bfq-test1234", "assistant_1234", authentication
        )
        journal = CONTROLLER.vapi_phone_intent_journal(
            "bfq-test1234",
            "us-west-2",
            intent,
            created_at="2026-08-11T04:20:00Z",
        )
        self.assertEqual(journal["producer"], "bridgefu-vapi-phone-intent@1")
        self.assertEqual(journal["owned_name"], "BFQ bfq-test1234 SIP smoke")
        self.assertEqual(journal["sip_uri"], "sip:bfq_0123456789abcdef@sip.vapi.ai")
        serialized = json.dumps(journal)
        self.assertNotIn(authentication["password"], serialized)
        self.assertNotIn("password", serialized.lower())
        CONTROLLER.validate_vapi_phone_intent_journal(journal)
        for field, replacement in (
            ("assistant_id", "assistant_other"),
            ("sip_uri", "sip:foreign@sip.vapi.ai"),
            ("authentication_username", "bfq_ffffffffffffffff"),
            ("intent_sha256", "0" * 64),
        ):
            changed = dict(journal)
            changed[field] = replacement
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.validate_vapi_phone_intent_journal(changed)

    def test_vapi_phone_journal_is_uploaded_from_memory_to_exact_key(self):
        class Runner:
            def run(self, arguments, **kwargs):
                self.arguments = arguments
                self.kwargs = kwargs
                return ""

        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace(
            execution_id="bfq-test1234", region="us-west-2"
        )
        controller.outputs = {"ArtifactBucket": "bridgefu-artifacts-test"}
        controller.runner = Runner()
        controller.temp_phone_journal_object = None
        controller.write_phone_ownership_journal("phone_1234", "assistant_1234")
        expected = (
            "s3://bridgefu-artifacts-test/qualification/bfq-test1234/"
            "ownership/vapi-phone.json"
        )
        self.assertEqual(controller.temp_phone_journal_object, expected)
        self.assertEqual(controller.runner.arguments[0:4], ["aws", "s3", "cp", "-"])
        self.assertIn(expected, controller.runner.arguments)
        self.assertIn("--sse", controller.runner.arguments)
        journal = json.loads(controller.runner.kwargs["input_text"])
        self.assertEqual(journal["phone_id"], "phone_1234")
        retained = controller.runner.kwargs["input_text"].lower()
        self.assertNotIn("sip:", retained)
        self.assertNotIn("password", retained)
        self.assertNotIn("authentication", retained)

    def test_vapi_phone_intent_journal_upload_is_exact_and_non_secret(self):
        class Runner:
            def run(self, arguments, **kwargs):
                self.arguments = arguments
                self.kwargs = kwargs
                return ""

        authentication = {
            "realm": "sip.vapi.ai",
            "username": "bfq_0123456789abcdef",
            "password": "not-retained-password-value",
        }
        intent = CONTROLLER.vapi_phone_intent(
            "bfq-test1234", "assistant_1234", authentication
        )
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace(
            execution_id="bfq-test1234", region="us-west-2"
        )
        controller.outputs = {"ArtifactBucket": "bridgefu-artifacts-test"}
        controller.runner = Runner()
        controller.temp_phone_intent_journal_object = None
        controller.write_phone_intent_journal(intent)
        expected = (
            "s3://bridgefu-artifacts-test/qualification/bfq-test1234/"
            "ownership/vapi-phone-intent.json"
        )
        self.assertEqual(controller.temp_phone_intent_journal_object, expected)
        self.assertEqual(controller.runner.arguments[0:4], ["aws", "s3", "cp", "-"])
        self.assertIn("--sse", controller.runner.arguments)
        journal = json.loads(controller.runner.kwargs["input_text"])
        self.assertEqual(journal["assistant_id"], "assistant_1234")
        retained = controller.runner.kwargs["input_text"]
        self.assertNotIn(authentication["password"], retained)
        self.assertNotIn("password", retained.lower())

    def test_vapi_phone_journal_precedes_uri_and_activation_validation(self):
        order = []
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace(
            execution_id="bfq-test1234", region="us-west-2"
        )
        controller.outputs = {"VapiAssistantId": "assistant_1234"}
        controller.aws = mock.Mock()
        controller.temp_phone_id = None
        controller.vapi = mock.Mock()
        controller.vapi.create_phone.side_effect = lambda *args, **kwargs: (
            order.append("post")
            or {
                "id": "phone_1234",
                "sipUri": "sip:unexpected@sip.vapi.ai",
            }
        )
        controller.write_phone_intent_journal = mock.Mock(
            side_effect=lambda intent: order.append("intent-journal")
        )
        controller.write_phone_ownership_journal = mock.Mock()
        with mock.patch.object(CONTROLLER, "ensure_connect_agent_available"):
            with self.assertRaisesRegex(
                CONTROLLER.QualificationError, "endpoint is invalid"
            ):
                controller._sip_smoke(Path("unused"), "unused")
        self.assertEqual(controller.temp_phone_id, "phone_1234")
        self.assertEqual(order, ["intent-journal", "post"])
        controller.write_phone_intent_journal.assert_called_once()
        controller.write_phone_ownership_journal.assert_called_once_with(
            "phone_1234", "assistant_1234"
        )
        controller.vapi.create_phone.reset_mock()
        controller.temp_phone_id = None
        controller.temp_phone_intent = None
        controller.temp_phone_intent_journal_object = None
        controller.temp_phone_journal_object = None
        controller.write_phone_intent_journal.side_effect = (
            CONTROLLER.QualificationError("intent upload failed")
        )
        with mock.patch.object(CONTROLLER, "ensure_connect_agent_available"):
            with self.assertRaisesRegex(
                CONTROLLER.QualificationError, "intent upload failed"
            ):
                controller._sip_smoke(Path("unused"), "unused")
        controller.vapi.create_phone.assert_not_called()

    def test_cleanup_reconciles_lost_phone_id_from_intent_before_delete(self):
        authentication = {
            "realm": "sip.vapi.ai",
            "username": "bfq_0123456789abcdef",
            "password": "not-retained-password-value",
        }
        intent = CONTROLLER.vapi_phone_intent(
            "bfq-test1234", "assistant_1234", authentication
        )
        owned = {
            "id": "phone_1234",
            "provider": "vapi",
            "name": intent["name"],
            "assistantId": intent["assistant_id"],
            "sipUri": intent["sip_uri"],
        }

        class Vapi:
            def __init__(self):
                self.matches = iter([owned, None])
                self.deleted = None

            def find_phone_for_intent(self, observed_intent):
                self.observed_intent = observed_intent
                return next(self.matches)

            def delete_phone(self, resource_id, observed_intent):
                self.deleted = (resource_id, observed_intent)

        class Aws:
            def __init__(self):
                self.removed = []

            def text(self, arguments, timeout=900):
                self.removed.append(arguments)
                return ""

        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace(
            execution_id="bfq-test1234", region="us-west-2"
        )
        controller.outputs = {"ArtifactBucket": "bridgefu-artifacts-test"}
        controller.vapi = Vapi()
        controller.aws = Aws()
        controller.temp_phone_id = None
        controller.temp_phone_intent = intent
        controller.temp_phone_intent_journal_object = (
            "s3://bridgefu-artifacts-test/qualification/bfq-test1234/"
            "ownership/vapi-phone-intent.json"
        )
        controller.temp_phone_journal_object = None
        controller.temp_sip_auth_object = None

        def write_ownership(phone_id, assistant_id):
            self.assertEqual((phone_id, assistant_id), ("phone_1234", "assistant_1234"))
            controller.temp_phone_journal_object = (
                "s3://bridgefu-artifacts-test/qualification/bfq-test1234/"
                "ownership/vapi-phone.json"
            )

        controller.write_phone_ownership_journal = write_ownership
        self.assertEqual(controller.cleanup_sip_transients(), [])
        self.assertEqual(controller.vapi.deleted, ("phone_1234", intent))
        self.assertIsNone(controller.temp_phone_id)
        self.assertIsNone(controller.temp_phone_intent)
        self.assertIsNone(controller.temp_phone_journal_object)
        self.assertIsNone(controller.temp_phone_intent_journal_object)
        removed = [item for call in controller.aws.removed for item in call]
        self.assertIn("ownership/vapi-phone.json", " ".join(removed))
        self.assertIn("ownership/vapi-phone-intent.json", " ".join(removed))

    def test_cleanup_retains_intent_when_ambiguous_create_is_not_visible(self):
        authentication = {
            "realm": "sip.vapi.ai",
            "username": "bfq_0123456789abcdef",
            "password": "not-retained-password-value",
        }
        intent = CONTROLLER.vapi_phone_intent(
            "bfq-test1234", "assistant_1234", authentication
        )

        class Vapi:
            def find_phone_for_intent(self, observed_intent):
                self.observed_intent = observed_intent
                return None

        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.vapi = Vapi()
        controller.aws = mock.Mock()
        controller.temp_phone_id = None
        controller.temp_phone_intent = intent
        controller.temp_phone_creation_ambiguous = True
        controller.temp_phone_intent_journal_object = (
            "s3://bridgefu-artifacts-test/qualification/bfq-test1234/"
            "ownership/vapi-phone-intent.json"
        )
        controller.temp_phone_journal_object = None
        controller.temp_sip_auth_object = None
        errors = controller.cleanup_sip_transients()
        self.assertIn("temporary Vapi SIP endpoint deletion failed", errors)
        self.assertTrue(controller.temp_phone_creation_ambiguous)
        self.assertEqual(controller.temp_phone_intent, intent)
        self.assertIsNotNone(controller.temp_phone_intent_journal_object)
        controller.aws.text.assert_not_called()

    def test_failed_phone_delete_retains_journal_and_skips_stack_deletion(self):
        output = Path(tempfile.mkdtemp(prefix="qualification-ownership-test-"))

        class Vapi:
            def delete_phone(self, resource_id, intent):
                raise CONTROLLER.QualificationError("delete failed")

            def get(self, resource, resource_id):
                return {"id": resource_id}

        class Aws:
            region = "us-west-2"

            def __init__(self):
                self.text_calls = []

            def text(self, arguments, timeout=900):
                self.text_calls.append(arguments)
                return ""

            def exists(self, arguments):
                return "describe-stacks" in arguments

            def json(self, arguments, timeout=900):
                if "list-object-versions" in arguments:
                    return {
                        "IsTruncated": False,
                        "Versions": [
                            {
                                "Key": (
                                    "qualification/bfq-test1234/ownership/"
                                    "vapi-phone.json"
                                ),
                                "VersionId": "version-1",
                            }
                        ],
                    }
                raise AssertionError(arguments)

        try:
            controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
            controller.args = SimpleNamespace(
                execution_id="bfq-test1234", region="us-west-2", output=output
            )
            controller.stack_name = "bridgefu-bfq-test1234"
            controller.outputs = {
                "ArtifactBucket": "bridgefu-artifacts-test",
                "VapiAssistantId": "assistant_1234",
            }
            controller.vapi = Vapi()
            controller.temp_phone_id = "phone_1234"
            controller.temp_phone_intent = {
                "name": "BFQ bfq-test1234 SIP smoke",
                "assistant_id": "assistant_1234",
                "sip_uri": "sip:bfq_0123456789abcdef@sip.vapi.ai",
                "authentication_realm": "sip.vapi.ai",
                "authentication_username": "bfq_0123456789abcdef",
            }
            controller.temp_phone_journal_object = (
                "s3://bridgefu-artifacts-test/qualification/bfq-test1234/"
                "ownership/vapi-phone.json"
            )
            controller.temp_sip_auth_object = None
            controller.acm_validation_journal = None
            controller.acm_validation_journal_object = None
            controller.acm_validation_discovery_complete = True
            controller.processes = []
            controller.ssm_commands = []
            controller.created_stack = True
            controller.aws = Aws()
            with self.assertRaises(CONTROLLER.QualificationError):
                controller.cleanup()
            self.assertEqual(controller.temp_phone_id, "phone_1234")
            self.assertIsNotNone(controller.temp_phone_journal_object)
            flattened = [value for call in controller.aws.text_calls for value in call]
            self.assertNotIn("delete-stack", flattened)
            self.assertNotIn("delete-objects", flattened)
        finally:
            shutil.rmtree(output)

    def test_failed_direct_tool_delete_blocks_stack_and_prefix_deletion(self):
        output = Path(tempfile.mkdtemp(prefix="qualification-direct-tool-test-"))

        class Vapi:
            def delete_direct_tool(self, *_args, **_kwargs):
                raise CONTROLLER.QualificationError("delete failed")

            def get(self, resource, resource_id):
                return {"id": resource_id}

        class Aws:
            region = "us-west-2"

            def __init__(self):
                self.text_calls = []

            def text(self, arguments, timeout=900):
                self.text_calls.append(arguments)
                return ""

            def exists(self, arguments):
                return "describe-stacks" in arguments

            def json(self, arguments, timeout=900):
                if "list-object-versions" in arguments:
                    return {"IsTruncated": False}
                raise AssertionError(arguments)

        try:
            controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
            controller.args = SimpleNamespace(
                execution_id="bfq-test1234", region="us-west-2", output=output
            )
            controller.stack_name = "bridgefu-bfq-test1234"
            controller.outputs = {
                "ArtifactBucket": "bridgefu-artifacts-test",
                "VapiAssistantId": "assistant_1234",
                "VapiWebhookCredentialId": "credential_1234",
                "DirectHandoffUrl": (
                    "https://example.execute-api.us-west-2.amazonaws.com/"
                    "v1/direct-handoff"
                ),
            }
            controller.vapi = Vapi()
            controller.direct_assistant_overlay_installed = False
            controller.direct_tool_id = "tool_1234"
            controller.direct_tool_desired = {}
            controller.direct_tool_prompt_sha256 = None
            controller.temp_phone_id = None
            controller.temp_phone_intent = None
            controller.temp_phone_creation_ambiguous = False
            controller.temp_phone_journal_object = None
            controller.temp_phone_intent_journal_object = None
            controller.temp_sip_auth_object = None
            controller.acm_validation_journal = None
            controller.acm_validation_journal_object = None
            controller.acm_validation_discovery_complete = True
            controller.processes = []
            controller.ssm_commands = []
            controller.created_stack = True
            controller.aws = Aws()
            with self.assertRaises(CONTROLLER.QualificationError):
                controller.cleanup()
            self.assertEqual(controller.direct_tool_id, "tool_1234")
            flattened = [value for call in controller.aws.text_calls for value in call]
            self.assertNotIn("delete-stack", flattened)
            self.assertNotIn("delete-objects", flattened)
        finally:
            shutil.rmtree(output)

    def test_versioned_qualification_prefix_is_paginated_deleted_and_proven(self):
        class Aws:
            def __init__(self):
                self.calls = []
                self.list_count = 0

            def json(self, arguments, timeout=900):
                self.calls.append(arguments)
                if "list-object-versions" in arguments:
                    self.list_count += 1
                    if self.list_count == 1:
                        return {
                            "IsTruncated": True,
                            "Versions": [
                                {
                                    "Key": "qualification/bfq-test1234/a",
                                    "VersionId": "version-1",
                                }
                            ],
                            "NextKeyMarker": "qualification/bfq-test1234/a",
                            "NextVersionIdMarker": "version-1",
                        }
                    if self.list_count == 2:
                        self.second_arguments = arguments
                        return {
                            "IsTruncated": False,
                            "DeleteMarkers": [
                                {
                                    "Key": "qualification/bfq-test1234/b",
                                    "VersionId": "marker-1",
                                }
                            ],
                        }
                    return {"IsTruncated": False}
                if "delete-objects" in arguments:
                    payload = json.loads(arguments[arguments.index("--delete") + 1])
                    self.deleted = payload["Objects"]
                    self.quiet = payload["Quiet"]
                    return {"Deleted": list(self.deleted)}
                raise AssertionError(arguments)

        aws = Aws()
        CONTROLLER.purge_object_versions_exact(
            aws,
            "bridgefu-artifacts-test",
            "qualification/bfq-test1234/",
        )
        self.assertEqual(
            aws.deleted,
            [
                {
                    "Key": "qualification/bfq-test1234/a",
                    "VersionId": "version-1",
                },
                {
                    "Key": "qualification/bfq-test1234/b",
                    "VersionId": "marker-1",
                },
            ],
        )
        self.assertFalse(aws.quiet)
        self.assertIn("--key-marker", aws.second_arguments)
        self.assertIn("--version-id-marker", aws.second_arguments)
        self.assertTrue(
            all(
                "--no-paginate" in call
                for call in aws.calls
                if "list-object-versions" in call
            )
        )

    def test_exact_key_version_cleanup_does_not_delete_adjacent_objects(self):
        class Aws:
            def __init__(self):
                self.list_count = 0

            def json(self, arguments, timeout=900):
                if "list-object-versions" in arguments:
                    self.list_count += 1
                    if self.list_count == 1:
                        return {
                            "IsTruncated": False,
                            "Versions": [
                                {
                                    "Key": "qualification/bfq-test1234/sip-auth.json",
                                    "VersionId": "secret-version",
                                },
                                {
                                    "Key": "qualification/bfq-test1234/sip-auth.json.bak",
                                    "VersionId": "unrelated-version",
                                },
                            ],
                        }
                    return {
                        "IsTruncated": False,
                        "Versions": [
                            {
                                "Key": "qualification/bfq-test1234/sip-auth.json.bak",
                                "VersionId": "unrelated-version",
                            }
                        ],
                    }
                if "delete-objects" in arguments:
                    self.deleted = json.loads(
                        arguments[arguments.index("--delete") + 1]
                    )["Objects"]
                    return {"Deleted": list(self.deleted)}
                raise AssertionError(arguments)

        aws = Aws()
        CONTROLLER.purge_object_versions_exact(
            aws,
            "bridgefu-artifacts-test",
            "qualification/bfq-test1234/sip-auth.json",
            exact_key=True,
        )
        self.assertEqual(
            aws.deleted,
            [
                {
                    "Key": "qualification/bfq-test1234/sip-auth.json",
                    "VersionId": "secret-version",
                }
            ],
        )

    def test_object_version_cleanup_requires_exact_deletion_receipt(self):
        class Aws:
            def __init__(self):
                self.list_count = 0

            def json(self, arguments, timeout=900):
                if "list-object-versions" in arguments:
                    self.list_count += 1
                    if self.list_count == 1:
                        return {
                            "IsTruncated": False,
                            "Versions": [
                                {
                                    "Key": "qualification/bfq-test1234/a",
                                    "VersionId": "version-1",
                                }
                            ],
                        }
                    return {"IsTruncated": False}
                if "delete-objects" in arguments:
                    return {
                        "Deleted": [
                            {
                                "Key": "qualification/bfq-test1234/a",
                                "VersionId": "wrong-version",
                            }
                        ]
                    }
                raise AssertionError(arguments)

        with self.assertRaisesRegex(
            CONTROLLER.QualificationError, "version deletion failed"
        ):
            CONTROLLER.purge_object_versions_exact(
                Aws(),
                "bridgefu-artifacts-test",
                "qualification/bfq-test1234/",
            )

    def test_object_version_pagination_and_entry_bounds_fail_closed(self):
        class TruncatedAws:
            def json(self, arguments, timeout=900):
                return {
                    "IsTruncated": True,
                    "NextKeyMarker": "qualification/bfq-test1234/a",
                    "NextVersionIdMarker": "version-1",
                }

        with mock.patch.object(CONTROLLER, "MAX_OBJECT_VERSION_PAGES", 1):
            with self.assertRaisesRegex(
                CONTROLLER.QualificationError, "pagination bound"
            ):
                CONTROLLER.list_object_versions_exact(
                    TruncatedAws(),
                    "bridgefu-artifacts-test",
                    "qualification/bfq-test1234/",
                )

        class TooManyAws:
            def json(self, arguments, timeout=900):
                return {
                    "IsTruncated": False,
                    "Versions": [
                        {
                            "Key": "qualification/bfq-test1234/a",
                            "VersionId": "version-1",
                        },
                        {
                            "Key": "qualification/bfq-test1234/b",
                            "VersionId": "version-2",
                        },
                    ],
                }

        with mock.patch.object(CONTROLLER, "MAX_OBJECT_VERSIONS", 1):
            with self.assertRaisesRegex(CONTROLLER.QualificationError, "version bound"):
                CONTROLLER.list_object_versions_exact(
                    TooManyAws(),
                    "bridgefu-artifacts-test",
                    "qualification/bfq-test1234/",
                )

    def test_failed_environment_retention_must_be_explicit(self):
        self.assertEqual(
            CONTROLLER.create_failure_arguments(False), ["--disable-rollback"]
        )
        self.assertEqual(
            CONTROLLER.create_failure_arguments(True), ["--disable-rollback"]
        )

    def test_connect_agent_availability_is_exact_and_idempotent(self):
        instance_arn = "arn:aws:connect:us-west-2:123456789012:instance/instance-1"

        class Runner:
            def probe(self, arguments, timeout=60):
                self.arguments = arguments
                return (
                    255,
                    "",
                    "InvalidRequestException: User already in requested status",
                )

        class Aws:
            region = "us-west-2"

            def __init__(self):
                self.runner = Runner()
                self.responses = iter(
                    [
                        {
                            "UserSummaryList": [
                                {
                                    "Username": "bridgefu-demo-agent",
                                    "Id": "user-1",
                                    "Arn": f"{instance_arn}/agent/user-1",
                                }
                            ]
                        },
                        {
                            "AgentStatusSummaryList": [
                                {
                                    "Name": "Available",
                                    "Type": "ROUTABLE",
                                    "Id": "status-1",
                                    "Arn": f"{instance_arn}/agent-state/status-1",
                                }
                            ]
                        },
                    ]
                )

            def json(self, arguments):
                return next(self.responses)

        aws = Aws()
        CONTROLLER.ensure_connect_agent_available(
            aws,
            {
                "ConnectInstanceId": "instance-1",
                "ConnectInstanceArn": instance_arn,
                "AgentUsername": "bridgefu-demo-agent",
            },
        )
        invocation = aws.runner.arguments
        self.assertIn("put-user-status", invocation)
        self.assertEqual(invocation[invocation.index("--user-id") + 1], "user-1")
        self.assertEqual(
            invocation[invocation.index("--agent-status-id") + 1], "status-1"
        )

    def test_scenario_checks_are_derived_from_dtmf_and_media_observations(self):
        fields = list(CONTROLLER.synthetic_context("bridgefu-web-sdk-handoff"))
        source = {
            "bridgefu": {"webrtc_call_started": True},
            "media": {
                "source_to_agent_marker_frames_sent": 25,
                "agent_marker_observed_at_ms": [1, 2, 3, 4, 5],
                "agent_to_source_marker_frames": 5,
                "dtmf_source_to_agent_sent_at_ms": [10],
                "dtmf_agent_to_source_observed": True,
            },
            "hangup": {"local_end_completed": True, "cleanup_observed": True},
        }
        agent = {
            "screen_pop": {"visible": True, "visible_fields": fields},
            "media": {
                "source_to_agent_marker_frames": 5,
                "source_marker_observed_at_ms": [1, 2, 3],
                "agent_to_source_marker_frames_sent": 25,
                "dtmf_source_to_agent_observed": True,
                "dtmf_agent_to_source_sent_at_ms": [10],
            },
        }
        call = {
            "status": "ended",
            "transfers": ["completed"],
            "artifact": {
                "messages": [
                    {"toolName": "bridgefu_direct_handoff"},
                ]
            },
        }
        checks = CONTROLLER.derive_scenario_checks(
            "bridgefu-web-sdk-handoff",
            source,
            agent,
            call,
            {"correlation_id": "bf1_x", "handoff_status": "CONSUMED"},
            {
                "bridgefu_received_correlation_header": True,
                "connect_lookup_available": True,
                "vapi_destination_uri_scheme_allowed": True,
                "vapi_destination_tls_transport": True,
                "vapi_destination_media_profile_allowed": True,
                "vapi_destination_media_posture_consistent": True,
                "vapi_destination_answered": True,
            },
        )
        self.assertTrue(all(checks.values()))
        self.assertTrue(checks["dtmf_agent_to_source"])
        agent["media"]["dtmf_source_to_agent_observed"] = False
        checks = CONTROLLER.derive_scenario_checks(
            "bridgefu-web-sdk-handoff",
            source,
            agent,
            call,
            {"correlation_id": "bf1_x", "handoff_status": "CONSUMED"},
            {
                "bridgefu_received_correlation_header": True,
                "connect_lookup_available": True,
                "vapi_destination_uri_scheme_allowed": True,
                "vapi_destination_tls_transport": True,
                "vapi_destination_media_profile_allowed": True,
                "vapi_destination_media_posture_consistent": True,
                "vapi_destination_answered": True,
            },
        )
        self.assertFalse(checks["dtmf_source_to_agent"])

    def test_dtmf_fields_are_required_by_each_observation_and_release_schema(self):
        participant = {
            "schema_version": 1,
            "producer": "bridgefu-agent-workspace-playwright@1",
            "producer_revision_sha256": "a" * 64,
            "execution_id": "bfq-test1234",
            "scenario_id": "bridgefu-web-sdk-handoff",
            "hangup_origin": "source",
            "correlation_fingerprint": "a" * 12,
            "source_call_fingerprint": "b" * 12,
            "observed_at": "2026-08-11T04:20:00Z",
            "screen_pop": {
                "visible": True,
                "visible_fields": [
                    "customer_name",
                    "issue_summary",
                    "intent",
                    "verification_status",
                ],
                "screenshot_sha256": "c" * 64,
            },
            "media": {
                "source_to_agent_marker_frames": 5,
                "source_marker_observed_at_ms": [1, 2, 3],
                "dtmf_source_to_agent_observed": True,
                "agent_marker_sent_at_ms": [1, 2, 3, 4, 5],
                "agent_to_source_marker_frames_sent": 25,
                "dtmf_agent_to_source_sent_at_ms": [6],
            },
            "hangup": {
                "origin": "source",
                "local_end_completed": False,
                "remote_end_observed": True,
                "cleanup_observed": True,
            },
            "redacted": True,
        }
        CONTROLLER.validate_schema(
            participant, "participant-observation-v1.schema.json"
        )
        for field in (
            "dtmf_source_to_agent_observed",
            "dtmf_agent_to_source_sent_at_ms",
        ):
            changed = json.loads(json.dumps(participant))
            del changed["media"][field]
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.validate_schema(
                    changed, "participant-observation-v1.schema.json"
                )

        web = {
            "schema_version": 1,
            "producer": "bridgefu-webrtc-browser-playwright@1",
            "producer_revision_sha256": "a" * 64,
            "site_bundle_sha256": "b" * 64,
            "browser_sdk_name": "@bridgefu/webrtc-browser",
            "browser_sdk_version": "0.1.0",
            "execution_id": "bfq-test1234",
            "scenario_id": "bridgefu-web-sdk-handoff",
            "hangup_origin": "source",
            "correlation_fingerprint": "a" * 12,
            "source_call_fingerprint": "b" * 12,
            "observed_at": "2026-08-11T04:20:00Z",
            "bridgefu": {
                "webrtc_call_started": True,
                "server_handoff_triggered": True,
                "call_end_observed": True,
            },
            "media": {
                "codec": "negotiated",
                "security": "srtp",
                "source_marker_sent_at_ms": [1, 2, 3, 4, 5],
                "dtmf_source_to_agent_sent_at_ms": [6],
                "agent_marker_observed_at_ms": [1, 2, 3],
                "source_to_agent_marker_frames_sent": 25,
                "agent_to_source_marker_frames": 3,
                "dtmf_agent_to_source_observed": True,
            },
            "hangup": {
                "origin": "source",
                "local_end_completed": True,
                "remote_end_observed": False,
                "cleanup_observed": True,
            },
            "redacted": True,
        }
        CONTROLLER.validate_schema(
            web, "bridgefu-browser-source-observation-v1.schema.json"
        )
        for field in (
            "dtmf_source_to_agent_sent_at_ms",
            "dtmf_agent_to_source_observed",
        ):
            changed = json.loads(json.dumps(web))
            del changed["media"][field]
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.validate_schema(
                    changed, "bridgefu-browser-source-observation-v1.schema.json"
                )

        sip = {
            "schema_version": 1,
            "producer": "bridgefu-vapi-sip-smoke@1",
            "producer_revision_sha256": "a" * 64,
            "execution_id": "bfq-test1234",
            "scenario_id": "vapi-sip-transfer",
            "observed_at": "2026-08-11T04:20:00Z",
            "signaling": {
                "source": "rvoip-sip-0.3.7",
                "target": "sip.vapi.ai",
                "invite_sent": True,
                "answered": True,
                "transport": "udp",
            },
            "media": {
                "codec": "pcmu-or-pcma",
                "prompt_frames_sent": 1,
                "source_marker_sent_at_ms": [1],
                "source_to_agent_marker_frames_sent": 5,
                "dtmf_source_to_agent_sent_at_ms": [2],
                "dtmf_source_to_agent_frames_sent": 15,
                "agent_marker_observed_at_ms": [1, 2, 3, 4, 5],
                "agent_to_source_marker_frames": 5,
            },
            "hangup": {"local_bye_completed": True, "cleanup_observed": True},
            "redacted": True,
        }
        CONTROLLER.validate_schema(sip, "source-observation-v1.schema.json")
        for field in (
            "dtmf_source_to_agent_sent_at_ms",
            "dtmf_source_to_agent_frames_sent",
        ):
            changed = json.loads(json.dumps(sip))
            del changed["media"][field]
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.validate_schema(changed, "source-observation-v1.schema.json")

        base_checks = {
            "vapi_call_connected": True,
            "vapi_transfer_invoked": True,
            "handoff_context_stored": True,
            "bridgefu_received_correlation_header": True,
            "amazon_connect_contact_connected": True,
            "configured_screen_pop_visible": True,
            "audio_source_to_agent": True,
            "audio_agent_to_source": True,
            "dtmf_source_to_agent": True,
            "source_call_ended": True,
        }
        evidence = {
            "schema_version": 1,
            "release": "1.2.3",
            "execution_id": "bfq-test1234",
            "region": "us-west-2",
            "started_at": "2026-08-11T04:20:00Z",
            "ended_at": "2026-08-11T04:21:00Z",
            "bridgefu_commit": "a" * 40,
            "scenarios": [
                {
                    "id": "vapi-sip-transfer",
                    "source_observation_sha256": "a" * 64,
                    "agent_observation_sha256": "b" * 64,
                    "checks": dict(base_checks),
                    "passed": True,
                },
                {
                    "id": "bridgefu-web-sdk-handoff",
                    "source_observation_sha256": "c" * 64,
                    "agent_observation_sha256": "d" * 64,
                    "checks": {**base_checks, "dtmf_agent_to_source": True},
                    "passed": True,
                },
            ],
            "teardown": {
                "customer_stack_absent": True,
                "connect_instance_absent": True,
                "temporary_vapi_resources_absent": True,
                "test_credentials_absent": True,
                "qualification_objects_absent": True,
            },
            "redacted": True,
        }
        CONTROLLER.validate_schema(evidence, "evidence-v1.schema.json")
        for scenario_index, field in (
            (0, "handoff_context_stored"),
            (0, "dtmf_source_to_agent"),
            (1, "dtmf_agent_to_source"),
        ):
            changed = json.loads(json.dumps(evidence))
            del changed["scenarios"][scenario_index]["checks"][field]
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.validate_schema(changed, "evidence-v1.schema.json")

    def test_cloudformation_failure_evidence_is_saved_before_cleanup(self):
        output = Path(tempfile.mkdtemp(prefix="qualification-evidence-test-"))
        try:
            args = SimpleNamespace(
                execution_id="bfq-test1234", region="us-west-2", output=output
            )
            controller = CONTROLLER.Controller(args)
            controller.created_stack = True
            controller.phase = "cloudformation_deploy"

            class Aws:
                region = "us-west-2"

                def json(self, arguments, timeout=900):
                    if "describe-stacks" in arguments:
                        return {"Stacks": [{"StackStatus": "CREATE_FAILED"}]}
                    return {
                        "StackEvents": [
                            {
                                "LogicalResourceId": "Candidate",
                                "ResourceType": "AWS::CloudFormation::Stack",
                                "ResourceStatus": "CREATE_FAILED",
                                "ResourceStatusReason": (
                                    "Image unavailable password=do-not-retain"
                                ),
                                "Timestamp": "2026-08-11T04:20:00Z",
                            }
                        ]
                    }

            controller.aws = Aws()
            controller.record_failure_evidence(
                CONTROLLER.QualificationError("aws cloudformation failed")
            )
            evidence = json.loads((output / "failure-evidence.json").read_text())
            self.assertEqual(evidence["phase"], "cloudformation_deploy")
            self.assertTrue(evidence["cloudformation"]["observed"])
            self.assertIn("capture_error", evidence["cloudformation"])
            CONTROLLER.validate_schema(evidence, "failure-evidence-v1.schema.json")
            failure = evidence["cloudformation"]["failed_events"][0]
            self.assertEqual(failure["stack_depth"], 0)
            reason = failure["reason"]
            self.assertIn("password=[REDACTED]", reason)
            self.assertNotIn("do-not-retain", reason)
        finally:
            shutil.rmtree(output)
            if "controller" in locals():
                shutil.rmtree(controller.work, ignore_errors=True)

    def test_failure_evidence_schema_accepts_every_current_run_phase(self):
        output = Path(tempfile.mkdtemp(prefix="qualification-phase-test-"))
        try:
            controller = CONTROLLER.Controller(
                SimpleNamespace(
                    execution_id="bfq-test1234", region="us-west-2", output=output
                )
            )
            controller.created_stack = False
            for phase in (
                "input_validation",
                "web_site_validation",
                "preflight",
                "cloudformation_deploy",
                "connect_authentication",
                "direct_secure_preflight",
                "credential_initialization",
                "vapi_web_transfer",
                "vapi_sip_transfer",
                "vapi_provisioning_resilience",
            ):
                with self.subTest(phase=phase):
                    controller.phase = phase
                    controller.record_failure_evidence(
                        CONTROLLER.QualificationError("bounded failure")
                    )
                    evidence = json.loads(
                        (output / "failure-evidence.json").read_text()
                    )
                    self.assertEqual(evidence["phase"], phase)
                    CONTROLLER.validate_schema(
                        evidence, "failure-evidence-v1.schema.json"
                    )
        finally:
            shutil.rmtree(output)
            if "controller" in locals():
                shutil.rmtree(controller.work, ignore_errors=True)

    def test_cloudformation_failure_capture_descends_into_bounded_nested_stacks(self):
        nested = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/bridgefu-candidate/12345678-1234-1234-1234-123456789012"
        )

        class Aws:
            region = "us-west-2"

            def json(self, arguments, timeout=900):
                identifier = arguments[arguments.index("--stack-name") + 1]
                if identifier == "bridgefu-bfq-test1234":
                    return {
                        "StackEvents": [
                            {
                                "EventId": "root-event",
                                "LogicalResourceId": "Candidate",
                                "PhysicalResourceId": nested,
                                "ResourceType": "AWS::CloudFormation::Stack",
                                "ResourceStatus": "CREATE_FAILED",
                                "ResourceStatusReason": "Nested stack failed",
                                "Timestamp": "2026-08-11T04:20:00Z",
                            }
                        ]
                    }
                self.assert_nested = identifier
                return {
                    "StackEvents": [
                        {
                            "EventId": "nested-event",
                            "LogicalResourceId": "BridgefuHost",
                            "ResourceType": "AWS::EC2::Instance",
                            "ResourceStatus": "CREATE_FAILED",
                            "ResourceStatusReason": "AMI was not launchable",
                            "Timestamp": "2026-08-11T04:20:01Z",
                        }
                    ]
                }

        aws = Aws()
        events, error = CONTROLLER.collect_cloudformation_failure_events(
            aws, "bridgefu-bfq-test1234"
        )
        self.assertIsNone(error)
        self.assertEqual(aws.assert_nested, nested)
        self.assertEqual([item["stack_depth"] for item in events], [0, 1])
        self.assertEqual(events[1]["reason"], "AMI was not launchable")

    def test_correlation_is_exact_deterministic_bf1_hmac(self):
        value = CONTROLLER.derive_correlation_id(
            "k" * 32, "bfq-test1234", "org_1234", "call_1234"
        )
        self.assertRegex(value, r"^bf1_[A-Za-z0-9_-]{43}$")
        self.assertEqual(
            value,
            CONTROLLER.derive_correlation_id(
                "k" * 32, "bfq-test1234", "org_1234", "call_1234"
            ),
        )
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.derive_correlation_id(
                "k" * 32, "bfq-test1234", "org|unsafe", "call_1234"
            )

    def test_session_contains_only_the_private_harness_contract(self):
        session = CONTROLLER.make_session(
            execution_id="bfq-test1234",
            scenario="bridgefu-web-sdk-handoff",
            call={
                "id": "call_1234",
                "orgId": "org_1234",
                "createdAt": "2026-08-08T12:00:00Z",
            },
            correlation_key="k" * 32,
            bridgefu_commit="a" * 40,
            release="1.2.3",
            sip_uri=None,
        )
        self.assertEqual(len(session), 25)
        self.assertEqual(session["source_call_id"], "call_1234")
        self.assertEqual(session["vapi_call_id"], "call_1234")
        self.assertEqual(session["expected_context"]["intent"], "qualification")
        self.assertEqual(session["hangup_origin"], "source")
        self.assertRegex(session["session_hmac"], r"^[0-9a-f]{64}$")

    def test_web_session_binds_bridgefu_source_and_vapi_call_separately(self):
        correlation = "bf1_" + "a" * 43
        session = CONTROLLER.make_session(
            execution_id="bfq-test1234",
            scenario="bridgefu-web-sdk-handoff",
            call={
                "id": "vapi_call_1234",
                "orgId": "org_1234",
                "createdAt": "2026-08-08T12:00:00Z",
            },
            correlation_key="k" * 32,
            bridgefu_commit="a" * 40,
            release="1.2.3",
            sip_uri=None,
            source_call_id="bridgefu_call_1234",
            correlation_id=correlation,
        )
        self.assertEqual(session["source_call_id"], "bridgefu_call_1234")
        self.assertEqual(session["vapi_call_id"], "vapi_call_1234")
        self.assertEqual(session["correlation_id"], correlation)
        self.assertEqual(
            session["source_call_fingerprint"],
            CONTROLLER.sha256_bytes(b"bridgefu_call_1234")[:12],
        )

    def test_direct_context_is_mapped_before_the_vapi_tool_can_replace(self):
        binding = CONTROLLER.bridgefu_web_handoff.DirectRouteBinding(
            tenant_id="support",
            call_id="bridgefu_call_1234",
            source_leg_id="browser_leg_1234",
            destination_leg_id="vapi_leg_1234",
            route_attachment={},
        )
        item = CONTROLLER.direct_context_item(
            correlation_id="bf1_" + "a" * 43,
            token_id="token_1234",  # noqa: S106 -- opaque non-secret test identity.
            binding=binding,
            schema_hash="b" * 64,
            now=1_786_000_000,
        )
        self.assertEqual(item["handoff_status"], {"S": "MAPPED"})
        self.assertEqual(item["bridgefu_call_id"], {"S": "bridgefu_call_1234"})
        self.assertEqual(item["direct_leg_id"], {"S": "vapi_leg_1234"})
        self.assertEqual(item["direct_route_id"], {"S": "amazon-connect"})
        self.assertEqual(item["expires_at"], {"N": "1786003600"})
        serialized = json.dumps(item)
        for forbidden in ("password", "Bearer ", "sips:", "handoff_token"):
            self.assertNotIn(forbidden, serialized)

    def test_direct_context_write_uses_one_stdin_document_and_no_private_argv(self):
        class Runner:
            def run(self, arguments, *, input_text=None, timeout=60, **_kwargs):
                self.arguments = arguments
                self.input_text = input_text
                self.timeout = timeout

        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace(region="us-west-2")
        controller.outputs = {
            "HandoffTableName": "bridgefu-bfq-test1234-handoffs",
            "ScreenPopSchemaHash": "b" * 64,
        }
        controller.runner = Runner()
        binding = CONTROLLER.bridgefu_web_handoff.DirectRouteBinding(
            tenant_id="support",
            call_id="bridgefu_call_1234",
            source_leg_id="browser_leg_1234",
            destination_leg_id="vapi_leg_1234",
            route_attachment={},
        )
        correlation = "bf1_" + "a" * 43
        token = "token_1234"  # noqa: S105 -- opaque one-use test identity.
        controller.stage_direct_context(
            correlation_id=correlation,
            token_id=token,
            binding=binding,
            now=1_786_000_000,
        )
        arguments = controller.runner.arguments
        self.assertEqual(arguments.count("--cli-input-json"), 1)
        self.assertEqual(
            arguments[arguments.index("--cli-input-json") + 1], "file:///dev/stdin"
        )
        self.assertNotIn(correlation, arguments)
        self.assertNotIn(token, arguments)
        request = json.loads(controller.runner.input_text)
        self.assertEqual(request["Item"]["correlation_id"], {"S": correlation})
        self.assertEqual(request["Item"]["direct_token_id"], {"S": token})

    def test_secret_write_uses_stdin_and_never_places_secret_on_argv(self):
        class Runner:
            def run(self, arguments, *, input_text=None, timeout=60, **_kwargs):
                self.arguments = arguments
                self.input_text = input_text

        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace(region="us-west-2")
        controller.runner = Runner()
        secret = "this-is-a-private-qualification-password"  # noqa: S105
        controller.put_secret_json(
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:qualification/test",
            {"password": secret},
        )
        self.assertNotIn(secret, controller.runner.arguments)
        self.assertNotIn("--cli-input-json", controller.runner.arguments)
        self.assertEqual(controller.runner.arguments.count("--secret-id"), 1)
        self.assertEqual(controller.runner.arguments.count("--secret-string"), 1)
        self.assertEqual(
            controller.runner.arguments[
                controller.runner.arguments.index("--secret-string") + 1
            ],
            "file:///dev/stdin",
        )
        self.assertEqual(
            json.loads(controller.runner.input_text),
            {"password": secret},
        )

    def test_qualification_tool_schema_uses_the_screen_pop_order(self):
        schema = CONTROLLER.qualification_field_schema()
        self.assertEqual(schema["required"], list(CONTROLLER.SCREEN_POP_KEYS))
        self.assertEqual(list(schema["properties"]), list(CONTROLLER.SCREEN_POP_KEYS))

    def test_dynamo_v2_values_must_match_exact_synthetic_context(self):
        session = {
            "scenario_id": "vapi-sip-transfer",
            "correlation_id": "bf1_" + "a" * 43,
            "expected_context": CONTROLLER.synthetic_context("vapi-sip-transfer"),
        }
        item = {
            "correlation_id": {"S": session["correlation_id"]},
            "handoff_status": {"S": "CONSUMED"},
            "screen_pop_values": {
                "M": {
                    key: {"S": value}
                    for key, value in session["expected_context"].items()
                }
            },
        }
        CONTROLLER.verify_handoff_item(item, session)
        item["screen_pop_values"]["M"]["intent"] = {"S": "wrong"}
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.verify_handoff_item(item, session)

    def test_log_proof_requires_exact_header_and_available_lookup(self):
        fingerprint = "a1b2c3d4e5f6"
        runtime = {
            "events": [
                {
                    "message": json.dumps(
                        {
                            "event": "bridgefu_sip_invite_evidence",
                            "correlation_fingerprint": fingerprint,
                            "header_name": "x-correlation-id",
                            "header_count": 1,
                        }
                    )
                },
                {
                    "message": json.dumps(
                        {
                            "event": "bridgefu_vapi_destination_security_evidence",
                            "correlation_fingerprint": fingerprint,
                            "leg": "vapi-to-bridgefu",
                            "uri_scheme": "sip",
                            "signaling_transport": "tls",
                            "media_profile": "RTP/SAVP",
                            "media_keying": "SDES-SRTP",
                            "media_suite": "AES_CM_128_HMAC_SHA1_80",
                            "inbound_srtp_context_installed": True,
                            "outbound_srtp_context_installed": True,
                            "answered": True,
                            "redacted": True,
                            "message": "accepted Vapi destination leg",
                        }
                    )
                },
            ]
        }
        lookup = {
            "events": [
                {
                    "message": json.dumps(
                        {
                            "event": "bridgefu_correlation_evidence",
                            "operation": "connect_lookup",
                            "correlation_fingerprint": fingerprint,
                            "result": "available",
                        }
                    )
                }
            ]
        }
        CONTROLLER.verify_log_evidence(
            runtime, lookup, fingerprint, "sips_optional_srtp"
        )
        runtime["events"][0]["message"] = runtime["events"][0]["message"].replace(
            '"header_count": 1', '"header_count": 2'
        )
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.verify_log_evidence(
                runtime, lookup, fingerprint, "sips_optional_srtp"
            )

    def test_web_log_proof_requires_outbound_bridgefu_to_vapi_security_event(self):
        fingerprint = "a1b2c3d4e5f6"
        runtime = {
            "events": [
                {
                    "message": json.dumps(
                        {
                            "event": "bridgefu_vapi_source_security_evidence",
                            "correlation_fingerprint": fingerprint,
                            "leg": "bridgefu-to-vapi",
                            "uri_scheme": "sips",
                            "signaling_transport": "tls",
                            "media_profile": "RTP/AVP",
                            "media_keying": "none",
                            "media_suite": "none",
                            "inbound_srtp_context_installed": False,
                            "outbound_srtp_context_installed": False,
                            "answered": True,
                            "redacted": True,
                            "message": "established Bridgefu Vapi source leg",
                        }
                    )
                }
            ]
        }
        lookup = {
            "events": [
                {
                    "message": json.dumps(
                        {
                            "event": "bridgefu_correlation_evidence",
                            "operation": "connect_lookup",
                            "correlation_fingerprint": fingerprint,
                            "result": "available",
                        }
                    )
                }
            ]
        }
        proof = CONTROLLER.verify_log_evidence(
            runtime,
            lookup,
            fingerprint,
            "sips_optional_srtp",
            "bridgefu-web-sdk-handoff",
        )
        self.assertTrue(proof["bridgefu_received_correlation_header"])
        self.assertEqual(proof["vapi_destination_media_profile"], "RTP/AVP")
        runtime["events"][0]["message"] = runtime["events"][0]["message"].replace(
            '"signaling_transport": "tls"', '"signaling_transport": "udp"'
        )
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.verify_log_evidence(
                runtime,
                lookup,
                fingerprint,
                "sips_optional_srtp",
                "bridgefu-web-sdk-handoff",
            )

    def test_vapi_call_requires_prepare_tool_and_transfer_activity(self):
        self.assertTrue(
            CONTROLLER.call_contains_transfer(
                {
                    "status": "ended",
                    "transfers": ["completed"],
                    "artifact": {
                        "messages": [
                            {"toolName": "prepare_handoff"},
                            {"toolName": "transferCall"},
                        ]
                    },
                }
            )
        )
        self.assertFalse(
            CONTROLLER.call_contains_transfer({"artifact": {"messages": []}})
        )
        self.assertTrue(
            CONTROLLER.call_contains_transfer(
                {
                    "status": "ended",
                    "artifact": {"messages": [{"toolName": "bridgefu_direct_handoff"}]},
                },
                "bridgefu-web-sdk-handoff",
            )
        )

    def test_aws_absence_check_fails_closed_on_access_denied(self):
        class Runner:
            def probe(self, arguments, timeout=60):
                return 255, "", "AccessDeniedException"

        aws = CONTROLLER.Aws("us-west-2", Runner())
        with self.assertRaises(CONTROLLER.QualificationError):
            aws.exists(["connect", "describe-instance", "--instance-id", "x"])


if __name__ == "__main__":
    unittest.main()
