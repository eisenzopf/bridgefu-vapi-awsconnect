from __future__ import annotations

import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "secure_preflight_controller", ROOT / "qualification" / "controller.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("qualification controller could not be imported")
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


def direct_agent_observation() -> dict[str, object]:
    return {
        "schema_version": 1,
        "producer": "bridgefu-agent-direct-secure-observer@1",
        "producer_revision_sha256": "a" * 64,
        "mode": "direct-secure-preflight",
        "agent_available": True,
        "sole_contact_auto_accepted": True,
        "remote_audio_observed": True,
        "outbound_rtp_observed": True,
        "remote_hangup_observed": True,
        "contact_cleanup_observed": True,
        "redacted": True,
    }


def cleanup_result(**changes: bool) -> dict[str, bool]:
    result = {name: True for name in CONTROLLER.direct_secure_preflight.CLEANUP_FIELDS}
    result.update(changes)
    return result


class FakeProcess:
    def __init__(
        self, running: bool = False, *, returncode: int = 0, stderr: str = ""
    ) -> None:
        self.running = running
        self.returncode = None if running else returncode
        self.terminated = False
        self.stderr = stderr

    def poll(self):
        return None if self.running else self.returncode

    def terminate(self):
        self.terminated = True
        self.running = False
        self.returncode = -15

    def kill(self):
        self.running = False
        self.returncode = -9

    def communicate(self, *args, **kwargs):
        return "", self.stderr


class FakeDirectAws:
    region = "us-west-2"

    def __init__(self, remote_cleanup: dict[str, bool] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.command_ids = iter(("command-probe", "command-cleanup"))
        self.remote_cleanup = remote_cleanup or cleanup_result()

    def text(self, arguments, timeout=900):
        self.calls.append(list(arguments))
        if "send-command" in arguments:
            return next(self.command_ids)
        return ""

    def json(self, arguments, timeout=900):
        self.calls.append(list(arguments))
        command_id = arguments[arguments.index("--command-id") + 1]
        value = (
            CONTROLLER.direct_secure_preflight.expected_probe_result()
            if command_id == "command-probe"
            else self.remote_cleanup
        )
        return {
            "Status": "Success",
            "StandardOutputContent": json.dumps(value, separators=(",", ":")),
        }


class SecurePreflightGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = Path(tempfile.mkdtemp(prefix="secure-preflight-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.temporary, ignore_errors=True)

    def controller_for_direct(
        self, *, remote_cleanup: dict[str, bool] | None = None, running=False
    ):
        probe = self.temporary / "bridgefu-direct-secure-probe"
        probe.write_bytes(b"static direct secure probe")
        probe.chmod(0o700)
        observation = self.temporary / "agent.json"
        CONTROLLER.private_json(observation, direct_agent_observation())
        process = FakeProcess(running=running)
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace(
            execution_id="bfq-test1234",
            region="us-west-2",
            direct_secure_probe=probe,
        )
        controller.outputs = {
            "ArtifactBucket": "bridgefu-artifacts-test",
            "BridgefuInstanceId": "i-0123456789abcdef0",
            "ConnectInstanceId": "connect-instance",
            "ConnectInstanceArn": (
                "arn:aws:connect:us-west-2:123456789012:instance/connect-instance"
            ),
            "AgentUsername": "bridgefu-demo-agent",
        }
        controller.aws = FakeDirectAws(remote_cleanup)
        controller.ssm_commands = []
        controller.processes = [process]
        controller.secure_preflight_binary_sha256 = CONTROLLER.sha256_file(probe)
        controller.secure_preflight_object_key = None
        controller.secure_preflight_cleanup_required = False
        controller.secure_preflight_restoration_passed = False
        controller.secure_preflight_cleanup_passed = False
        controller.secure_preflight_evidence = None
        controller.start_direct_secure_agent = mock.Mock(
            return_value=(process, observation)
        )
        controller.complete_process = mock.Mock()
        return controller, process

    def test_cli_requires_executable_non_symlink_and_hashes_it(self):
        option = next(
            action
            for action in CONTROLLER.parser()._actions
            if "--direct-secure-probe" in action.option_strings
        )
        self.assertTrue(option.required)

        probe = self.temporary / "probe"
        probe.write_bytes(b"immutable probe")
        probe.chmod(0o700)
        sip = self.temporary / "sip"
        sip.write_bytes(b"sip")
        checkout = self.temporary / "checkout"
        checkout.mkdir()
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace(
            execution_id="bfq-test1234",
            region="us-west-2",
            release="1.2.3",
            hosted_zone_id="Z1234",
            hosted_zone_name="example.test",
            cloudformation_role_arn=("arn:aws:iam::123456789012:role/qualification"),
            template_url="https://example.test/template.yaml",
            sip_client=sip,
            direct_secure_probe=probe,
            demo_site_archive=probe,
            demo_site_sha256=CONTROLLER.sha256_file(probe),
            bridgefu_checkout=checkout,
        )
        controller.bridgefu_lock = {
            "commit": "a" * 40,
            "cargo_lock_sha256": "b" * 64,
        }
        controller.secure_preflight_binary_sha256 = None
        with mock.patch.object(
            CONTROLLER.shutil,
            "which",
            return_value="/usr/local/bin/session-manager-plugin",
        ):
            controller.validate_inputs()
        self.assertEqual(
            controller.secure_preflight_binary_sha256,
            CONTROLLER.sha256_file(probe),
        )

        link = self.temporary / "probe-link"
        link.symlink_to(probe)
        controller.args.direct_secure_probe = link
        with (
            mock.patch.object(
                CONTROLLER.shutil,
                "which",
                return_value="/usr/local/bin/session-manager-plugin",
            ),
            self.assertRaises(CONTROLLER.QualificationError),
        ):
            controller.validate_inputs()

        controller.args.direct_secure_probe = probe
        with (
            mock.patch.object(CONTROLLER.shutil, "which", return_value=None),
            self.assertRaisesRegex(
                CONTROLLER.QualificationError, "Session Manager plugin is unavailable"
            ),
        ):
            controller.validate_inputs()

    def test_browser_readiness_surfaces_bounded_redacted_early_exit(self):
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        process = FakeProcess(
            returncode=1,
            stderr="browser failed password=do-not-retain\nsecond line",
        )
        controller.processes = [process]
        with self.assertRaisesRegex(
            CONTROLLER.QualificationError, "exited before readiness"
        ) as raised:
            controller.wait_for_process_file(
                process,
                self.temporary / "missing.json",
                CONTROLLER.BROWSER_READINESS_TIMEOUT_SECONDS,
                "Amazon Connect smoke observer",
            )
        self.assertIn("password=[REDACTED]", str(raised.exception))
        self.assertNotIn("do-not-retain", str(raised.exception))
        self.assertNotIn(process, controller.processes)

    def test_browser_readiness_timeout_terminates_owned_process(self):
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        process = FakeProcess(running=True, stderr="bounded timeout detail")
        controller.processes = [process]
        with (
            mock.patch.object(
                CONTROLLER.time, "monotonic", side_effect=(0.0, 0.0, 211.0)
            ),
            mock.patch.object(CONTROLLER.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                CONTROLLER.QualificationError,
                "readiness timed out: bounded timeout detail",
            ):
                controller.wait_for_process_file(
                    process,
                    self.temporary / "missing.json",
                    CONTROLLER.BROWSER_READINESS_TIMEOUT_SECONDS,
                    "Vapi Web smoke source",
                )
        self.assertTrue(process.terminated)
        self.assertNotIn(process, controller.processes)

    def test_all_browser_readiness_paths_use_process_aware_upper_bound(self):
        self.assertGreaterEqual(CONTROLLER.BROWSER_READINESS_TIMEOUT_SECONDS, 210)
        controller = (ROOT / "qualification" / "controller.py").read_text()
        self.assertNotIn("self.wait_for_file(", controller)
        self.assertEqual(controller.count("self.wait_for_process_file("), 3)

    def test_success_uses_ready_observer_first_static_object_and_exact_cleanup(self):
        controller, _ = self.controller_for_direct()
        with (
            mock.patch.object(CONTROLLER, "ensure_connect_agent_available"),
            mock.patch.object(CONTROLLER, "wait_for_ssm_command"),
            mock.patch.object(
                CONTROLLER, "cancel_and_wait_ssm_terminal", return_value=True
            ),
            mock.patch.object(CONTROLLER, "purge_object_versions_exact") as purge,
        ):
            controller.direct_secure_preflight(self.temporary / "storage.json")

        self.assertTrue(controller.secure_preflight_evidence["passed"])
        self.assertTrue(controller.secure_preflight_cleanup_passed)
        controller.start_direct_secure_agent.assert_called_once()
        send_calls = [call for call in controller.aws.calls if "send-command" in call]
        self.assertEqual(len(send_calls), 2)
        probe_program = send_calls[0][send_calls[0].index("--parameters") + 1]
        self.assertIn("--request-stdin", probe_program)
        self.assertIn("--send-dtmf", probe_program)
        self.assertNotIn("api.vapi.ai", probe_program.lower())
        self.assertNotIn("sip.vapi.ai", probe_program.lower())
        upload = next(call for call in controller.aws.calls if call[:2] == ["s3", "cp"])
        self.assertEqual(upload[2], os.fspath(controller.args.direct_secure_probe))
        purge.assert_called_once()
        _, bucket, key = purge.call_args.args
        targets = [value for value in upload if value.startswith("s3://")]
        self.assertEqual(len(targets), 1)
        self.assertIn(f"/{key}", targets[0])
        self.assertNotIn("correlation", " ".join(upload).lower())
        self.assertEqual(bucket, "bridgefu-artifacts-test")
        self.assertRegex(
            key,
            r"^qualification/bfq-test1234/direct-secure-preflight/"
            r"[0-9a-f]{32}/bridgefu-direct-secure-probe$",
        )
        self.assertTrue(purge.call_args.kwargs["exact_key"])

    def test_timeout_still_cancels_waits_restores_and_purges(self):
        controller, process = self.controller_for_direct(running=True)
        waits = mock.Mock(
            side_effect=[CONTROLLER.QualificationError("command timed out"), None]
        )
        with (
            mock.patch.object(CONTROLLER, "ensure_connect_agent_available"),
            mock.patch.object(CONTROLLER, "wait_for_ssm_command", waits),
            mock.patch.object(
                CONTROLLER, "cancel_and_wait_ssm_terminal", return_value=True
            ) as cancel,
            mock.patch.object(CONTROLLER, "purge_object_versions_exact") as purge,
        ):
            with self.assertRaises(CONTROLLER.QualificationError):
                controller.direct_secure_preflight(self.temporary / "storage.json")
        self.assertGreaterEqual(cancel.call_count, 1)
        self.assertEqual(
            len([call for call in controller.aws.calls if "send-command" in call]),
            2,
        )
        purge.assert_called_once()
        self.assertTrue(controller.secure_preflight_restoration_passed)
        self.assertTrue(controller.secure_preflight_cleanup_passed)
        self.assertTrue(process.terminated)
        self.assertIsNone(controller.secure_preflight_evidence)

    def test_failed_restoration_blocks_gate_and_disallows_retention(self):
        controller, _ = self.controller_for_direct(
            remote_cleanup=cleanup_result(configuration_restored=False)
        )
        with (
            mock.patch.object(CONTROLLER, "ensure_connect_agent_available"),
            mock.patch.object(CONTROLLER, "wait_for_ssm_command"),
            mock.patch.object(
                CONTROLLER, "cancel_and_wait_ssm_terminal", return_value=True
            ),
            mock.patch.object(CONTROLLER, "purge_object_versions_exact"),
        ):
            with self.assertRaises(CONTROLLER.QualificationError):
                controller.direct_secure_preflight(self.temporary / "storage.json")
        self.assertFalse(controller.secure_preflight_restoration_passed)
        self.assertFalse(controller.secure_preflight_cleanup_passed)
        self.assertIsNone(controller.secure_preflight_evidence)

        run_controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        run_controller.args = SimpleNamespace(
            retain_on_failure=True,
            output=self.temporary,
            release="1.2.3",
            execution_id="bfq-test1234",
            region="us-west-2",
        )
        run_controller.work = self.temporary / "work"
        run_controller.work.mkdir()
        run_controller.phase = "initialization"
        run_controller.bridgefu_lock = {"commit": "a" * 40}
        run_controller.scenario_evidence = []
        run_controller.secure_preflight_evidence = None
        run_controller.secure_preflight_cleanup_required = False
        run_controller.secure_preflight_restoration_passed = False
        run_controller.secure_preflight_cleanup_passed = False
        run_controller.database_reset_evidence = {}
        run_controller.validate_inputs = mock.Mock()
        run_controller.preflight = mock.Mock()
        run_controller.deploy = mock.Mock()
        run_controller.build_site = mock.Mock(return_value=(Path("site"), "digest"))
        run_controller.authenticate_agent = mock.Mock(return_value=Path("storage"))
        run_controller.reset_test_database = mock.Mock()

        def fail_direct(_storage):
            run_controller.secure_preflight_cleanup_required = True
            run_controller.secure_preflight_restoration_passed = False
            run_controller.secure_preflight_cleanup_passed = False
            raise CONTROLLER.QualificationError("restoration failed")

        run_controller.direct_secure_preflight = mock.Mock(side_effect=fail_direct)
        run_controller.initialize_vapi = mock.Mock()
        run_controller.record_failure_evidence = mock.Mock()
        run_controller.cleanup = mock.Mock(return_value={})
        run_controller.stop_active_work = mock.Mock(return_value=[])
        run_controller.record_retained_environment = mock.Mock()
        with self.assertRaises(CONTROLLER.QualificationError):
            run_controller.run()
        run_controller.initialize_vapi.assert_not_called()
        run_controller.cleanup.assert_called_once()
        run_controller.record_retained_environment.assert_not_called()

    def test_owned_ssm_is_cancelled_and_observed_terminal(self):
        class Aws:
            def __init__(self):
                self.statuses = iter(("InProgress", "Cancelling", "Cancelled"))
                self.cancelled = []

            def json(self, arguments):
                return {"Status": next(self.statuses)}

            def text(self, arguments):
                self.cancelled.append(arguments)
                return ""

        aws = Aws()
        with mock.patch.object(CONTROLLER.time, "sleep"):
            self.assertTrue(
                CONTROLLER.cancel_and_wait_ssm_terminal(
                    aws,
                    "command-probe",
                    "i-0123456789abcdef0",
                    timeout=1,
                    poll_seconds=0,
                )
            )
        self.assertEqual(
            aws.cancelled,
            [["ssm", "cancel-command", "--command-id", "command-probe"]],
        )

    def test_run_orders_restoration_before_credentials_and_both_sources(self):
        source = inspect.getsource(CONTROLLER.Controller.run)
        self.assertLess(
            source.index('self.reset_test_database("direct-secure-preflight")'),
            source.index("self.direct_secure_preflight(storage)"),
        )
        self.assertLess(
            source.index("self.direct_secure_preflight(storage)"),
            source.index("self.initialize_vapi()"),
        )
        self.assertLess(
            source.index("self.initialize_vapi()"),
            source.index('self.outputs["CorrelationKeySecretArn"]'),
        )
        self.assertLess(
            source.index("self.direct_secure_preflight(storage)"),
            source.index("self.web_smoke("),
        )
        self.assertLess(
            source.index("self.reset_test_database(WEB_SCENARIO)"),
            source.index("self.web_smoke("),
        )
        self.assertLess(
            source.index('self.reset_test_database("vapi-sip-transfer")'),
            source.index("self.sip_smoke("),
        )
        self.assertLess(
            source.index("self.direct_secure_preflight(storage)"),
            source.index("self.sip_smoke("),
        )
        direct = inspect.getsource(CONTROLLER.Controller.direct_secure_preflight)
        self.assertLess(
            direct.index("start_direct_secure_agent"),
            direct.index("send_owned_shell"),
        )
        self.assertNotIn("self.vapi", direct)

    def test_owned_shell_sends_real_bounded_ssm_command_lines(self):
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.aws = FakeDirectAws()
        controller.ssm_commands = []

        command_id = controller.send_owned_shell(
            "i-0123456789abcdef0",
            "set -euo pipefail\nvalue='safe (value)' && printf '%s\\n' \"$value\"",
        )

        self.assertEqual(command_id, "command-probe")
        arguments = controller.aws.calls[-1]
        encoded = arguments[arguments.index("--parameters") + 1]
        self.assertEqual(
            json.loads(encoded),
            {
                "commands": [
                    "set -euo pipefail",
                    "value='safe (value)' && printf '%s\\n' \"$value\"",
                ]
            },
        )
        self.assertTrue(encoded.startswith("{"))
        self.assertNotIn("\\n", json.loads(encoded)["commands"][0])

    def test_owned_shell_strips_blanks_and_rejects_empty_crlf_and_oversized_lines(self):
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.aws = FakeDirectAws()
        controller.ssm_commands = []
        controller.send_owned_shell("i-0123456789abcdef0", "one\n\ntwo")
        encoded = controller.aws.calls[-1][-3]
        self.assertEqual(json.loads(encoded), {"commands": ["one", "two"]})
        controller.aws.calls.clear()
        for script in ("", "one\r\ntwo", "x" * 8193):
            with self.subTest(script_length=len(script)):
                with self.assertRaises(CONTROLLER.QualificationError):
                    controller.send_owned_shell("i-0123456789abcdef0", script)
        self.assertEqual(controller.aws.calls, [])

    def test_all_controller_ssm_parameters_avoid_aws_cli_shorthand(self):
        source = (ROOT / "qualification" / "controller.py").read_text(encoding="utf-8")
        self.assertNotIn('"commands=" +', source)
        self.assertNotIn("'commands=[", source)

    def test_every_controller_ssm_program_uses_one_exact_validated_encoder(self):
        source = (ROOT / "qualification" / "controller.py").read_text(encoding="utf-8")
        self.assertEqual(source.count('"ssm",\n                "send-command"'), 5)
        # Five dispatches plus the encoder definition itself.
        self.assertEqual(source.count("encode_ssm_shell_parameters("), 6)

        programs = (
            [
                "systemctl is-active bridgefu.service",
                "curl --fail --silent --show-error --max-time 5 "
                "http://127.0.0.1:9090/readyz",
            ],
            [
                "set -euo pipefail",
                "value='safe (value)'",
                "printf '%s\\n' \"$value\"",
            ],
            [
                "set -euo pipefail",
                "install -d -m 0700 /var/lib/bridgefu/qualification/bfq-test1234",
                "true",
            ],
        )
        for commands in programs:
            with self.subTest(commands=commands):
                encoded = CONTROLLER.encode_ssm_shell_parameters(commands)
                decoded = json.loads(encoded)
                self.assertEqual(decoded, {"commands": commands})
                checked = subprocess.run(
                    ["bash", "-n"],
                    input="\n".join(decoded["commands"]) + "\n",
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(checked.returncode, 0, checked.stderr)

        for commands in (
            [],
            [""],
            ["true\nfalse"],
            ["true\r"],
            ["x" * 8193],
            ["true"] * 1025,
            ["x" * 8192] * 8,
        ):
            with self.subTest(invalid_commands=len(commands)):
                with self.assertRaises(CONTROLLER.QualificationError):
                    CONTROLLER.encode_ssm_shell_parameters(commands)

    def test_browser_mode_has_private_readiness_and_no_session_contract(self):
        browser = ROOT / "qualification" / "browser" / "agent-workspace-playwright.mjs"
        text = browser.read_text(encoding="utf-8")
        direct = text.split("async function observeDirectSecure(options)", 1)[1].split(
            "async function observe(options)", 1
        )[0]
        self.assertNotIn("--session", direct)
        self.assertNotIn("correlation", direct.lower())
        self.assertNotIn("screen_pop", direct)
        self.assertLess(
            direct.index("exclusiveJson(readyPath"), direct.index("mediaProbe")
        )
        self.assertIn("sole_contact_auto_accepted: true", direct)
        self.assertIn("outbound_rtp_observed: true", direct)
        subprocess.run(["node", "--check", os.fspath(browser)], check=True)
        rejected = subprocess.run(
            [
                "node",
                os.fspath(browser),
                "observe-direct-secure",
                "--session",
                "super-secret-session-value",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertNotIn("super-secret-session-value", rejected.stderr)

    def test_evidence_v2_requires_preflight_and_exact_two_scenarios(self):
        base_checks = {
            "vapi_call_connected": True,
            "vapi_transfer_invoked": True,
            "handoff_context_stored": True,
            "bridgefu_received_correlation_header": True,
            "vapi_destination_uri_scheme_allowed": True,
            "vapi_destination_tls_transport": True,
            "vapi_destination_media_profile_allowed": True,
            "vapi_destination_media_posture_consistent": True,
            "vapi_destination_answered": True,
            "amazon_connect_contact_connected": True,
            "configured_screen_pop_visible": True,
            "audio_source_to_agent": True,
            "audio_agent_to_source": True,
            "dtmf_source_to_agent": True,
            "source_call_ended": True,
        }
        secure_checks = {
            name: True
            for name in (
                "sips_signaling",
                "tls_transport",
                "rtp_savp",
                "sdes_srtp",
                "srtp_contexts_installed",
                "answered",
                "inbound_200",
                "outbound_ack",
                "contact_dns",
                "contact_sips",
                "contact_tls",
                "exactly_one_correlation_header",
                "agent_available",
                "agent_sole_contact_auto_accepted",
                "agent_remote_audio",
                "agent_outbound_rtp",
                "agent_remote_hangup",
                "agent_contact_cleanup",
                "owned_ssm_commands_terminal",
                "runtime_probe_process_absent",
                "runtime_configuration_restored",
                "runtime_private_dns_verified",
                "runtime_run_artifacts_absent",
                "runtime_bridgefu_ready",
            )
        }
        evidence = {
            "schema_version": 2,
            "release": "1.2.3",
            "execution_id": "bfq-test1234",
            "region": "us-west-2",
            "started_at": "2026-08-11T04:20:00Z",
            "ended_at": "2026-08-11T04:21:00Z",
            "bridgefu_commit": "a" * 40,
            "secure_preflight": {
                "binary_sha256": "a" * 64,
                "probe_result_sha256": "b" * 64,
                "agent_observation_sha256": "c" * 64,
                "cleanup_receipt_sha256": "d" * 64,
                "checks": secure_checks,
                "passed": True,
            },
            "database_resets": {
                stage: {
                    "schema_version": 1,
                    "producer": "bridgefu-qualification-database-reset@1",
                    "stage": stage,
                    "test_delete_verified": True,
                    "prior_calls_terminal": True,
                    "fresh_database": True,
                    "bridgefu_ready": True,
                    "redacted": True,
                }
                for stage in (
                    "direct-secure-preflight",
                    "bridgefu-web-sdk-handoff",
                    "vapi-sip-transfer",
                )
            },
            "vapi_provisioning_resilience": {
                "schema_version": 1,
                "producer": "bridgefu-vapi-provisioning-resilience@1",
                "ambiguous_create_reconciled": True,
                "first_cycle_deleted": True,
                "second_cycle_recreated": True,
                "exact_owner_resources_present": True,
                "redacted": True,
                "passed": True,
            },
            "scenarios": [
                {
                    "id": "vapi-sip-transfer",
                    "source_observation_sha256": "e" * 64,
                    "agent_observation_sha256": "f" * 64,
                    "runtime_security_evidence_sha256": "0" * 64,
                    "runtime_security_media_profile": "RTP/SAVP",
                    "runtime_security_media_keying": "SDES-SRTP",
                    "runtime_security_media_suite": "AES_CM_128_HMAC_SHA1_80",
                    "runtime_security_srtp_negotiated": True,
                    "checks": dict(base_checks),
                    "passed": True,
                },
                {
                    "id": "bridgefu-web-sdk-handoff",
                    "source_observation_sha256": "1" * 64,
                    "agent_observation_sha256": "2" * 64,
                    "runtime_security_evidence_sha256": "3" * 64,
                    "runtime_security_media_profile": "RTP/AVP",
                    "runtime_security_media_keying": "none",
                    "runtime_security_media_suite": "none",
                    "runtime_security_srtp_negotiated": False,
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
                "qualification_private_dns_absent": True,
                "qualification_acm_validation_records_absent": True,
            },
            "redacted": True,
        }
        CONTROLLER.validate_schema(evidence, "evidence-v2.schema.json")
        changed = json.loads(json.dumps(evidence))
        changed["secure_preflight"]["checks"]["tls_transport"] = False
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.validate_schema(changed, "evidence-v2.schema.json")
        duplicate = json.loads(json.dumps(evidence))
        duplicate["scenarios"][1]["id"] = "vapi-sip-transfer"
        duplicate["scenarios"][1]["checks"].pop("dtmf_agent_to_source")
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.validate_schema(duplicate, "evidence-v2.schema.json")
        sip_extra = json.loads(json.dumps(evidence))
        sip_extra["scenarios"][0]["checks"]["dtmf_agent_to_source"] = True
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.validate_schema(sip_extra, "evidence-v2.schema.json")
        missing_runtime_security = json.loads(json.dumps(evidence))
        del missing_runtime_security["scenarios"][0]["checks"][
            "vapi_destination_tls_transport"
        ]
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.validate_schema(
                missing_runtime_security, "evidence-v2.schema.json"
            )
        unsupported_suite = json.loads(json.dumps(evidence))
        unsupported_suite["scenarios"][1]["runtime_security_media_suite"] = (
            "UNSUPPORTED"
        )
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.validate_schema(unsupported_suite, "evidence-v2.schema.json")


if __name__ == "__main__":
    unittest.main()
