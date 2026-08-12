from __future__ import annotations

import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from qualification.diagnostics import capture_vapi_sdp as CAPTURE


def valid_summary() -> dict:
    return {
        "schema_version": 2,
        "producer": "bridgefu-sdp-observer@2",
        "wire": {
            "tls_handshake": "accepted",
            "decrypted_payload_present": True,
            "framing": "complete",
            "rvoip_sip_parse": "accepted",
            "message_kind": "request",
            "method": "INVITE",
            "request_uri_scheme": "sips",
            "header_count": 10,
            "via_count": 1,
            "contact_count": 1,
            "content_type_count": 1,
            "content_length_count": 1,
            "correlation_header_count": 1,
            "content_type": "application/sdp",
            "body_present": True,
            "rvoip_sdp_parse": "accepted",
        },
        "sdp_present": True,
        "media": [
            {
                "kind": "audio",
                "transport": "RTP/SAVP",
                "payload_types": [0, 101],
                "codecs": [
                    {"payload_type": 0, "name": "PCMU"},
                    {"payload_type": 101, "name": "telephone-event"},
                ],
            }
        ],
        "sdes": {
            "crypto_line_count": 1,
            "suites": ["AES_CM_128_HMAC_SHA1_80"],
            "unrecognized_suite_count": 0,
        },
        "dtls": {
            "fingerprint_present": False,
            "fingerprint_line_count": 0,
            "fingerprint_algorithms": [],
            "unrecognized_fingerprint_algorithm_count": 0,
            "setup_values": [],
            "unrecognized_setup_value_count": 0,
        },
        "redacted": True,
    }


def arguments(output: Path) -> SimpleNamespace:
    return SimpleNamespace(
        profile="qualification-admin",
        region="us-west-2",
        stack="bridgefu-bfq-test1234",
        execution="bfq-test1234",
        observer_path="/usr/local/bin/bridgefu-sdp-observer",
        sip_client="/usr/local/bin/bridgefu-vapi-sip-smoke",
        prompt="/var/lib/bridgefu/qualification/prompt.pcm",
        vapi_secret_arn=(  # noqa: S106 - this is a non-secret ARN
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:vapi-test"
        ),
        output=output,
    )


class Runner:
    def run(self, arguments, **kwargs):
        return ""

    def probe(self, arguments, **kwargs):
        return 0, "", ""


class Harness(CAPTURE.SdpCapture):
    def __init__(self, args, failure: str | None = None):
        super().__init__(args, Runner())
        self.failure = failure
        self.remote_calls = 0
        self.sent_scripts: list[str] = []
        self.cleanup_attempts: list[str] = []

    def discover_target(self):
        return CAPTURE.Target(
            "i-0123456789abcdef0",
            "assistant_1234",
            "bridgefu-artifacts-test",
            ("192.0.2.10/32", "192.0.2.11/32"),
        )

    def connect_vapi(self, target):
        return object()

    def prepare_phone(self, target):
        self.phone_id = "phone_1234"
        return (
            {
                "realm": "sip.vapi.ai",
                "username": "bfq_0123456789abcdef",
                "password": "do-not-retain-password",
            },
            "sip:bfq_0123456789abcdef@sip.vapi.ai",
        )

    def upload_auth(self, target, authentication):
        self.auth_object = self.object_uri(target)

    def remote_cleanup(self, target):
        self.remote_calls += 1
        values = {
            "redirect_rules_absent": True,
            "observer_process_absent": True,
            "source_process_absent": True,
            "bridgefu_active": True,
        }
        if self.remote_calls > 1 and self.failure in values:
            values[self.failure] = False
        return values

    def send_shell(self, target, script):
        self.sent_scripts.append(script)
        return f"12345678-1234-1234-1234-{len(self.sent_scripts):012d}"

    def invocation(self, target, command_id, timeout):
        return {
            "Status": "Success",
            "StandardOutputContent": json.dumps(valid_summary()),
        }

    def cancel_command(self, target, command_id):
        self.cleanup_attempts.append("cancel")
        return self.failure != "ssm_commands_cancelled"

    def delete_phone(self):
        self.cleanup_attempts.append("phone")
        if self.failure == "temporary_vapi_endpoint_absent":
            return False
        self.phone_id = None
        return True

    def delete_auth(self):
        self.cleanup_attempts.append("auth")
        if self.failure == "temporary_auth_object_absent":
            return False
        self.auth_object = None
        return True


class SdpCaptureDiagnosticTests(unittest.TestCase):
    def test_ssm_shell_document_uses_one_real_command_entry_per_line(self):
        class Aws:
            def text(self, arguments, timeout=900):
                self.arguments = arguments
                return "12345678-1234-1234-1234-123456789012"

        capture = CAPTURE.SdpCapture(arguments(Path("unused")), Runner())
        capture.aws = Aws()
        target = Harness(arguments(Path("unused"))).discover_target()
        capture.send_shell(target, "set -euo pipefail\nprintf 'ready\\n'\ntrue")
        parameter = capture.aws.arguments[
            capture.aws.arguments.index("--parameters") + 1
        ]
        commands = json.loads(parameter.removeprefix("commands="))
        self.assertEqual(commands, ["set -euo pipefail", "printf 'ready\\n'", "true"])
        self.assertTrue(all("\n" not in command for command in commands))
        with self.assertRaises(CAPTURE.DiagnosticError):
            capture.send_shell(target, "set -e\n\ntrue")

    def test_happy_path_writes_only_private_redacted_summary_and_receipt(self):
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent) / "evidence"
            capture = Harness(arguments(output))
            capture.run()
            self.assertEqual(
                {item.name for item in output.iterdir()},
                {"sdp-summary.json", "cleanup-receipt.json"},
            )
            for path in output.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                retained = path.read_text(encoding="utf-8")
                for forbidden in (
                    "do-not-retain-password",
                    "sip:bfq_",
                    "192.0.2.",
                    "X-Correlation-Id",
                ):
                    self.assertNotIn(forbidden, retained)
            receipt = json.loads((output / "cleanup-receipt.json").read_text())
            self.assertTrue(receipt["passed"])
            self.assertEqual(capture.cleanup_attempts.count("cancel"), 2)
            self.assertIn("phone", capture.cleanup_attempts)
            self.assertIn("auth", capture.cleanup_attempts)

    def test_every_cleanup_failure_is_retained_and_fails_closed(self):
        fields = (
            "ssm_commands_cancelled",
            "redirect_rules_absent",
            "observer_process_absent",
            "source_process_absent",
            "bridgefu_active",
            "temporary_vapi_endpoint_absent",
            "temporary_auth_object_absent",
        )
        for field in fields:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as parent:
                output = Path(parent) / "evidence"
                capture = Harness(arguments(output), field)
                with self.assertRaises(CAPTURE.DiagnosticError):
                    capture.run()
                receipt = json.loads(
                    (output / "cleanup-receipt.json").read_text(encoding="utf-8")
                )
                self.assertFalse(receipt[field])
                self.assertFalse(receipt["passed"])
                self.assertTrue((output / "sdp-summary.json").is_file())
                self.assertIn("phone", capture.cleanup_attempts)
                self.assertIn("auth", capture.cleanup_attempts)

    def test_summary_validator_rejects_open_vocabulary_and_extra_fields(self):
        CAPTURE.validate_sdp_summary(valid_summary())
        for mutation in ("transport", "codec", "suite", "extra"):
            with self.subTest(mutation=mutation):
                value = valid_summary()
                if mutation == "transport":
                    value["media"][0]["transport"] = "RTP/SAVP 192.0.2.1"
                elif mutation == "codec":
                    value["media"][0]["codecs"][0]["name"] = "customer-secret"
                elif mutation == "suite":
                    value["sdes"]["suites"] = ["inline:key-material"]
                else:
                    value["remote_body"] = "secret"
                with self.assertRaises(CAPTURE.DiagnosticError):
                    CAPTURE.validate_sdp_summary(value)

    def test_scripts_are_exact_source_bounded_and_contain_guaranteed_cleanup(self):
        capture = Harness(arguments(Path("unused")))
        target = capture.discover_target()
        observer = capture.observer_script(target)
        source = capture.source_script(target)
        cleanup = capture.remote_cleanup_script(target)
        for cidr in target.signaling_cidrs:
            self.assertIn(f"-s {cidr}", observer)
            self.assertIn(f"-s {cidr}", source)
            self.assertIn(f"-s {cidr}", cleanup)
        self.assertEqual(observer.count("iptables -t nat -I PREROUTING"), 2)
        self.assertNotIn("0.0.0.0/0", observer)
        self.assertIn("command -v iptables", observer)
        self.assertIn("trap cleanup EXIT INT TERM", observer)
        self.assertIn("sport = :15061", observer)
        self.assertIn("--to-ports 15061", observer)
        self.assertIn("--dport 5061", observer)
        self.assertNotIn("rm -rf", cleanup)
        self.assertIn('rmdir "$run"', cleanup)
        self.assertNotIn("do-not-retain-password", source)
        self.assertNotIn("sip:bfq_0123456789abcdef", source)
        for label, script in (
            ("observer", observer),
            ("source", source),
            ("cleanup", cleanup),
        ):
            with self.subTest(shell_syntax=label):
                checked = subprocess.run(
                    ["bash", "-n"],
                    input=script,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_signaling_sources_must_be_exactly_two_distinct_ipv4_hosts(self):
        valid = {
            "VapiSignalingCidr1": "192.0.2.10/32",
            "VapiSignalingCidr2": "192.0.2.11/32",
        }
        self.assertEqual(
            CAPTURE.exact_signaling_cidrs(valid),
            ("192.0.2.10/32", "192.0.2.11/32"),
        )
        for changed in (
            {**valid, "VapiSignalingCidr1": "192.0.2.0/24"},
            {**valid, "VapiSignalingCidr2": "192.0.2.10/32"},
            {**valid, "VapiSignalingCidr3": "192.0.2.12/32"},
            {**valid, "VapiSignalingCidr2": "2001:db8::1/128"},
        ):
            with self.assertRaises(CAPTURE.DiagnosticError):
                CAPTURE.exact_signaling_cidrs(changed)

    def test_retained_target_discovery_validates_stack_instance_and_test_mode(self):
        root = "bridgefu-bfq-test1234"
        candidate_name = "bridgefu-bfq-test1234-candidate"
        runtime_name = "bridgefu-bfq-test1234-runtime"
        candidate = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            f"stack/{candidate_name}/12345678-1234-1234-1234-123456789012"
        )
        runtime = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            f"stack/{runtime_name}/12345678-1234-1234-1234-123456789013"
        )

        class Aws:
            region = "us-west-2"

            def __init__(self, retention="TestDelete"):
                self.retention = retention

            def json(self, arguments, timeout=900):
                if arguments[0:2] == ["cloudformation", "describe-stacks"]:
                    name = arguments[arguments.index("--stack-name") + 1]
                    if name == root:
                        return {
                            "Stacks": [
                                {
                                    "StackName": root,
                                    "StackStatus": "CREATE_COMPLETE",
                                    "Outputs": [
                                        {
                                            "OutputKey": "BridgefuInstanceId",
                                            "OutputValue": "i-0123456789abcdef0",
                                        },
                                        {
                                            "OutputKey": "VapiAssistantId",
                                            "OutputValue": "assistant_1234",
                                        },
                                        {
                                            "OutputKey": "ArtifactBucket",
                                            "OutputValue": "bridgefu-artifacts-test",
                                        },
                                    ],
                                }
                            ]
                        }
                    if name == candidate:
                        return {
                            "Stacks": [
                                {
                                    "StackName": candidate_name,
                                    "StackStatus": "CREATE_COMPLETE",
                                    "Parameters": [
                                        {
                                            "ParameterKey": "DataRetentionMode",
                                            "ParameterValue": self.retention,
                                        },
                                        {
                                            "ParameterKey": "DeploymentId",
                                            "ParameterValue": "bfq-test1234",
                                        },
                                    ],
                                }
                            ]
                        }
                    return {
                        "Stacks": [
                            {
                                "StackName": runtime_name,
                                "StackStatus": "CREATE_COMPLETE",
                                "Parameters": [
                                    {
                                        "ParameterKey": "DataRetentionMode",
                                        "ParameterValue": "TestDelete",
                                    },
                                    {
                                        "ParameterKey": "VapiSignalingCidr1",
                                        "ParameterValue": "192.0.2.10/32",
                                    },
                                    {
                                        "ParameterKey": "VapiSignalingCidr2",
                                        "ParameterValue": "192.0.2.11/32",
                                    },
                                ],
                            }
                        ]
                    }
                if arguments[0:2] == [
                    "cloudformation",
                    "list-stack-resources",
                ]:
                    parent = arguments[arguments.index("--stack-name") + 1]
                    if parent == root:
                        logical = "Candidate"
                        resource_type = "AWS::CloudFormation::Stack"
                        physical = candidate
                    elif parent == candidate:
                        logical = "Runtime"
                        resource_type = "AWS::CloudFormation::Stack"
                        physical = runtime
                    else:
                        logical = "GatewayInstance"
                        resource_type = "AWS::EC2::Instance"
                        physical = "i-0123456789abcdef0"
                    return {
                        "StackResourceSummaries": [
                            {
                                "LogicalResourceId": logical,
                                "ResourceType": resource_type,
                                "ResourceStatus": "CREATE_COMPLETE",
                                "PhysicalResourceId": physical,
                            }
                        ]
                    }
                if arguments[0:2] == ["ec2", "describe-instances"]:
                    return {
                        "Reservations": [
                            {
                                "Instances": [
                                    {
                                        "InstanceId": "i-0123456789abcdef0",
                                        "State": {"Name": "running"},
                                        "Tags": [
                                            {
                                                "Key": "Project",
                                                "Value": "bridgefu-vapi-awsconnect",
                                            },
                                            {
                                                "Key": "ManagedBy",
                                                "Value": "bridgefu-cloudformation",
                                            },
                                            {
                                                "Key": "BridgefuExecutionId",
                                                "Value": "bfq-test1234",
                                            },
                                        ],
                                    }
                                ]
                            }
                        ]
                    }
                raise AssertionError(arguments)

        capture = CAPTURE.SdpCapture(arguments(Path("unused")), Runner())
        capture.aws = Aws()
        target = capture.discover_target()
        self.assertEqual(target.instance_id, "i-0123456789abcdef0")
        self.assertEqual(target.assistant_id, "assistant_1234")
        capture.aws = Aws(retention="ProductionRetain")
        with self.assertRaisesRegex(CAPTURE.DiagnosticError, "TestDelete"):
            capture.discover_target()

    def test_cancel_is_successful_only_after_terminal_ssm_state(self):
        capture = CAPTURE.SdpCapture(arguments(Path("unused")), Runner())
        target = CAPTURE.Target(
            "i-0123456789abcdef0",
            "assistant_1234",
            "bridgefu-artifacts-test",
            ("192.0.2.10/32", "192.0.2.11/32"),
        )
        capture.aws = mock.Mock()
        capture.aws.json.return_value = {"Status": "InProgress"}
        capture.aws.text.return_value = ""
        capture.invocation = mock.Mock(return_value={"Status": "Cancelled"})
        self.assertTrue(
            capture.cancel_command(target, "12345678-1234-1234-1234-123456789012")
        )
        capture.invocation.assert_called_once()
        capture.invocation.return_value = {"Status": "InProgress"}
        self.assertFalse(
            capture.cancel_command(target, "12345678-1234-1234-1234-123456789013")
        )

    def test_auth_cleanup_purges_every_version_of_only_the_exact_key(self):
        capture = CAPTURE.SdpCapture(arguments(Path("unused")), Runner())
        capture.target = CAPTURE.Target(
            "i-0123456789abcdef0",
            "assistant_1234",
            "bridgefu-artifacts-test",
            ("192.0.2.10/32", "192.0.2.11/32"),
        )
        capture.auth_object = capture.object_uri(capture.target)
        with mock.patch.object(CAPTURE, "purge_object_versions_exact") as purge:
            self.assertTrue(capture.delete_auth())
        purge.assert_called_once_with(
            capture.aws,
            "bridgefu-artifacts-test",
            "qualification/bfq-test1234/diagnostics/sip-auth.json",
            exact_key=True,
        )
        self.assertIsNone(capture.auth_object)


if __name__ == "__main__":
    unittest.main()
