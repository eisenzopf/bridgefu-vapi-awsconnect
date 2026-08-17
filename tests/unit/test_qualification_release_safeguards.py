from __future__ import annotations

import datetime as dt
import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "qualification_release_safeguards_controller",
    ROOT / "qualification" / "controller.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("qualification controller could not be imported")
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


class QualificationReleaseSafeguardTests(unittest.TestCase):
    def controller(self):
        value = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        value.args = SimpleNamespace(
            execution_id="bfq-test-1234",
            region="us-west-2",
            expected_account_id="123456789012",
        )
        return value

    def test_stale_connect_child_tag_is_absent_when_parent_is_absent(self) -> None:
        controller = self.controller()

        class Aws:
            @staticmethod
            def exists(command):
                self.assertEqual(
                    command,
                    [
                        "connect",
                        "describe-instance",
                        "--instance-id",
                        "instance-1234",
                    ],
                )
                return False

        controller.aws = Aws()
        category, live = controller._tagged_resource_is_live(
            "arn:aws:connect:us-west-2:123456789012:"
            "instance/instance-1234/contact-flow/flow-5678"
        )

        self.assertEqual(category, "connect_resources")
        self.assertFalse(live)

    def test_unknown_tagged_service_fails_closed(self) -> None:
        controller = self.controller()
        controller.aws = object()

        with self.assertRaisesRegex(
            CONTROLLER.QualificationError, "cannot be verified exactly"
        ):
            controller._tagged_resource_is_live(
                "arn:aws:mystery:us-west-2:123456789012:resource/unknown"
            )

    def test_tagged_ec2_instance_uses_nested_instance_identity_and_tombstone(
        self,
    ) -> None:
        controller = self.controller()

        class Aws:
            def __init__(self, state):
                self.state = state

            def json(self, command, timeout=120):
                del timeout
                self_command = [
                    "ec2",
                    "describe-instances",
                    "--filters",
                    "Name=instance-id,Values=i-0123456789abcdef0",
                ]
                self_test.assertEqual(command, self_command)
                return {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-0123456789abcdef0",
                                    "State": {"Name": self.state},
                                }
                            ]
                        }
                    ]
                }

        self_test = self
        arn = "arn:aws:ec2:us-west-2:123456789012:instance/i-0123456789abcdef0"
        controller.aws = Aws("running")
        self.assertEqual(
            controller._tagged_resource_is_live(arn), ("ec2_instances", True)
        )
        controller.aws = Aws("terminated")
        self.assertEqual(
            controller._tagged_resource_is_live(arn), ("ec2_instances", False)
        )

    def test_deleted_nat_gateway_tombstone_is_not_a_live_resource(self) -> None:
        controller = self.controller()

        class Aws:
            @staticmethod
            def json(command, timeout=120):
                del timeout
                self.assertEqual(
                    command,
                    [
                        "ec2",
                        "describe-nat-gateways",
                        "--filters",
                        "Name=nat-gateway-id,Values=nat-0123456789abcdef0",
                    ],
                )
                return {
                    "NatGateways": [
                        {
                            "NatGatewayId": "nat-0123456789abcdef0",
                            "State": "deleted",
                        }
                    ]
                }

        controller.aws = Aws()
        present = controller._ec2_present_ids(
            "describe-nat-gateways",
            "NatGateways",
            "NatGatewayId",
            "nat-gateway-id",
            ["nat-0123456789abcdef0"],
            state_key="State",
            absent_states=frozenset({"deleted"}),
        )

        self.assertEqual(present, set())

    def test_late_vapi_reappearance_is_found_after_direct_ids_are_cleared(self) -> None:
        controller = self.controller()
        stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/bridgefu-product-Vapi-ABC/01234567-89ab-cdef-0123-456789abcdef"
        )
        controller.outputs = {
            "VapiPrepareUrl": "https://prepare.example.test/v1/prepare",
            "DirectHandoffUrl": "https://direct.example.test/v1/handoff",
        }
        controller.owned_resource_inventory = {
            "stack_logical_ids": {stack_id: "VapiResources"}
        }
        controller.direct_assistant_id = None
        controller.direct_tool_id = None

        class Vapi:
            @staticmethod
            def list(resource_type, limit=100):
                self.assertEqual(limit, 100)
                if resource_type == "assistant":
                    return [
                        {
                            "id": "assistant_late1234",
                            "name": "late visible resource",
                            "metadata": {"bridgefu_deployment": "bfq-test-1234"},
                            "credentialIds": ["credential_late1234"],
                            "model": {"toolIds": ["tool_late1234"]},
                        }
                    ]
                if resource_type == "credential":
                    return [
                        {
                            "id": "credential_late1234",
                            "name": "late visible resource",
                        }
                    ]
                if resource_type == "tool":
                    return [
                        {
                            "id": "tool_late1234",
                            "type": "function",
                            "function": {"name": "prepare_handoff"},
                            "server": {"credentialId": "credential_late1234"},
                        }
                    ]
                if resource_type == "phone-number":
                    return []
                raise AssertionError(resource_type)

        controller.vapi = Vapi()
        fingerprints = controller._related_vapi_resource_fingerprints()

        self.assertEqual(len(fingerprints), 3)

    def test_active_call_window_uses_session_start_through_terminal_hangup(
        self,
    ) -> None:
        base = int(dt.datetime(2026, 8, 16, 20, 0, tzinfo=dt.UTC).timestamp() * 1_000)
        session = {"started_epoch_ms": base}
        source = {
            "observed_at": "2026-08-16T20:00:50Z",
            "hangup": {"local_bye_completed": True, "cleanup_observed": True},
            "media": {
                "source_marker_sent_at_ms": [base + 5_000, base + 45_000],
                "agent_marker_observed_at_ms": [base + 42_000],
                "dtmf_source_to_agent_sent_at_ms": [base + 35_000],
            },
        }
        agent = {
            "observed_at": "2026-08-16T20:00:51Z",
            "hangup": {
                "local_end_completed": False,
                "remote_end_observed": True,
                "cleanup_observed": True,
            },
            "media": {
                "source_marker_observed_at_ms": [base + 20_000],
                "agent_marker_sent_at_ms": [base + 25_000, base + 40_000],
                "dtmf_agent_to_source_sent_at_ms": [base + 37_000],
            },
        }

        started, ended = CONTROLLER.established_call_window(source, agent, session)

        self.assertEqual(started, dt.datetime(2026, 8, 16, 20, 0, tzinfo=dt.UTC))
        self.assertEqual(ended, dt.datetime(2026, 8, 16, 20, 0, 51, tzinfo=dt.UTC))

    def test_active_call_window_requires_terminal_cleanup(self) -> None:
        base = int(dt.datetime(2026, 8, 16, 20, 0, tzinfo=dt.UTC).timestamp() * 1_000)
        source = {
            "observed_at": "2026-08-16T20:00:30Z",
            "media": {"source_marker_sent_at_ms": [base + 10_000]},
            "hangup": {"local_bye_completed": True, "cleanup_observed": False},
        }
        agent = {
            "observed_at": "2026-08-16T20:00:31Z",
            "media": {"agent_marker_sent_at_ms": [base + 20_000]},
            "hangup": {
                "local_end_completed": False,
                "remote_end_observed": True,
                "cleanup_observed": True,
            },
        }

        with self.assertRaisesRegex(
            CONTROLLER.QualificationError, "telemetry window is invalid"
        ):
            CONTROLLER.established_call_window(
                source, agent, {"started_epoch_ms": base}
            )


if __name__ == "__main__":
    unittest.main()
