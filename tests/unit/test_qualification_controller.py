from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "qualification_controller", ROOT / "qualification" / "controller.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("qualification controller could not be imported")
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


class QualificationControllerTests(unittest.TestCase):
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
            scenario="vapi-web-transfer",
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
        self.assertEqual(len(session), 24)
        self.assertEqual(session["expected_context"]["intent"], "qualification")
        self.assertEqual(session["hangup_origin"], "source")
        self.assertRegex(session["session_hmac"], r"^[0-9a-f]{64}$")

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
        CONTROLLER.verify_log_evidence(runtime, lookup, fingerprint)
        runtime["events"][0]["message"] = runtime["events"][0]["message"].replace(
            '"header_count": 1', '"header_count": 2'
        )
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.verify_log_evidence(runtime, lookup, fingerprint)

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
                    }
                }
            )
        )
        self.assertFalse(
            CONTROLLER.call_contains_transfer({"artifact": {"messages": []}})
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
