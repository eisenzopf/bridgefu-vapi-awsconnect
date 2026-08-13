from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QUALIFICATION = ROOT / "qualification"
SPEC = importlib.util.spec_from_file_location(
    "scenario_security_controller", QUALIFICATION / "controller.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("qualification controller could not be imported")
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


def security_event(fingerprint: str, **updates: object) -> dict[str, object]:
    value: dict[str, object] = {
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
    }
    value.update(updates)
    return value


def runtime_logs(fingerprint: str, *security: dict[str, object]) -> dict[str, object]:
    invite = {
        "event": "bridgefu_sip_invite_evidence",
        "correlation_fingerprint": fingerprint,
        "header_name": "x-correlation-id",
        "header_count": 1,
    }
    events = [{"message": json.dumps(invite, separators=(",", ":"))}]
    for value in security:
        fields = {**value, "message": "accepted Vapi destination leg"}
        events.append(
            {
                "message": json.dumps(
                    {"level": "INFO", "fields": fields}, separators=(",", ":")
                )
            }
        )
    return {"events": events}


def lookup_logs(fingerprint: str) -> dict[str, object]:
    return {
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


class ScenarioSecurityAndReadinessTests(unittest.TestCase):
    def test_agent_readiness_is_exact_and_bound_to_scenario(self) -> None:
        value = {
            "schema_version": 1,
            "producer": "bridgefu-agent-workspace-playwright@1",
            "mode": "scenario-observer",
            "execution_id": "bfq-test1234",
            "scenario_id": "bridgefu-web-sdk-handoff",
            "agent_available": True,
            "redacted": True,
        }
        self.assertEqual(
            CONTROLLER.validate_agent_readiness(
                value, "bfq-test1234", "bridgefu-web-sdk-handoff"
            ),
            value,
        )
        for changed in (
            {**value, "agent_available": False},
            {**value, "scenario_id": "vapi-sip-transfer"},
            {**value, "unexpected": True},
        ):
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.validate_agent_readiness(
                    changed, "bfq-test1234", "bridgefu-web-sdk-handoff"
                )

    def test_web_source_readiness_requires_exact_call_binding(self) -> None:
        call_id = "call_1234"
        started = dt.datetime(2026, 8, 11, 4, 20, tzinfo=dt.UTC)
        value = {
            "schema_version": 1,
            "call_id": call_id,
            "source_call_fingerprint": CONTROLLER.sha256_bytes(call_id.encode("utf-8"))[
                :12
            ],
            "started_at": "2026-08-11T04:20:00.000Z",
            "started_epoch_ms": int(started.timestamp() * 1000),
        }
        self.assertEqual(CONTROLLER.validate_web_source_readiness(value), value)
        for changed in (
            {**value, "source_call_fingerprint": "0" * 12},
            {**value, "started_epoch_ms": value["started_epoch_ms"] + 1},
            {**value, "authorization": "forbidden"},
        ):
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.validate_web_source_readiness(changed)

    def test_observer_readiness_precedes_session_and_contact_wait(self) -> None:
        browser = QUALIFICATION / "browser" / "agent-workspace-playwright.mjs"
        text = browser.read_text(encoding="utf-8")
        observe = text.split("async function observe(options)", 1)[1].split(
            "async function main()", 1
        )[0]
        self.assertIn('required(options, "--ready")', observe)
        self.assertIn('required(options, "--execution-id")', observe)
        self.assertIn('required(options, "--scenario-id")', observe)
        self.assertLess(
            observe.index("exclusiveJson(readyPath"),
            observe.index("const session = validateSession(sessionPath)"),
        )
        self.assertLess(
            observe.index("const session = validateSession(sessionPath)"),
            observe.index("waitForAutoAcceptedContact"),
        )
        subprocess.run(["node", "--check", os.fspath(browser)], check=True)

    def test_controller_waits_for_connect_observer_before_each_trigger(self) -> None:
        text = (QUALIFICATION / "controller.py").read_text(encoding="utf-8")
        start_agent = text.split("    def start_agent(", 1)[1].split(
            "    def start_direct_secure_agent(", 1
        )[0]
        web = text.split("    def web_smoke(", 1)[1].split(
            "    def cleanup_sip_transients(", 1
        )[0]
        sip = text.split("    def _sip_smoke(", 1)[1].split(
            "    def verify_scenario(", 1
        )[0]
        self.assertIn("--ready", start_agent)
        self.assertLess(
            web.index("self.wait_for_agent_readiness("),
            web.index("private_json(trigger"),
        )
        self.assertLess(
            sip.index("self.wait_for_agent_readiness("), sip.index('"send-command"')
        )
        self.assertLess(
            web.index("validate_web_source_readiness"),
            web.index("private_json(trigger"),
        )

    def test_web_handoff_orders_authority_context_and_browser_trigger(self) -> None:
        text = (QUALIFICATION / "controller.py").read_text(encoding="utf-8")
        web = text.split("    def _web_smoke(", 1)[1].split(
            "    def cleanup_sip_transients(", 1
        )[0]
        ordered = (
            "self.provision_temporary_vapi_phone()",
            "self.install_direct_assistant_overlay()",
            "self.install_web_runtime(",
            "self.authorize_web_media()",
            "ensure_connect_agent_available",
            "self.wait_for_agent_readiness(",
            "self.create_direct_route(",
            "self.stage_direct_context(",
            '"bridgefu-web-playwright.mjs"',
            "validate_web_source_readiness",
            "self.wait_for_vapi_call(",
            "private_json(session_path, session)",
            "private_json(trigger",
            "self.verify_scenario(",
        )
        positions = [web.index(fragment) for fragment in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("handoff_token", web.split("private_json(session_path", 1)[1])

    def test_destination_security_proof_is_single_correlated_runtime_event(
        self,
    ) -> None:
        fingerprint = "a1b2c3d4e5f6"
        proof = CONTROLLER.verify_log_evidence(
            runtime_logs(fingerprint, security_event(fingerprint)),
            lookup_logs(fingerprint),
            fingerprint,
            "sips_optional_srtp",
        )
        for name in (
            "vapi_destination_uri_scheme_allowed",
            "vapi_destination_tls_transport",
            "vapi_destination_media_profile_allowed",
            "vapi_destination_media_posture_consistent",
            "vapi_destination_answered",
        ):
            self.assertIs(proof[name], True)
        self.assertRegex(
            proof["vapi_destination_security_evidence_sha256"], r"^[0-9a-f]{64}$"
        )
        self.assertEqual(
            proof["vapi_destination_media_suite"], "AES_CM_128_HMAC_SHA1_80"
        )
        self.assertEqual(proof["vapi_destination_media_profile"], "RTP/SAVP")
        self.assertEqual(proof["vapi_destination_media_keying"], "SDES-SRTP")
        self.assertIs(proof["vapi_destination_srtp_negotiated"], True)

        plain = CONTROLLER.verify_log_evidence(
            runtime_logs(
                fingerprint,
                security_event(
                    fingerprint,
                    media_profile="RTP/AVP",
                    media_keying="none",
                    media_suite="none",
                    inbound_srtp_context_installed=False,
                    outbound_srtp_context_installed=False,
                ),
            ),
            lookup_logs(fingerprint),
            fingerprint,
            "sips_optional_srtp",
        )
        self.assertEqual(plain["vapi_destination_media_profile"], "RTP/AVP")
        self.assertEqual(plain["vapi_destination_media_keying"], "none")
        self.assertEqual(plain["vapi_destination_media_suite"], "none")
        self.assertIs(plain["vapi_destination_srtp_negotiated"], False)

        failures = (
            runtime_logs(fingerprint),
            runtime_logs(
                fingerprint,
                security_event(fingerprint),
                security_event(fingerprint, media_suite="AES_CM_128_HMAC_SHA1_32"),
            ),
            runtime_logs(
                fingerprint,
                security_event(fingerprint, signaling_transport="tcp"),
            ),
            runtime_logs(
                fingerprint,
                security_event(fingerprint, uri_scheme="sips"),
            ),
            runtime_logs(
                fingerprint,
                security_event(fingerprint, media_profile="RTP/AVP"),
            ),
            runtime_logs(
                fingerprint,
                security_event(fingerprint, media_keying="plaintext"),
            ),
            runtime_logs(
                fingerprint,
                security_event(fingerprint, inbound_srtp_context_installed=False),
            ),
            runtime_logs(
                fingerprint,
                security_event(fingerprint, answered=False),
            ),
            runtime_logs(
                fingerprint,
                security_event(fingerprint, media_suite="UNSUPPORTED"),
            ),
            runtime_logs(
                fingerprint,
                security_event(fingerprint, correlation_id="must-not-be-accepted"),
            ),
        )
        for runtime in failures:
            with self.assertRaises(CONTROLLER.QualificationError):
                CONTROLLER.verify_log_evidence(
                    runtime,
                    lookup_logs(fingerprint),
                    fingerprint,
                    "sips_optional_srtp",
                )
        wrong_message = runtime_logs(fingerprint, security_event(fingerprint))
        wrong_message["events"][1]["message"] = wrong_message["events"][1][
            "message"
        ].replace("accepted Vapi destination leg", "unexpected tracing message")
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.verify_log_evidence(
                wrong_message,
                lookup_logs(fingerprint),
                fingerprint,
                "sips_optional_srtp",
            )

    def test_direct_preflight_event_cannot_substitute_for_scenario_security(
        self,
    ) -> None:
        fingerprint = "a1b2c3d4e5f6"
        runtime = runtime_logs(fingerprint)
        runtime["events"].append(
            {
                "message": json.dumps(
                    {
                        "event": "bridgefu_direct_secure_preflight",
                        "correlation_fingerprint": fingerprint,
                        "tls_transport": True,
                        "rtp_savp": True,
                    }
                )
            }
        )
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.verify_log_evidence(
                runtime,
                lookup_logs(fingerprint),
                fingerprint,
                "sips_optional_srtp",
            )

    def test_zero_state_contract_does_not_overclaim_unobserved_resources(self) -> None:
        controller = (QUALIFICATION / "controller.py").read_text(encoding="utf-8")
        schema = (
            QUALIFICATION / "schemas" / "zero-state-observation-v1.schema.json"
        ).read_text(encoding="utf-8")
        self.assertNotIn("preexisting_connect_resources_mutated", controller)
        self.assertNotIn("preexisting_connect_resources_mutated", schema)
        value = {
            "schema_version": 1,
            "producer": "bridgefu-vapi-awsconnect-qualification@1",
            "producer_revision_sha256": "a" * 64,
            "execution_id": "bfq-test1234",
            "observed_at": "2026-08-11T04:20:00Z",
            "customer_stack_absent": True,
            "connect_instance_absent": True,
            "temporary_vapi_resources_absent": True,
            "test_credentials_absent": True,
            "qualification_objects_absent": True,
            "qualification_private_dns_absent": True,
            "qualification_acm_validation_records_absent": True,
            "redacted": True,
        }
        CONTROLLER.validate_schema(value, "zero-state-observation-v1.schema.json")
        with self.assertRaises(CONTROLLER.QualificationError):
            CONTROLLER.validate_schema(
                {**value, "preexisting_connect_resources_mutated": False},
                "zero-state-observation-v1.schema.json",
            )


if __name__ == "__main__":
    unittest.main()
