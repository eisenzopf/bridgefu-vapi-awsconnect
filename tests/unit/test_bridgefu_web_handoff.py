from __future__ import annotations

import copy
import unittest

from qualification import bridgefu_web_handoff as HANDOFF


def route_response() -> dict:
    token = "A" * 43
    signaling_token = "bfs1.header.payload.signature"  # noqa: S105 -- synthetic
    expires = "2026-08-13T23:00:00Z"
    return {
        "call_id": "018f9c2a-7b3d-7ef0-bfee-9d5a5c600001",
        "tenant_id": "support",
        "state": "pending",
        "legs": [
            {
                "leg_id": "018f9c2a-7b3d-7ef0-bfee-9d5a5c600002",
                "direction": "inbound",
                "kind": "webrtc",
            },
            {
                "leg_id": "018f9c2a-7b3d-7ef0-bfee-9d5a5c600003",
                "direction": "outbound",
                "kind": "sip",
            },
        ],
        "route_id": "vapi-direct-assistant",
        "attachment": {
            "type": "webrtc",
            "signaling_uri": "wss://control.example.test/webrtc",
            "token": token,
            "signaling_credential": {
                "usage": "bridgefu-webrtc-signaling",
                "token": signaling_token,
                "expires_at": expires,
            },
            "subprotocols": [
                "rvoip.webrtc.v1",
                f"token.{signaling_token}",
                f"bridgefu.attach.{token}",
            ],
            "ice_servers": [],
            "expires_at": expires,
        },
    }


class BridgefuWebHandoffTests(unittest.TestCase):
    def test_signed_token_has_no_call_leg_route_or_endpoint_and_tampering_fails(self):
        token = HANDOFF.issue_handoff_token(
            "k" * 32,
            "session_1234",
            "token_1234",
            issued_at=2_000_000_000,
            lifetime_seconds=3600,
        )
        for forbidden in (
            "call_1234",
            "leg_1234",
            "amazon-connect",
            "sip:",
            "wss:",
        ):
            self.assertNotIn(forbidden, token)
        self.assertEqual(
            HANDOFF.verify_handoff_token(token, "k" * 32, now=2_000_000_100),
            ("session_1234", "token_1234"),
        )
        changed = token[:-1] + ("A" if token[-1] != "A" else "B")
        with self.assertRaises(HANDOFF.DirectHandoffContractError):
            HANDOFF.verify_handoff_token(changed, "k" * 32, now=2_000_000_100)

    def test_route_request_contains_only_server_owned_context(self):
        token = HANDOFF.issue_handoff_token(
            "k" * 32,
            "session_1234",
            "token_1234",
            issued_at=2_000_000_000,
        )
        correlation = "bf1_" + "A" * 43
        self.assertEqual(
            HANDOFF.route_request(correlation, token),
            {
                "ingress": "webrtc",
                "context": {
                    "correlation_id": correlation,
                    "metadata": {"handoff_token": token},
                },
            },
        )

    def test_route_response_binds_one_browser_leg_and_one_vapi_leg(self):
        binding = HANDOFF.parse_route_response(
            route_response(), "vapi-direct-assistant"
        )
        self.assertEqual(binding.call_id, "018f9c2a-7b3d-7ef0-bfee-9d5a5c600001")
        self.assertEqual(binding.source_leg_id, "018f9c2a-7b3d-7ef0-bfee-9d5a5c600002")
        self.assertEqual(
            binding.destination_leg_id, "018f9c2a-7b3d-7ef0-bfee-9d5a5c600003"
        )
        browser = binding.browser_input()
        self.assertEqual(
            browser["route_binding"]["callId"],
            "018f9c2a-7b3d-7ef0-bfee-9d5a5c600001",
        )
        self.assertNotIn("018f9c2a-7b3d-7ef0-bfee-9d5a5c600003", str(browser))
        self.assertNotIn("vapi-direct-assistant", str(browser))
        self.assertNotEqual(
            browser["route_attachment"]["token"],
            browser["route_attachment"]["signaling_credential"]["token"],
        )
        for mutation in (
            lambda value: value["legs"].append(value["legs"][0]),
            lambda value: value["attachment"].update(type="sip"),
            lambda value: value["attachment"]["subprotocols"].reverse(),
            lambda value: value["attachment"]["signaling_credential"].update(
                token=value["attachment"]["token"]
            ),
            lambda value: value.update(route_id="amazon-connect"),
        ):
            changed = copy.deepcopy(route_response())
            mutation(changed)
            with self.assertRaises(HANDOFF.DirectHandoffContractError):
                HANDOFF.parse_route_response(changed, "vapi-direct-assistant")

    def test_tool_token_is_static_and_absent_from_model_schema(self):
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["customer_name"],
            "properties": {"customer_name": {"type": "string", "maxLength": 256}},
        }
        tool = HANDOFF.direct_tool_payload(
            endpoint_url="https://api.example.test/v1/direct-handoff",
            credential_id="credential_1234",
            field_schema=schema,
            execution_id="bfq_test1234",
        )
        self.assertEqual(tool["function"]["name"], "bridgefu_direct_handoff")
        self.assertNotIn("handoff_token", tool["function"]["parameters"]["properties"])
        self.assertEqual(
            tool["parameters"],
            [{"key": "handoff_token", "value": "{{ bridgefu_handoff_token }}"}],
        )
        self.assertNotIn("metadata", tool)
        self.assertTrue(
            HANDOFF.direct_tool_owned(
                tool,
                execution_id="bfq_test1234",
                endpoint_url="https://api.example.test/v1/direct-handoff",
                credential_id="credential_1234",
            )
        )
        foreign = copy.deepcopy(tool)
        foreign["server"]["credentialId"] = "credential_foreign"
        self.assertFalse(
            HANDOFF.direct_tool_owned(
                foreign,
                execution_id="bfq_test1234",
                endpoint_url="https://api.example.test/v1/direct-handoff",
                credential_id="credential_1234",
            )
        )

    def test_direct_assistant_has_one_exclusive_tool_and_no_server_surface(self):
        assistant, prompt_hash = HANDOFF.direct_assistant_payload(
            execution_id="bfq-test1234",
            tool_id="direct_tool_1234",
            model_name="gpt-4.1",
            voice_id="Elliot",
        )
        self.assertEqual(assistant["model"]["toolIds"], ["direct_tool_1234"])
        self.assertEqual(len(assistant["model"]["messages"]), 1)
        self.assertNotIn("tools", assistant["model"])
        self.assertNotIn("server", assistant)
        self.assertNotIn("serverMessages", assistant)
        self.assertNotIn("credentialIds", assistant)
        self.assertEqual(assistant["maxDurationSeconds"], 300)
        self.assertTrue(
            HANDOFF.direct_assistant_owned(
                assistant,
                execution_id="bfq-test1234",
                tool_id="direct_tool_1234",
                prompt_sha256=prompt_hash,
                model_name="gpt-4.1",
                voice_id="Elliot",
            )
        )
        normalized = copy.deepcopy(assistant)
        normalized["model"]["tools"] = []
        normalized["server"] = None
        normalized["serverMessages"] = []
        normalized["credentialIds"] = None
        normalized["latestVersion"] = "2"
        normalized["isServerUrlSecretSet"] = False
        normalized["analysisPlan"] = {
            "summaryPlan": {"enabled": False},
            "successEvaluationPlan": {"enabled": False},
        }
        normalized["voice"]["fallbackPlan"] = {}
        normalized["transcriber"]["smartFormat"] = True
        normalized["transcriber"]["fallbackPlan"] = {"autoFallback": {"enabled": True}}
        normalized["artifactPlan"]["loggingEnabled"] = False
        self.assertTrue(
            HANDOFF.direct_assistant_owned(
                normalized,
                execution_id="bfq-test1234",
                tool_id="direct_tool_1234",
                prompt_sha256=prompt_hash,
                model_name="gpt-4.1",
                voice_id="Elliot",
            )
        )
        foreign = copy.deepcopy(assistant)
        foreign["model"]["tools"] = [{"type": "transferCall"}]
        self.assertFalse(
            HANDOFF.direct_assistant_owned(
                foreign,
                execution_id="bfq-test1234",
                tool_id="direct_tool_1234",
                prompt_sha256=prompt_hash,
                model_name="gpt-4.1",
                voice_id="Elliot",
            )
        )
        for path, injected in (
            (("hooks",), [{"type": "customer"}]),
            (("serverUrl",), "https://foreign.example.test"),
            (("model", "knowledgeBaseId"), "foreign_knowledge"),
        ):
            changed = copy.deepcopy(assistant)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = injected
            self.assertFalse(
                HANDOFF.direct_assistant_owned(
                    changed,
                    execution_id="bfq-test1234",
                    tool_id="direct_tool_1234",
                    prompt_sha256=prompt_hash,
                    model_name="gpt-4.1",
                    voice_id="Elliot",
                )
            )


if __name__ == "__main__":
    unittest.main()
