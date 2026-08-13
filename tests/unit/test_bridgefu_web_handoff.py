from __future__ import annotations

import copy
import unittest

from qualification import bridgefu_web_handoff as HANDOFF


def route_response() -> dict:
    token = "A" * 43
    expires = "2026-08-13T23:00:00Z"
    return {
        "call_id": "call_1234",
        "tenant_id": "support",
        "state": "pending",
        "legs": [
            {
                "leg_id": "source_1234",
                "direction": "inbound",
                "kind": "web_rtc",
            },
            {
                "leg_id": "destination_1234",
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
                "token": token,
                "expires_at": expires,
            },
            "subprotocols": [
                "rvoip.webrtc.v1",
                f"token.{token}",
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
        self.assertEqual(binding.call_id, "call_1234")
        self.assertEqual(binding.source_leg_id, "source_1234")
        self.assertEqual(binding.destination_leg_id, "destination_1234")
        browser = binding.browser_input()
        self.assertEqual(browser["route_binding"]["callId"], "call_1234")
        self.assertNotIn("destination_1234", str(browser))
        self.assertNotIn("vapi-direct-assistant", str(browser))
        for mutation in (
            lambda value: value["legs"].append(value["legs"][0]),
            lambda value: value["attachment"].update(type="sip"),
            lambda value: value["attachment"]["subprotocols"].reverse(),
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

    def test_overlay_round_trip_preserves_every_unowned_assistant_property(self):
        assistant = {
            "id": "assistant_1234",
            "name": "Bridgefu",
            "model": {
                "provider": "openai",
                "messages": [{"role": "system", "content": "original"}],
                "toolIds": ["existing_1234"],
                "temperature": 0.2,
            },
            "voice": {"provider": "vapi", "voiceId": "Elliot"},
            "metadata": {"owner": "customer"},
            "server": {"url": "https://existing.example.test"},
        }
        overlaid, prompt_hash = HANDOFF.apply_assistant_overlay(
            assistant, "direct_tool_1234"
        )
        self.assertEqual(assistant["model"]["toolIds"], ["existing_1234"])
        self.assertEqual(
            overlaid["model"]["toolIds"], ["existing_1234", "direct_tool_1234"]
        )
        restored = HANDOFF.remove_assistant_overlay(
            overlaid, "direct_tool_1234", prompt_hash
        )
        self.assertEqual(restored, assistant)
        foreign = copy.deepcopy(overlaid)
        foreign["model"]["messages"][-1]["content"] += " changed"
        with self.assertRaises(HANDOFF.DirectHandoffContractError):
            HANDOFF.remove_assistant_overlay(foreign, "direct_tool_1234", prompt_hash)


if __name__ == "__main__":
    unittest.main()
