from __future__ import annotations

import json
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONNECT_TEMPLATE = ROOT / "cloudformation" / "nested" / "connect.yaml"


def wrapper_source() -> str:
    text = CONNECT_TEMPLATE.read_text()
    resource = text.split("  WrapperEntryFlow:\n", 1)[1]
    block = resource.split("      Content: !Sub |\n", 1)[1].split(
        "\n      Tags:\n", 1
    )[0]
    return textwrap.dedent(block)


def guide_source() -> str:
    text = CONNECT_TEMPLATE.read_text()
    resource = text.split("  AgentGuideFlow:\n", 1)[1]
    block = resource.split("      Content: !Sub |\n", 1)[1].split(
        "\n      Tags:\n", 1
    )[0]
    return textwrap.dedent(block)


def render_guide(agent_guide_template: str) -> dict:
    content = guide_source().replace(
        "${AgentGuideTemplateString}", agent_guide_template
    )
    if "${" in content:
        raise AssertionError("agent guide contains an unresolved substitution")
    return json.loads(content)


def render_wrapper(
    *, next_action: str, decision_action: str = "", transfer_actions: str = ""
) -> dict:
    content = wrapper_source()
    replacements = {
        "${LookupFunctionArn}": (
            "arn:aws:lambda:us-west-2:123456789012:function:bridgefu-test-lookup"
        ),
        "${AgentGuideFlow.ContactFlowArn}": (
            "arn:aws:connect:us-west-2:123456789012:instance/instance-1/"
            "contact-flow/guide-flow"
        ),
        "${TargetContactFlowArn}": (
            "arn:aws:connect:us-west-2:123456789012:instance/instance-1/"
            "contact-flow/target-flow"
        ),
        "${RoutingNextAction}": next_action,
        "${RoutingDecisionActionJson}": decision_action,
        "${RoutingTransferActionsJson}": transfer_actions,
    }
    for source, value in replacements.items():
        content = content.replace(source, value)
    if "${" in content:
        raise AssertionError("wrapper flow contains an unresolved substitution")
    return json.loads(content)


def assert_action_graph(test: unittest.TestCase, document: dict) -> dict:
    actions = {item["Identifier"]: item for item in document["Actions"]}
    test.assertEqual(len(actions), len(document["Actions"]))
    test.assertIn(document["StartAction"], actions)
    for action in actions.values():
        transitions = action["Transitions"]
        if "NextAction" in transitions:
            test.assertIn(transitions["NextAction"], actions)
        for branch in transitions.get("Errors", []):
            test.assertIn(branch["NextAction"], actions)
        for branch in transitions.get("Conditions", []):
            test.assertIn(branch["NextAction"], actions)
    return actions


class ConnectFlowContractTests(unittest.TestCase):
    def test_agent_guide_embeds_literal_labels_and_runtime_value_references(self):
        encoded_rows = (
            "<p><strong>Customer:</strong> "
            "$.Attributes.screen_pop_value_1</p>"
            "<p><strong>Issue \\\\ summary:</strong> "
            "$.Attributes.screen_pop_value_2</p>"
        )
        document = render_guide(encoded_rows)
        actions = assert_action_graph(self, document)
        view_data = actions["show-context"]["Parameters"]["ViewData"]
        self.assertEqual(view_data["Heading"], "Bridgefu caller context")
        self.assertEqual(
            view_data["Sections"][0]["TemplateString"],
            encoded_rows.replace("\\\\", "\\"),
        )
        self.assertNotIn(
            "$.Attributes.screen_pop_label_",
            view_data["Sections"][0]["TemplateString"],
        )
        self.assertIn(
            "$.Attributes.context_available",
            view_data["Sections"][1]["TemplateString"],
        )

    def test_default_wrapper_is_a_complete_non_routed_flow(self):
        document = render_wrapper(next_action="transfer-to-customer-flow")
        actions = assert_action_graph(self, document)
        self.assertNotIn("choose-reviewed-route", actions)
        self.assertEqual(
            actions["set-agent-guide"]["Transitions"]["NextAction"],
            "transfer-to-customer-flow",
        )
        invocation = actions["lookup-context"]["Parameters"]
        self.assertEqual(invocation["InvocationTimeLimitSeconds"], 8)
        self.assertEqual(invocation["InvocationType"], "SYNCHRONOUS")
        self.assertEqual(
            invocation["ResponseValidation"], {"ResponseType": "STRING_MAP"}
        )
        for identifier in ("copy-context", "context-unavailable"):
            self.assertEqual(
                actions[identifier]["Parameters"]["TargetContact"], "Current"
            )
        unavailable = actions["context-unavailable"]["Parameters"]["Attributes"]
        self.assertTrue(all(unavailable.values()))

    def test_routed_wrapper_inserts_a_nonempty_decision_and_owned_transfers(self):
        decision = {
            "Identifier": "choose-reviewed-route",
            "Type": "Compare",
            "Parameters": {
                "ComparisonValue": "$.Attributes.bridgefu_routing_value"
            },
            "Transitions": {
                "NextAction": "transfer-to-customer-flow",
                "Conditions": [
                    {
                        "NextAction": "transfer-to-route-1",
                        "Condition": {"Operator": "Equals", "Operands": ["billing"]},
                    }
                ],
                "Errors": [
                    {
                        "NextAction": "transfer-to-customer-flow",
                        "ErrorType": "NoMatchingCondition",
                    }
                ],
            },
        }
        transfer = {
            "Identifier": "transfer-to-route-1",
            "Type": "TransferToFlow",
            "Parameters": {
                "ContactFlowId": (
                    "arn:aws:connect:us-west-2:123456789012:instance/instance-1/"
                    "contact-flow/billing-flow"
                )
            },
            "Transitions": {
                "NextAction": "disconnect",
                "Errors": [
                    {
                        "NextAction": "transfer-to-customer-flow",
                        "ErrorType": "NoMatchingError",
                    }
                ],
            },
        }
        document = render_wrapper(
            next_action="choose-reviewed-route",
            decision_action="," + json.dumps(decision, separators=(",", ":")),
            transfer_actions="," + json.dumps(transfer, separators=(",", ":")),
        )
        actions = assert_action_graph(self, document)
        self.assertEqual(
            actions["set-agent-guide"]["Transitions"]["NextAction"],
            "choose-reviewed-route",
        )
        self.assertEqual(
            len(actions["choose-reviewed-route"]["Transitions"]["Conditions"]), 1
        )
        self.assertIn("transfer-to-route-1", actions)


if __name__ == "__main__":
    unittest.main()
