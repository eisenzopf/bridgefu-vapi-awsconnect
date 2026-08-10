from __future__ import annotations

import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "lambda" / "common"
HANDLER_PATH = ROOT / "lambda" / "configuration" / "handler.py"
import sys

sys.path.insert(0, str(COMMON))
spec = importlib.util.spec_from_file_location("configuration_handler", HANDLER_PATH)
handler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handler)


class FakeConnect:
    def describe_instance(self, **_kwargs):
        return {"Instance": {"InstanceStatus": "ACTIVE"}}

    def describe_contact_flow(self, **_kwargs):
        return {"ContactFlow": {"State": "ACTIVE"}}


class FakeRoute53:
    def get_hosted_zone(self, **_kwargs):
        return {
            "HostedZone": {
                "Name": "example.com.",
                "Config": {"PrivateZone": False},
            }
        }


class FakeBoto3:
    def client(self, service):
        return FakeConnect() if service == "connect" else FakeRoute53()


class ConfigurationTests(unittest.TestCase):
    def properties(self):
        return {
            "AccountId": "123456789012",
            "ConnectInstanceArn": (
                "arn:aws:connect:us-west-2:123456789012:instance/instance-1"
            ),
            "TargetContactFlowArn": (
                "arn:aws:connect:us-west-2:123456789012:instance/instance-1/"
                "contact-flow/default-flow"
            ),
            "PublicHostedZoneId": "Z123",
            "SipHostname": "bridgefu.example.com",
            "ScreenPopFieldsJson": json.dumps(
                [
                    {
                        "key": "department",
                        "label": "Department",
                        "description": "Selected department",
                        "type": "choice",
                        "required": True,
                        "choices": ["billing", "support"],
                    }
                ]
            ),
            "RoutingJson": json.dumps(
                {
                    "fieldKey": "department",
                    "routes": [
                        {
                            "value": "billing",
                            "contactFlowArn": (
                                "arn:aws:connect:us-west-2:123456789012:"
                                "instance/instance-1/contact-flow/billing-flow"
                            ),
                        }
                    ],
                }
            ),
        }

    def test_renders_only_configured_rows_and_reviewed_routes(self):
        with mock.patch.dict(os.environ, {"AWS_REGION": "us-west-2"}):
            result = handler.render(self.properties(), boto3_module=FakeBoto3())
        self.assertEqual(result["FieldCount"], "1")
        self.assertIn("screen_pop_label_1", result["AgentGuideTemplateString"])
        self.assertNotIn("screen_pop_label_2", result["AgentGuideTemplateString"])
        self.assertEqual(result["RoutingFieldKey"], "department")
        self.assertEqual(result["RoutingNextAction"], "choose-reviewed-route")
        decision = json.loads(result["RoutingDecisionActionJson"][1:])
        self.assertEqual(decision["Identifier"], "choose-reviewed-route")
        self.assertEqual(len(decision["Transitions"]["Conditions"]), 1)
        transfer = json.loads(result["RoutingTransferActionsJson"][1:])
        self.assertEqual(transfer["Identifier"], "transfer-to-route-1")
        self.assertIn("billing-flow", transfer["Parameters"]["ContactFlowId"])

    def test_no_routing_bypasses_the_compare_action(self):
        properties = self.properties()
        properties["RoutingJson"] = "{}"
        with mock.patch.dict(os.environ, {"AWS_REGION": "us-west-2"}):
            result = handler.render(properties, boto3_module=FakeBoto3())
        self.assertEqual(result["RoutingFieldKey"], "")
        self.assertEqual(result["RoutingNextAction"], "transfer-to-customer-flow")
        self.assertEqual(result["RoutingDecisionActionJson"], "")
        self.assertEqual(result["RoutingTransferActionsJson"], "")

    def test_rejects_cross_account_connect_target(self):
        properties = self.properties()
        properties["TargetContactFlowArn"] = properties["TargetContactFlowArn"].replace(
            "123456789012", "999999999999"
        )
        with (
            mock.patch.dict(os.environ, {"AWS_REGION": "us-west-2"}),
            self.assertRaisesRegex(handler.ConfigurationError, "connect_arn_scope"),
        ):
            handler.render(properties, boto3_module=FakeBoto3())


if __name__ == "__main__":
    unittest.main()
