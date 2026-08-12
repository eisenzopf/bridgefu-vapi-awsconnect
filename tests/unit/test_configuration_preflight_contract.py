from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "lambda" / "common"
HANDLER_PATH = ROOT / "lambda" / "configuration" / "handler.py"
sys.path.insert(0, str(COMMON))
spec = importlib.util.spec_from_file_location(
    "configuration_preflight_handler", HANDLER_PATH
)
handler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handler)


class FakeConnect:
    def describe_instance(self, **_kwargs):
        return {"Instance": {"InstanceStatus": "ACTIVE"}}

    def describe_contact_flow(self, **_kwargs):
        return {"ContactFlow": {"State": "ACTIVE", "Status": "PUBLISHED"}}


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


def properties() -> dict[str, str]:
    return {
        "AccountId": "123456789012",
        "Partition": "aws",
        "DeploymentId": "support",
        "ConnectInstanceArn": (
            "arn:aws:connect:us-west-2:123456789012:instance/instance-1"
        ),
        "TargetContactFlowArn": (
            "arn:aws:connect:us-west-2:123456789012:instance/instance-1/"
            "contact-flow/default-flow"
        ),
        "PublicHostedZoneId": "Z123",
        "SipHostname": "bridgefu.example.com",
        "SipSecurity": "sips_optional_srtp",
        "MaxConcurrentCalls": "100",
        "VapiApiKeySecretArn": (
            "arn:aws:secretsmanager:us-west-2:123456789012:secret:vapi-key-AbCdEf"
        ),
        "RuntimeImageId": "ami-0123456789abcdef0",
        "ScreenPopFieldsJson": json.dumps(
            [
                {
                    "key": "summary",
                    "label": "Summary",
                    "description": "Caller summary.",
                    "type": "text",
                    "required": True,
                    "max_length": 256,
                }
            ]
        ),
        "RoutingJson": "{}",
        "DataRetentionMode": "ProductionRetain",
    }


class ConfigurationPreflightContractTests(unittest.TestCase):
    def test_accepts_only_same_region_and_account_vapi_secret(self):
        with mock.patch.dict(os.environ, {"AWS_REGION": "us-west-2"}):
            result = handler.render(properties(), boto3_module=FakeBoto3())
        self.assertEqual(result["FieldCount"], "1")
        self.assertEqual(result["DataRetentionMode"], "ProductionRetain")
        self.assertEqual(result["RuntimeImageId"], "ami-0123456789abcdef0")
        self.assertEqual(result["DeploymentId"], "support")
        self.assertEqual(result["ConnectInstanceArn"], properties()["ConnectInstanceArn"])
        self.assertEqual(result["PublicHostedZoneId"], "Z123")
        self.assertEqual(result["SipHostname"], "bridgefu.example.com")
        self.assertEqual(result["SipSecurity"], "sips_optional_srtp")
        self.assertEqual(result["MaxConcurrentCalls"], "100")
        self.assertNotIn("VapiApiKeySecretArn", result)
        self.assertEqual(result["RetainVapiResourcesOnDelete"], "true")

        for replacement in (
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:vapi-key-AbCdEf",
            "arn:aws:secretsmanager:us-west-2:999999999999:secret:vapi-key-AbCdEf",
            "not-an-arn",
            "arn:aws-us-gov:secretsmanager:us-west-2:123456789012:secret:vapi-key-AbCdEf",
        ):
            candidate = properties()
            candidate["VapiApiKeySecretArn"] = replacement
            with (
                mock.patch.dict(os.environ, {"AWS_REGION": "us-west-2"}),
                self.assertRaisesRegex(
                    handler.ConfigurationError, "vapi_secret_arn_scope_invalid"
                ),
            ):
                handler.render(candidate, boto3_module=FakeBoto3())

    def test_rejects_unknown_retention_mode(self):
        candidate = properties()
        candidate["DataRetentionMode"] = "DeleteEverything"
        with (
            mock.patch.dict(os.environ, {"AWS_REGION": "us-west-2"}),
            self.assertRaisesRegex(
                handler.ConfigurationError, "data_retention_mode_invalid"
            ),
        ):
            handler.render(candidate, boto3_module=FakeBoto3())

    def test_stack_update_cannot_switch_retention_mode(self):
        sent: list[tuple[str, str]] = []

        def record_send(_event, status, _physical_id, _data, reason):
            sent.append((status, reason))

        current = properties()
        old = dict(current)
        old["DataRetentionMode"] = "TestDelete"
        event = {
            "RequestType": "Update",
            "PhysicalResourceId": "bridgefu-configuration-v1",
            "ResourceProperties": current,
            "OldResourceProperties": old,
        }
        with mock.patch.object(handler, "_send", side_effect=record_send):
            handler.lambda_handler(event, None)
        self.assertEqual(sent, [("FAILED", "data_retention_mode_immutable")])

    def test_stack_update_cannot_replace_runtime_image_in_place(self):
        sent: list[tuple[str, str]] = []

        def record_send(_event, status, _physical_id, _data, reason):
            sent.append((status, reason))

        current = properties()
        old = dict(current)
        old["RuntimeImageId"] = "ami-fedcba98765432100"
        event = {
            "RequestType": "Update",
            "PhysicalResourceId": "bridgefu-configuration-v1",
            "ResourceProperties": current,
            "OldResourceProperties": old,
        }
        with mock.patch.object(handler, "_send", side_effect=record_send):
            handler.lambda_handler(event, None)
        self.assertEqual(sent, [("FAILED", "runtime_image_id_immutable")])

    def test_stack_update_rejects_every_launch_bound_change(self):
        cases = {
            "DeploymentId": ("replacement", "deployment_id_immutable"),
            "ConnectInstanceArn": (
                "arn:aws:connect:us-west-2:123456789012:instance/instance-2",
                "connect_instance_arn_immutable",
            ),
            "PublicHostedZoneId": ("Z999", "public_hosted_zone_id_immutable"),
            "SipHostname": ("replacement.example.com", "sip_hostname_immutable"),
            "SipSecurity": ("sips_srtp", "sip_security_immutable"),
            "MaxConcurrentCalls": ("200", "max_concurrent_calls_immutable"),
        }

        for property_name, (old_value, expected_error) in cases.items():
            with self.subTest(property_name=property_name):
                sent: list[tuple[str, str]] = []

                def record_send(_event, status, _physical_id, _data, reason):
                    sent.append((status, reason))

                current = properties()
                old = dict(current)
                old[property_name] = old_value
                event = {
                    "RequestType": "Update",
                    "PhysicalResourceId": "bridgefu-configuration-v1",
                    "ResourceProperties": current,
                    "OldResourceProperties": old,
                }
                with mock.patch.object(handler, "_send", side_effect=record_send):
                    handler.lambda_handler(event, None)
                self.assertEqual(sent, [("FAILED", expected_error)])


if __name__ == "__main__":
    unittest.main()
