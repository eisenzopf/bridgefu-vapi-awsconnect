from __future__ import annotations

import re
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRODUCT = (ROOT / "cloudformation" / "template.yaml").read_text()
CONFIGURATION = (
    ROOT / "cloudformation" / "nested" / "configuration.yaml"
).read_text()
NETWORK = (ROOT / "cloudformation" / "nested" / "network.yaml").read_text()
VAPI = (ROOT / "cloudformation" / "nested" / "vapi.yaml").read_text()
VAPI_HANDLER = (ROOT / "lambda" / "vapi_provisioner" / "handler.py").read_text()
DEPLOY_DOC = (ROOT / "docs" / "deploy.md").read_text()
OPERATIONS_DOC = (ROOT / "docs" / "operations.md").read_text()


def section(text: str, start: str, end: str) -> str:
    return text.split(start, 1)[1].split(end, 1)[0]


class ProductTemplateContractTests(unittest.TestCase):
    def test_product_is_vapi_us_only_without_a_region_prompt(self):
        parameters = section(PRODUCT, "\nParameters:\n", "\nMappings:\n")
        parameter_names = set(
            re.findall(r"^  ([A-Za-z][A-Za-z0-9]*):", parameters, re.MULTILINE)
        )

        self.assertNotIn("VapiRegion", parameter_names)
        self.assertNotIn("VapiRegionConfiguration", PRODUCT)
        self.assertNotIn("https://api.eu.vapi.ai", PRODUCT)
        self.assertNotIn("63.182.83.170/32", PRODUCT)
        self.assertNotIn("VapiApiBaseUrl", PRODUCT + VAPI)
        self.assertNotIn("https://api.eu.vapi.ai", PRODUCT + VAPI + VAPI_HANDLER)
        self.assertIn('"https://api.vapi.ai"', VAPI_HANDLER)
        self.assertEqual(PRODUCT.count("VapiSignalingCidr1: 44.229.228.186/32"), 1)
        self.assertEqual(PRODUCT.count("VapiSignalingCidr2: 44.238.177.138/32"), 1)
        self.assertEqual(PRODUCT.count("MediaSourceCidr: 0.0.0.0/0"), 1)
        self.assertIn("There is no Vapi-region option", DEPLOY_DOC)

    def test_v1_product_uses_one_fixed_internally_consistent_vpc_layout(self):
        parameters = section(PRODUCT, "\nParameters:\n", "\nMappings:\n")
        parameter_names = set(
            re.findall(r"^  ([A-Za-z][A-Za-z0-9]*):", parameters, re.MULTILINE)
        )

        self.assertNotIn("VpcCidr", parameter_names)
        network_parameters = section(NETWORK, "\nParameters:\n", "\nRules:\n")
        for expected in (
            "VpcCidr:\n    Type: String\n    Default: 10.42.0.0/16",
            "PublicSubnet1Cidr:\n    Type: String\n    Default: 10.42.0.0/24",
            "PublicSubnet2Cidr:\n    Type: String\n    Default: 10.42.1.0/24",
            "PrivateSubnet1Cidr:\n    Type: String\n    Default: 10.42.10.0/24",
            "PrivateSubnet2Cidr:\n    Type: String\n    Default: 10.42.11.0/24",
        ):
            self.assertIn(expected, network_parameters)
        self.assertIn("VpcCidr: 10.42.0.0/16", PRODUCT)
        self.assertIn("dedicated VPC CIDR is fixed in v1", DEPLOY_DOC)

    def test_early_configuration_gate_owns_secret_and_immutable_inputs(self):
        configuration = section(PRODUCT, "\n  Configuration:\n", "\n  Network:\n")
        for expected in (
            "DeploymentId: !Ref DeploymentId",
            "ConnectInstanceArn: !Ref ConnectInstanceArn",
            "PublicHostedZoneId: !Ref PublicHostedZoneId",
            "SipHostname: !Ref SipHostname",
            "SipSecurity: !Ref SipSecurity",
            "MaxConcurrentCalls: !Ref MaxConcurrentCalls",
            "VapiApiKeySecretArn: !Ref VapiApiKeySecretArn",
            "DataRetentionMode: !Ref DataRetentionMode",
        ):
            self.assertIn(expected, configuration)
        self.assertIn(
            "RuntimeImageId: !FindInMap [RegionRelease, !Ref 'AWS::Region', AmiId]",
            configuration,
        )
        network = section(PRODUCT, "\n  Network:\n", "\n  HandoffService:\n")
        self.assertIn(
            "DeploymentId: !GetAtt Configuration.Outputs.DeploymentId", network
        )
        self.assertIn("`DataRetentionMode` is also fixed for the lifetime", DEPLOY_DOC)
        self.assertIn("`DataRetentionMode`, and the release AMI", OPERATIONS_DOC)
        self.assertEqual(
            PRODUCT.count(
                "DataRetentionMode: !GetAtt Configuration.Outputs.DataRetentionMode"
            ),
            2,
        )
        self.assertIn(
            "RetainVapiResourcesOnDelete: !GetAtt "
            "Configuration.Outputs.RetainVapiResourcesOnDelete",
            PRODUCT,
        )
        for output in (
            "DeploymentId",
            "ConnectInstanceArn",
            "PublicHostedZoneId",
            "SipHostname",
            "SipSecurity",
            "MaxConcurrentCalls",
        ):
            self.assertIn(
                f"{output}: {{Value: !GetAtt Configuration.{output}}}",
                CONFIGURATION,
            )
        self.assertIn("The settings written into the gateway", OPERATIONS_DOC)

    def test_vapi_call_entry_ownership_is_explicit(self):
        self.assertIn("does **not** create, reassign, or delete", DEPLOY_DOC)
        self.assertIn("test-call control in the\nVapi dashboard", DEPLOY_DOC)
        self.assertIn("existing Vapi phone number or Vapi SIP\nendpoint", DEPLOY_DOC)
        self.assertIn("Record its currently assigned assistant", DEPLOY_DOC)
        self.assertIn("Reassign the prior assistant to roll back", DEPLOY_DOC)

    def test_retention_notice_matches_selected_mode(self):
        output = PRODUCT.split("\n  VapiRetentionNotice:\n", 1)[1]
        self.assertIn("Value: !If", output)
        self.assertIn("- RetainCustomerData", output)
        self.assertIn(
            "The Vapi assistant, tool, and credential are retained", output
        )
        self.assertIn(
            "The disposable Vapi assistant, tool, and credential are deleted", output
        )

    def test_v1_release_upgrade_is_parallel_not_in_place_ami_replacement(self):
        configuration = section(PRODUCT, "\n  Configuration:\n", "\n  Network:\n")
        runtime = section(PRODUCT, "\n  Runtime:\n", "\n  VapiResources:\n")
        expected_image = "!FindInMap [RegionRelease, !Ref 'AWS::Region', AmiId]"
        self.assertIn(f"RuntimeImageId: {expected_image}", configuration)
        self.assertIn("AmiId: !GetAtt Configuration.Outputs.RuntimeImageId", runtime)
        self.assertIn("Do not update an existing v1 stack", OPERATIONS_DOC)
        self.assertIn("Use a parallel deployment for a release upgrade", OPERATIONS_DOC)
        self.assertNotIn(
            "An AMI change replaces the single EC2 gateway", OPERATIONS_DOC
        )

    def test_documented_quick_create_link_targets_the_published_latest_template(self):
        match = re.search(
            r"\[Launch Bridgefu with CloudFormation\]\((https://[^)]+)\)",
            DEPLOY_DOC,
        )
        self.assertIsNotNone(match)
        parsed = urllib.parse.urlsplit(match.group(1))
        self.assertEqual(parsed.netloc, "console.aws.amazon.com")
        self.assertEqual(parsed.query, "")
        route, query_text = parsed.fragment.split("?", 1)
        self.assertEqual(route, "/stacks/create/review")
        query = urllib.parse.parse_qs(query_text)
        self.assertEqual(query["stackName"], ["bridgefu-vapi-connect"])
        self.assertEqual(query["param_DeploymentId"], ["support"])
        self.assertEqual(query["param_InstanceType"], ["c7g.2xlarge"])
        self.assertEqual(
            query["templateURL"],
            [
                "https://bridgefu-vapi-awsconnect-225478700523-us-east-1."
                "s3.us-east-1.amazonaws.com/latest/cloudformation/template.yaml"
            ],
        )
        self.assertIn("normal AWS region selector", DEPLOY_DOC)

    def test_deletion_documentation_does_not_claim_logs_are_retained(self):
        self.assertIn("CloudWatch log groups are deleted with the stack", OPERATIONS_DOC)
        self.assertIn("Production retention\ndoes not retain CloudWatch logs", OPERATIONS_DOC)
        self.assertIn("The AWS Backup vault and its recovery points", OPERATIONS_DOC)


if __name__ == "__main__":
    unittest.main()
