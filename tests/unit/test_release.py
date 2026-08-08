from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ReleaseContractTests(unittest.TestCase):
    def test_public_template_prompts_only_for_customer_configuration(self):
        text = (ROOT / "cloudformation" / "template.yaml").read_text()
        parameter_text = text.split("\nParameters:\n", 1)[1].split("\nMappings:\n", 1)[
            0
        ]
        parameters = set(re.findall(r"^  ([A-Za-z0-9]+):", parameter_text, re.M))
        self.assertEqual(
            parameters,
            {
                "DeploymentId",
                "InstanceType",
                "ConnectInstanceArn",
                "TargetContactFlowArn",
                "PublicHostedZoneId",
                "SipHostname",
                "VapiApiKeySecretArn",
                "VapiModel",
                "VapiVoiceId",
                "ScreenPopFieldsJson",
                "RoutingJson",
                "ContextTtlSeconds",
                "MaxConcurrentCalls",
                "LogRetentionDays",
                "AlarmEmail",
                "VpcCidr",
                "VapiSignalingCidr1",
                "VapiSignalingCidr2",
                "VapiSignalingCidr3",
                "VapiSignalingCidr4",
                "MediaSourceCidr",
                "DataRetentionMode",
            },
        )
        for forbidden in (
            "AmiId",
            "ArtifactBucket",
            "ArtifactKey",
            "NestedTemplateBaseUrl",
            "BridgefuImageUri",
            "SubnetId",
            "VapiApiKey",
        ):
            self.assertNotIn(forbidden, parameters)

    def test_release_contains_versioned_quick_create_links_and_no_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "release" / "build_release.py"),
                    "--version",
                    "1.2.3-test",
                    "--output",
                    directory,
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            output = Path(directory)
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertFalse(manifest["contains_secrets"])
            self.assertEqual(manifest["bridgefu"]["required_rvoip_version"], "0.3.7")
            links = json.loads((output / "quick-create-links.json").read_text())
            self.assertEqual(set(links), {"us-east-1", "us-west-2"})
            parsed = urllib.parse.urlsplit(links["us-west-2"])
            self.assertEqual(parsed.netloc, "us-west-2.console.aws.amazon.com")
            query = urllib.parse.parse_qs(parsed.fragment.split("?", 1)[1])
            self.assertEqual(query["stackName"], ["bridgefu-vapi-connect"])
            self.assertEqual(query["param_InstanceType"], ["t4g.large"])
            self.assertIn("/releases/1.2.3-test/", query["templateURL"][0])

    def test_release_builder_refuses_to_replace_unowned_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release"
            output.mkdir()
            (output / "customer-file.txt").write_text("keep me\n")
            result = subprocess.run(  # noqa: S603
                [
                    sys.executable,
                    str(ROOT / "release" / "build_release.py"),
                    "--version",
                    "1.2.3-test",
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((output / "customer-file.txt").read_text(), "keep me\n")

    def test_test_retention_mode_deletes_vapi_qualification_resources(self):
        root = (ROOT / "cloudformation" / "template.yaml").read_text()
        nested = (ROOT / "cloudformation" / "nested" / "vapi.yaml").read_text()
        self.assertIn(
            "RetainVapiResourcesOnDelete: !If [RetainCustomerData, 'true', 'false']",
            root,
        )
        self.assertIn(
            "RetainVapiResourcesOnDelete: !Ref RetainVapiResourcesOnDelete",
            nested,
        )


if __name__ == "__main__":
    unittest.main()
