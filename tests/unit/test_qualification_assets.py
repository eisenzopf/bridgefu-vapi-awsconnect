from __future__ import annotations

import json
import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QUALIFICATION = ROOT / "qualification"


class QualificationAssetTests(unittest.TestCase):
    def test_matrix_contains_only_the_two_release_smokes(self):
        text = (QUALIFICATION / "matrix.yaml").read_text()
        scenarios = set(re.findall(r"^  - id: ([a-z0-9-]+)$", text, re.M))
        self.assertEqual(scenarios, {"vapi-sip-transfer", "vapi-web-transfer"})
        for removed_scope in ("soak", "failure_drill", "dtmf", "sip-rtp-pcmu"):
            self.assertNotIn(removed_scope, text)

    def test_sip_source_uses_exact_crates_io_rvoip_037(self):
        crate = tomllib.loads((QUALIFICATION / "sip-client" / "Cargo.toml").read_text())
        self.assertEqual(
            crate["dependencies"]["rvoip-sip"],
            {"version": "=0.3.7", "default-features": False},
        )
        lock = (QUALIFICATION / "sip-client" / "Cargo.lock").read_text()
        package = lock.split('name = "rvoip-sip"', 1)[1].split("[[package]]", 1)[0]
        self.assertIn('version = "0.3.7"', package)
        self.assertIn(
            'source = "registry+https://github.com/rust-lang/crates.io-index"',
            package,
        )

    def test_web_sdk_is_referenced_from_bridgefu_not_copied(self):
        self.assertFalse((QUALIFICATION / "web-sdk").exists())
        lock = json.loads((ROOT / "bridgefu.lock.json").read_text())
        self.assertEqual(
            lock["repository"], "https://github.com/eisenzopf/bridgefu.git"
        )
        self.assertRegex(lock["commit"], r"^[0-9a-f]{40}$")
        browser = (QUALIFICATION / "browser" / "vapi-web-playwright.mjs").read_text()
        self.assertIn('join(ROOT, "qualification/package.json")', browser)

    def test_packer_creates_runtime_staging_directory_before_upload(self):
        packer = (ROOT / "image" / "bridgefu.pkr.hcl").read_text()
        create = 'inline = ["install -d -m 0755 /tmp/bridgefu-runtime"]'
        upload = 'destination = "/tmp/bridgefu-runtime/"'
        self.assertIn(create, packer)
        self.assertIn(upload, packer)
        self.assertLess(packer.index(create), packer.index(upload))

    def test_image_verifies_al2023_preinstalled_aws_cli_and_curl(self):
        install = (ROOT / "image" / "install.sh").read_text()
        package_block = install.split("sudo dnf install -y", 1)[1].split("\n\n", 1)[0]
        self.assertNotIn("awscli2", package_block)
        self.assertNotRegex(package_block, r"(?:^|\s)curl(?:\s|$)")
        self.assertIn("aws --version 2>&1 | grep -Eq '^aws-cli/2\\.'", install)
        self.assertIn(
            "curl --version 2>&1 | grep -Eq '^Protocols:.* https( |$)'", install
        )

    def test_image_audits_rvoip_without_python_tomllib(self):
        install = (ROOT / "image" / "install.sh").read_text()
        self.assertNotIn("tomllib", install)
        self.assertIn("cargo metadata --locked --format-version 1", install)
        self.assertIn('select(.name | startswith("rvoip"))', install)
        self.assertIn(
            '(.source // "") != "registry+https://github.com/rust-lang/crates.io-index"',
            install,
        )

    def test_disposable_connect_template_cannot_target_an_existing_instance(self):
        text = (
            QUALIFICATION / "cloudformation" / "disposable-connect.yaml"
        ).read_text()
        self.assertIn("Type: AWS::Connect::Instance", text)
        parameters = text.split("\nParameters:\n", 1)[1].split("\nResources:\n", 1)[0]
        self.assertNotIn("ConnectInstanceArn:", parameters)
        self.assertIn("DeletionPolicy: Delete", text)
        self.assertIn("AutoAccept: true", text)

    def test_release_publication_is_downstream_of_live_qualification(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        publish = workflow.split("\n  publish:\n", 1)[1]
        self.assertIn("needs: [build-candidate, live-qualification]", publish)
        self.assertIn("modify-image-attribute", publish)
        qualification = workflow.split("\n  live-qualification:\n", 1)[1].split(
            "\n  publish:\n", 1
        )[0]
        self.assertIn("qualification/controller.py run", qualification)
        self.assertIn("bridgefu-vapi-sip-smoke", qualification)

    def test_controller_proves_and_removes_every_disposable_resource_class(self):
        controller = (QUALIFICATION / "controller.py").read_text()
        for proof in (
            "customer_stack_absent",
            "connect_instance_absent",
            "temporary_vapi_resources_absent",
            "test_credentials_absent",
            "qualification_objects_absent",
            "bridgefu_sip_invite_evidence",
            "bridgefu_correlation_evidence",
        ):
            self.assertIn(proof, controller)


if __name__ == "__main__":
    unittest.main()
