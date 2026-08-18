from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "ami_build_inputs.py"
SPEC = importlib.util.spec_from_file_location("ami_build_inputs", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("AMI build input verifier could not be imported")
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)


class AmiBuildInputTests(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / "image" / "build-inputs.json"
        self.value = SUBJECT.load(self.path)

    def write_and_load(self, value):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inputs.json"
            path.write_text(json.dumps(value))
            return SUBJECT.load(path)

    def test_reviewed_inputs_are_exact_and_never_use_latest(self):
        self.assertEqual(self.value["packer"]["core_version"], "1.12.0")
        self.assertEqual(self.value["packer"]["amazon_plugin_version"], "1.3.9")
        self.assertEqual(
            set(self.value["packer"]["amazon_plugin_zip_sha256"]),
            {"darwin_arm64", "linux_amd64", "linux_arm64"},
        )
        self.assertEqual(self.value["source_ami"]["region"], "us-west-2")
        self.assertEqual(
            self.value["builder"],
            {"instance_type": "m7g.4xlarge", "vcpu_count": 16, "cargo_jobs": 8},
        )
        for key in ("package_url", "signature_url", "key_url"):
            self.assertNotIn("/latest/", self.value["cloudwatch_agent"][key])

    def test_mutable_or_tampered_input_fails_closed(self):
        mutations = []
        latest = copy.deepcopy(self.value)
        latest["cloudwatch_agent"]["package_url"] = latest["cloudwatch_agent"][
            "package_url"
        ].replace(latest["cloudwatch_agent"]["version"], "latest")
        mutations.append(latest)
        ranged = copy.deepcopy(self.value)
        ranged["packer"]["amazon_plugin_version"] = ">= 1.3.9"
        mutations.append(ranged)
        unpinned = copy.deepcopy(self.value)
        unpinned["source_ami"].pop("id")
        mutations.append(unpinned)
        digest = copy.deepcopy(self.value)
        digest["cloudwatch_agent"]["package_sha256"] = "0" * 63
        mutations.append(digest)
        extra = copy.deepcopy(self.value)
        extra["source_ami"]["most_recent"] = True
        mutations.append(extra)
        undersized = copy.deepcopy(self.value)
        undersized["builder"] = {
            "instance_type": "m7g.2xlarge",
            "vcpu_count": 8,
            "cargo_jobs": 4,
        }
        mutations.append(undersized)
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(SUBJECT.BuildInputError):
                self.write_and_load(value)

    def test_live_source_ami_shape_is_verified_exactly(self):
        source = self.value["source_ami"]
        response = {
            "Images": [
                {
                    "ImageId": source["id"],
                    "OwnerId": source["owner_id"],
                    "Name": source["name"],
                    "Architecture": "arm64",
                    "State": "available",
                    "RootDeviceType": "ebs",
                    "VirtualizationType": "hvm",
                }
            ]
        }
        result = mock.Mock(returncode=0, stdout=json.dumps(response), stderr="")
        with mock.patch.object(SUBJECT.subprocess, "run", return_value=result):
            SUBJECT.verify_source_ami(self.value)
        response["Images"][0]["OwnerId"] = "000000000000"
        result.stdout = json.dumps(response)
        with mock.patch.object(SUBJECT.subprocess, "run", return_value=result):
            with self.assertRaises(SUBJECT.BuildInputError):
                SUBJECT.verify_source_ami(self.value)

    def test_packer_and_install_use_the_reviewed_inputs(self):
        packer = (ROOT / "image" / "bridgefu.pkr.hcl").read_text()
        install = (ROOT / "image" / "install.sh").read_text()
        candidate = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        makefile = (ROOT / "Makefile").read_text()
        local_validator = (ROOT / "release" / "validate.py").read_text()
        self.assertIn('version = "= 1.3.9"', packer)
        self.assertIn("source_ami = var.source_ami_id", packer)
        self.assertIn("instance_type = var.builder_instance_type", packer)
        self.assertIn(
            'condition     = var.builder_instance_type == "m7g.4xlarge"', packer
        )
        self.assertIn(
            'cargo build --locked --release --jobs "$BRIDGEFU_BUILD_JOBS"', install
        )
        self.assertNotIn("most_recent", packer)
        self.assertIn("image/build-inputs.json", packer)
        self.assertIn("amazon-cloudwatch-agent.rpm.sig", install)
        self.assertIn("gpg --batch --no-autostart", install)
        self.assertIn("--no-default-keyring", install)
        self.assertIn("--dearmor", install)
        self.assertNotIn("gpg --batch --import", install)
        self.assertIn(
            "CloudWatch Agent detached signature verification failed", install
        )
        self.assertIn("image-rpm-inventory.tsv", install)
        for workflow, platform in (
            (candidate, "linux_arm64"),
            (ci, "linux_amd64"),
        ):
            with self.subTest(platform=platform):
                self.assertIn(f"packer_plugin_platform={platform}", workflow)
                self.assertIn("amazon_plugin_zip_sha256", workflow)
                self.assertIn("sha256sum --check --strict", workflow)
                self.assertIn("packer plugins install --path", workflow)
                self.assertLess(
                    workflow.index("packer plugins install --path"),
                    workflow.index("packer init image/bridgefu.pkr.hcl"),
                )
                self.assertIn('-var source_ami_id="$source_base_ami"', workflow)
                self.assertIn(
                    '-var builder_instance_type="$builder_instance_type"', workflow
                )
                self.assertIn('-var cargo_build_jobs="$cargo_build_jobs"', workflow)
        self.assertIn("python3 release/validate.py --packer-only", makefile)
        self.assertIn("amazon_plugin_zip_sha256", local_validator)
        self.assertIn("Packer Amazon plugin archive digest mismatch", local_validator)
        self.assertIn(
            "f\"source_ami_id={inputs['source_ami']['id']}\"", local_validator
        )
        self.assertLess(
            local_validator.index('"plugins",\n                "install"'),
            local_validator.index('[packer, "init"'),
        )


if __name__ == "__main__":
    unittest.main()
