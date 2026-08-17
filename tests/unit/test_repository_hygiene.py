from __future__ import annotations

import re
import subprocess
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class RepositoryHygieneTests(unittest.TestCase):
    def test_sensitive_local_artifacts_are_ignored(self):
        rules = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
        required = {
            ".env",
            ".env.*",
            ".aws/",
            "*.pem",
            "*.key",
            "*.p12",
            "*.pfx",
            "*.pcap",
            "*.pcapng",
            "*.har",
            "*.log",
            "*.sqlite",
            "*.db-wal",
            "**/playwright/.auth/",
            "**/storage-state.json",
            "target/",
            "/diagnostic/",
            "/diagnostics/",
            "/failure-evidence/",
            "/failure-*/",
        }
        self.assertEqual(required - rules, set())
        self.assertIn("!.env.example", rules)

        for candidate in (
            "diagnostic/probe.json",
            "diagnostics/call.json",
            "failure-evidence/trace.json",
            "failure-v016-smoke/call.json",
        ):
            with self.subTest(candidate=candidate):
                result = subprocess.run(
                    ["git", "check-ignore", "--no-index", "--quiet", candidate],
                    cwd=ROOT,
                    check=False,
                )
                self.assertEqual(result.returncode, 0)

    def test_secret_scan_is_immutable_and_complete_history(self):
        workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        )
        steps = workflow["jobs"]["secret-scan"]["steps"]
        checkout = steps[0]
        self.assertEqual(checkout["with"]["fetch-depth"], 0)
        self.assertFalse(checkout["with"]["persist-credentials"])
        run = steps[1]["run"]
        self.assertIn(
            "zricethezav/gitleaks@sha256:"
            "c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f",
            run,
        )
        self.assertIn("git /repo", run)
        self.assertIn("--redact=100", run)
        self.assertIn("--gitleaks-ignore-path /repo/.gitleaksignore", run)

    def test_historical_allowlist_is_fingerprint_only(self):
        lines = [
            line
            for line in (ROOT / ".gitleaksignore")
            .read_text(encoding="utf-8")
            .splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(len(lines), 9)
        for line in lines:
            self.assertRegex(
                line,
                r"^[0-9a-f]{40}:tests/unit/[A-Za-z0-9_.-]+:generic-api-key:[0-9]+$",
            )
            self.assertNotIn("*", line)

    def test_public_status_ledger_has_no_live_cloud_identifiers(self):
        status = (
            ROOT
            / "docs"
            / "maintainers"
            / "CLOUDFORMATION_RELEASE_QUALIFICATION_STATUS.md"
        ).read_text(encoding="utf-8")
        forbidden = {
            "AWS account number": r"(?<![0-9])[0-9]{12}(?![0-9])",
            "AWS ARN": r"\barn:aws(?:-[a-z0-9-]+)?:",
            "AMI ID": r"\bami-[0-9a-f]{8,17}\b",
            "snapshot ID": r"\bsnap-[0-9a-f]{8,17}\b",
            "EC2 instance ID": r"\bi-[0-9a-f]{8,17}\b",
            "VPC ID": r"\bvpc-[0-9a-f]{8,17}\b",
            "S3 URI": r"\bs3://",
        }
        for label, pattern in forbidden.items():
            with self.subTest(label=label):
                self.assertIsNone(re.search(pattern, status, flags=re.IGNORECASE))

    def test_release_environment_documentation_matches_workflow_contract(self):
        guide = (ROOT / "docs" / "maintainers" / "release.md").read_text(
            encoding="utf-8"
        )
        qualification = (ROOT / "qualification" / "README.md").read_text(
            encoding="utf-8"
        )
        self.assertEqual(guide.count("- `AWS_ACCOUNT_ID`"), 3)
        self.assertEqual(guide.count("- `RELEASE_SIGNING_KEY_ARN`"), 3)
        self.assertEqual(
            guide.count("- `VAPI_API_KEY_SECRET_ARN_US_WEST_2`"), 2
        )
        self.assertEqual(
            guide.count("- `VAPI_API_KEY_SECRET_ARN_US_EAST_1`"), 2
        )
        self.assertNotIn("VAPI_PUBLIC_KEY", guide + qualification)
        for variable in (
            "AWS_ACCOUNT_ID",
            "AWS_QUALIFICATION_ROLE_ARN",
            "AWS_QUALIFICATION_CLOUDFORMATION_ROLE_ARN",
            "RELEASE_SIGNING_KEY_ARN",
            "VAPI_API_KEY_SECRET_ARN_US_WEST_2",
            "VAPI_API_KEY_SECRET_ARN_US_EAST_1",
            "PUBLIC_HOSTED_ZONE_ID",
            "PUBLIC_HOSTED_ZONE_NAME",
        ):
            self.assertIn(f"- `{variable}`", qualification)
        self.assertNotIn("- `VAPI_API_KEY_SECRET_ARN`", qualification)

    def test_source_import_matches_the_current_bridgefu_lock(self):
        source_import = (ROOT / "SOURCE_IMPORT.md").read_text(encoding="utf-8")
        lock = __import__("json").loads(
            (ROOT / "bridgefu.lock.json").read_text(encoding="utf-8")
        )
        self.assertIn(lock["commit"], source_import)
        self.assertIn(lock["cargo_lock_sha256"], source_import)
        self.assertIn("Historical import", source_import)
        self.assertNotIn("180ca1fe1099872a2e3ddabb116f757566dc3683", source_import)

    def test_every_alarm_runbook_reference_exists_and_is_starter_specific(self):
        templates = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                ROOT / "cloudformation" / "nested" / "observability.yaml",
                ROOT / "cloudformation" / "nested" / "runtime.yaml",
            )
        )
        references = set(re.findall(r"runbooks/([a-z-]+\.md)", templates))
        self.assertEqual(len(references), 8)
        for reference in references:
            with self.subTest(reference=reference):
                text = (ROOT / "runbooks" / reference).read_text(encoding="utf-8")
                self.assertNotIn("systemctl status bridgefu haproxy docker", text)
                self.assertNotIn("qualified HA profile", text)
                self.assertNotIn("confirm one SIPS URI", text)

    def test_optional_mode_documentation_separates_uri_scheme_from_tls(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        qualification = (ROOT / "qualification" / "README.md").read_text(
            encoding="utf-8"
        )
        product = (ROOT / "cloudformation" / "template.yaml").read_text(
            encoding="utf-8"
        )
        self.assertIn("SIP over TLS; SRTP preferred", readme)
        self.assertNotIn("SIPS transfer; SRTP preferred", readme)
        self.assertIn("`sip:...;transport=tls` produced an observed TLS", qualification)
        self.assertNotIn("Production must use a SIPS mode", product)

    def test_single_local_preflight_is_fail_closed_and_complete(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        validator = (ROOT / "release" / "validate.py").read_text(encoding="utf-8")
        self.assertIn("preflight: preflight-tools", makefile)
        for target in (
            "test",
            "qualification-test",
            "sdk-test",
            "lint",
            "package",
            "validate",
            "packer-validate",
        ):
            self.assertIn(f"$(MAKE) {target}", makefile)
        self.assertNotIn("if command -v", makefile)
        self.assertIn('npm --version | cut -d. -f1)" = 10', makefile)
        self.assertIn("actionlint", makefile)
        self.assertIn("release/reap_qualification.sh", makefile)
        self.assertIn('require_command("cfn-lint")', validator)
        self.assertIn("amazon_plugin_zip_sha256", validator)
        self.assertIn('return "darwin_arm64"', validator)
        self.assertIn("Packer Amazon plugin archive digest mismatch", validator)
        self.assertLess(
            validator.index('"plugins",\n                "install"'),
            validator.index('[packer, "init"'),
        )

    def test_release_validation_fails_when_cfn_lint_is_missing(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "release" / "validate.py")],
            cwd=ROOT,
            env={"PATH": ""},
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required local validation tool is missing: cfn-lint", result.stderr)


if __name__ == "__main__":
    unittest.main()
