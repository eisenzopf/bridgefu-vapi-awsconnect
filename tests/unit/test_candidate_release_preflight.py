#!/usr/bin/env python3
"""Executable contracts for candidate release gates before remote mutation."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "candidate.yml"


def workflow() -> dict[str, Any]:
    value = yaml.safe_load(WORKFLOW_PATH.read_text())
    if not isinstance(value, dict):
        raise AssertionError("candidate workflow is not a mapping")
    return value


def named_step(steps: list[dict[str, Any]], name: str) -> tuple[int, dict[str, Any]]:
    matches = [
        (index, step) for index, step in enumerate(steps) if step.get("name") == name
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one candidate step named {name!r}")
    return matches[0]


def executable(path: Path, source: str) -> None:
    path.write_text(source)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class CandidateReleasePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = workflow()
        self.steps = self.value["jobs"]["build-private-candidate"]["steps"]

    def run_ci_attestation(
        self, response: dict[str, Any]
    ) -> subprocess.CompletedProcess:
        _, step = named_step(
            self.steps, "Require successful exact-main CI before AWS authentication"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            arguments = root / "gh-arguments"
            executable(
                root / "gh",
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf "%s\\n" "$@" > "$GH_ARGUMENTS"\n'
                'printf "%s" "$GH_RESPONSE"\n',
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{root}:{environment['PATH']}",
                    "GH_ARGUMENTS": str(arguments),
                    "GH_RESPONSE": json.dumps(response),
                    "GH_TOKEN": "synthetic-token",
                    "GITHUB_REPOSITORY": "owner/repository",
                    "GITHUB_SHA": "a" * 40,
                }
            )
            result = subprocess.run(
                ["bash", "-c", step["run"]],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                timeout=10,
            )
            if result.returncode == 0:
                self.assertEqual(
                    arguments.read_text().splitlines(),
                    [
                        "api",
                        "-X",
                        "GET",
                        "repos/owner/repository/actions/workflows/ci.yml/runs",
                        "-f",
                        f"head_sha={'a' * 40}",
                        "-f",
                        "status=completed",
                        "-f",
                        "per_page=100",
                    ],
                )
            return result

    def test_ci_attestation_is_exact_success_only_and_precedes_aws(self):
        ci_index, ci = named_step(
            self.steps, "Require successful exact-main CI before AWS authentication"
        )
        aws_index = next(
            index
            for index, step in enumerate(self.steps)
            if str(step.get("uses", "")).startswith(
                "aws-actions/configure-aws-credentials@"
            )
        )
        mutation_index, _ = named_step(
            self.steps, "Journal ownership and prove the version is unused"
        )
        self.assertLess(ci_index, aws_index)
        self.assertLess(aws_index, mutation_index)
        self.assertEqual(ci["env"], {"GH_TOKEN": "${{ github.token }}"})
        self.assertEqual(
            self.value["permissions"],
            {"actions": "read", "contents": "read", "id-token": "write"},
        )
        passing = {
            "workflow_runs": [
                {
                    "head_sha": "a" * 40,
                    "head_branch": "main",
                    "event": "push",
                    "conclusion": "success",
                }
            ]
        }
        self.assertEqual(self.run_ci_attestation(passing).returncode, 0)
        for field, replacement in (
            ("head_sha", "b" * 40),
            ("head_branch", "feature"),
            ("event", "pull_request"),
            ("conclusion", "failure"),
        ):
            value = json.loads(json.dumps(passing))
            value["workflow_runs"][0][field] = replacement
            with self.subTest(field=field):
                self.assertNotEqual(self.run_ci_attestation(value).returncode, 0)
        self.assertNotEqual(
            self.run_ci_attestation({"workflow_runs": []}).returncode, 0
        )

    def test_exact_aws_account_is_checked_before_candidate_mutation(self):
        account_index, account = named_step(
            self.steps, "Verify the deployed release-control IAM contract"
        )
        mutation_index, _ = named_step(
            self.steps, "Journal ownership and prove the version is unused"
        )
        self.assertLess(account_index, mutation_index)
        self.assertEqual(
            account["env"]["EXPECTED_AWS_ACCOUNT_ID"], "${{ vars.AWS_ACCOUNT_ID }}"
        )
        self.assertEqual(
            account["env"]["EXPECTED_CALLER_ROLE_ARN"],
            "${{ vars.AWS_CANDIDATE_ROLE_ARN }}",
        )
        self.assertIn("release/verify_release_control_plane.py", account["run"])
        self.assertIn(
            '--expected-account-id "$EXPECTED_AWS_ACCOUNT_ID"', account["run"]
        )
        self.assertIn(
            '--expected-caller-role-arn "$EXPECTED_CALLER_ROLE_ARN"', account["run"]
        )
        self.assertIn("release/verify_release_buckets.py", account["run"])

    def run_ami_prefix(self, verified: bool) -> tuple[subprocess.CompletedProcess, str]:
        _, step = named_step(self.steps, "Build and copy private candidate AMIs")
        prefix = step["run"].split('artifact_id="', 1)[0]
        prefix = prefix.replace(
            "${{ steps.inputs.outputs.bridgefu_commit }}", "a" * 40
        ).replace("${{ steps.inputs.outputs.bridgefu_lock }}", "b" * 64)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "image").mkdir()
            (root / "target" / "candidate").mkdir(parents=True)
            (root / "image" / "build-inputs.json").write_text(
                (ROOT / "image" / "build-inputs.json").read_text()
            )
            packer_arguments = root / "packer-arguments"
            executable(
                root / "python",
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'test "$*" = "release/ami_build_inputs.py --inputs '
                'image/build-inputs.json --verify-source-ami"\n'
                "printf '%s\\n' "
                f'\'{{"schema_version":1,"verified":{str(verified).lower()},'
                '"redacted":true,"source_ami_id":"ami-098176c88d53db397"}\'\n',
            )
            executable(
                root / "packer",
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'if [[ "$1" = version ]]; then echo "Packer v1.12.0"; exit 0; fi\n'
                'if [[ "$1 $2" = "plugins installed" ]]; then\n'
                '  echo "/tmp/packer-plugin-amazon_v1.3.9_x5.0_linux_arm64"\n'
                "  exit 0\n"
                "fi\n"
                'if [[ "$1 $2" = "plugins install" ]]; then exit 0; fi\n'
                'printf "%s\\n" "$*" >> "$PACKER_ARGUMENTS"\n',
            )
            executable(
                root / "uname",
                "#!/usr/bin/env bash\n"
                'if [[ "$1" = -s ]]; then echo Linux; else echo aarch64; fi\n',
            )
            executable(
                root / "curl",
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "while (( $# > 0 )); do\n"
                '  if [[ "$1" = --output ]]; then : > "$2"; exit 0; fi\n'
                "  shift\n"
                "done\n"
                "exit 2\n",
            )
            executable(
                root / "sha256sum",
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'if [[ "$1" = --check ]]; then cat >/dev/null; exit 0; fi\n'
                "exit 2\n",
            )
            executable(
                root / "unzip",
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'test "$1" = -q\n'
                'test "$4" = -d\n'
                'mkdir -p "$5"\n'
                ': > "$5/$3"\n',
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{root}:{environment['PATH']}",
                    "PACKER_ARGUMENTS": str(packer_arguments),
                    "CANDIDATE_ID": "candidate-0.1.20-abcdef123456-12345-1",
                    "GITHUB_SHA": "c" * 40,
                    "VERSION": "0.1.20",
                }
            )
            result = subprocess.run(
                ["bash", "-c", prefix],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
                cwd=root,
                timeout=10,
            )
            captured = packer_arguments.read_text() if packer_arguments.exists() else ""
            return result, captured

    def test_verified_ami_input_and_exact_source_id_gate_packer(self):
        _, step = named_step(self.steps, "Build and copy private candidate AMIs")
        script = step["run"]
        verification = "python release/ami_build_inputs.py"
        source = 'source_base_ami="$(jq -r .source_ami.id image/build-inputs.json)"'
        plugin_hash = "sha256sum --check --strict"
        plugin_install = "packer plugins install --path"
        initialization = "packer init image/bridgefu.pkr.hcl"
        build = "packer build"
        self.assertLess(script.index(verification), script.index(source))
        self.assertLess(script.index(source), script.index(plugin_hash))
        self.assertLess(script.index(plugin_hash), script.index(plugin_install))
        self.assertLess(script.index(plugin_install), script.index(initialization))
        self.assertLess(script.index(initialization), script.index(build))
        self.assertIn("--verify-source-ami", script)
        self.assertIn("packer_plugin_platform=linux_arm64", script)
        self.assertIn("amazon_plugin_zip_sha256", script)
        self.assertIn(
            "github.com/hashicorp/packer-plugin-amazon/releases/download", script
        )
        self.assertIn('-var source_ami_id="$source_base_ami"', script)

        success, arguments = self.run_ami_prefix(True)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(arguments.count("init image/bridgefu.pkr.hcl"), 1)
        self.assertEqual(arguments.count("build "), 1)
        self.assertIn(
            "-var source_ami_id=ami-098176c88d53db397",
            arguments,
        )

        rejected, arguments = self.run_ami_prefix(False)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertEqual(arguments, "")


if __name__ == "__main__":
    unittest.main()
