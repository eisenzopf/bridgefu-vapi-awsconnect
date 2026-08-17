#!/usr/bin/env python3
"""Executable contract tests for candidate credential lifetime boundaries."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "candidate.yml"
CONFIGURE_AWS = (
    "aws-actions/configure-aws-credentials@b47578312673ae6fa5b5096b330d9fbac3d116df"
)


def workflow() -> dict:
    return yaml.safe_load(WORKFLOW_PATH.read_text())


def named_step(job: dict, name: str) -> tuple[int, dict]:
    matches = [
        (index, step)
        for index, step in enumerate(job["steps"])
        if step.get("name") == name
    ]
    if len(matches) != 1:
        raise AssertionError(f"expected exactly one step named {name!r}")
    return matches[0]


class CandidateCredentialLifetimeTests(unittest.TestCase):
    def test_regions_are_explicit_jobs_and_virginia_requires_oregon(self):
        jobs = workflow()["jobs"]
        self.assertNotIn("qualify-regions-sequentially", jobs)
        self.assertEqual(jobs["qualify-oregon"]["needs"], "build-private-candidate")
        self.assertEqual(
            jobs["qualify-virginia"]["needs"],
            ["build-private-candidate", "qualify-oregon"],
        )
        self.assertLess(
            list(jobs).index("qualify-oregon"), list(jobs).index("qualify-virginia")
        )

    def test_each_region_has_one_fresh_session_and_a_shorter_job_timeout(self):
        jobs = workflow()["jobs"]
        for job_name, label, region in (
            ("qualify-oregon", "Oregon", "us-west-2"),
            ("qualify-virginia", "Virginia", "us-east-1"),
        ):
            job = jobs[job_name]
            self.assertGreater(job["timeout-minutes"], 0)
            self.assertLess(job["timeout-minutes"], 180)
            auth_steps = [
                (index, step)
                for index, step in enumerate(job["steps"])
                if step.get("uses", "").startswith(
                    "aws-actions/configure-aws-credentials@"
                )
            ]
            self.assertEqual(len(auth_steps), 1)
            auth_index, auth = auth_steps[0]
            self.assertEqual(auth["uses"], CONFIGURE_AWS)
            self.assertEqual(
                auth["name"], f"Acquire fresh {label} qualification AWS session"
            )
            self.assertEqual(auth["with"]["role-duration-seconds"], 10800)
            self.assertEqual(auth["with"]["aws-region"], region)
            self.assertEqual(
                job["steps"][auth_index + 1]["name"],
                f"Verify {label} qualification control-plane bindings",
            )
            self.assertEqual(
                job["steps"][auth_index + 2]["name"],
                f"Run both {label} live smoke paths and prove teardown",
            )

    def test_no_region_loop_shares_one_session(self):
        jobs = workflow()["jobs"]
        for job_name, label, region, other_region in (
            ("qualify-oregon", "Oregon", "us-west-2", "us-east-1"),
            ("qualify-virginia", "Virginia", "us-east-1", "us-west-2"),
        ):
            _, smoke = named_step(
                jobs[job_name], f"Run both {label} live smoke paths and prove teardown"
            )
            script = smoke["run"]
            self.assertNotIn("for REGION in", script)
            self.assertNotIn("while read -r region", script)
            self.assertEqual(script.count("qualification/controller.py run"), 1)
            controller = script.split("qualification/controller.py run", 1)[1]
            self.assertIn(f"--region {region}", controller)
            self.assertNotIn(f"--region {other_region}", controller)

    def test_candidate_session_is_refreshed_after_packer_before_staging(self):
        steps = workflow()["jobs"]["build-private-candidate"]["steps"]
        build_index, _ = named_step(
            {"steps": steps}, "Build and copy private candidate AMIs"
        )
        refresh_index, refresh = named_step(
            {"steps": steps}, "Refresh candidate AWS session after the AMI build"
        )
        staging_index, _ = named_step(
            {"steps": steps},
            "Build staged release assets and native qualification clients",
        )
        self.assertLess(build_index, refresh_index)
        self.assertLess(refresh_index, staging_index)
        self.assertEqual(refresh["uses"], CONFIGURE_AWS)
        self.assertEqual(refresh["with"]["role-duration-seconds"], 10800)
        self.assertEqual(refresh["with"]["aws-region"], "us-west-2")

    def test_seal_inputs_and_regional_artifact_names_are_unchanged(self):
        jobs = workflow()["jobs"]
        expected = {
            "qualify-oregon": (
                "qualification-us-west-2",
                "target/live-qualification-us-west-2",
            ),
            "qualify-virginia": (
                "qualification-us-east-1",
                "target/live-qualification-us-east-1",
            ),
        }
        for job_name, (artifact_name, artifact_path) in expected.items():
            uploads = [
                step
                for step in jobs[job_name]["steps"]
                if step.get("uses", "").startswith("actions/upload-artifact@")
            ]
            self.assertEqual(len(uploads), 1)
            self.assertEqual(uploads[0]["with"]["name"], artifact_name)
            self.assertEqual(uploads[0]["with"]["path"], artifact_path)

        seal = jobs["seal-qualified-receipt"]
        self.assertEqual(
            seal["needs"],
            ["build-private-candidate", "qualify-oregon", "qualify-virginia"],
        )
        downloads = {
            step["with"]["name"]: step["with"]["path"]
            for step in seal["steps"]
            if step.get("uses", "").startswith("actions/download-artifact@")
        }
        self.assertEqual(
            downloads,
            {
                "private-release-candidate": "target/candidate",
                "qualification-us-west-2": "target/qualification/us-west-2",
                "qualification-us-east-1": "target/qualification/us-east-1",
            },
        )


if __name__ == "__main__":
    unittest.main()
