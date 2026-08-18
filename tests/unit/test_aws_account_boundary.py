from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow(name: str) -> dict:
    return yaml.safe_load(
        (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
    )


class AwsAccountBoundaryTests(unittest.TestCase):
    def test_publication_checks_exact_account_before_bucket_derivation(self):
        data = workflow("release.yml")
        steps = data["jobs"]["publish-exact-qualified-candidate"]["steps"]
        step = next(
            item
            for item in steps
            if item.get("name")
            == "Resolve tag and download its immutable qualified receipt"
        )
        self.assertEqual(
            step["env"]["EXPECTED_AWS_ACCOUNT_ID"], "${{ vars.AWS_ACCOUNT_ID }}"
        )
        run = step["run"]
        identity = run.index('account_id="$(aws sts get-caller-identity')
        boundary = run.index('test "$account_id" = "$EXPECTED_AWS_ACCOUNT_ID"')
        bucket = run.index(
            'east_bucket="bridgefu-vapi-awsconnect-$account_id-us-east-1"'
        )
        self.assertLess(identity, boundary)
        self.assertLess(boundary, bucket)

    def test_every_recovery_job_checks_exact_account(self):
        data = workflow("release-reaper.yml")
        jobs = data["jobs"]
        self.assertEqual(
            set(jobs),
            {
                "prune-expired-private-ami-cache",
                "delete-cancelled-qualification-stacks",
                "delete-failed-private-candidate",
                "rollback-interrupted-publication",
            },
        )
        for job_name, job in jobs.items():
            with self.subTest(job=job_name):
                steps = job["steps"]
                credential_index = next(
                    index
                    for index, step in enumerate(steps)
                    if str(step.get("uses", "")).startswith(
                        "aws-actions/configure-aws-credentials@"
                    )
                )
                boundary_index = next(
                    index
                    for index, step in enumerate(steps)
                    if step.get("name") == "Verify recovery control-plane bindings"
                )
                mutation_index = next(
                    index
                    for index, step in enumerate(steps)
                    if index > boundary_index and "run" in step
                )
                self.assertLess(credential_index, boundary_index)
                self.assertLess(boundary_index, mutation_index)
                boundary = steps[boundary_index]
                self.assertEqual(
                    boundary["env"]["EXPECTED_AWS_ACCOUNT_ID"],
                    "${{ vars.AWS_ACCOUNT_ID }}",
                )
                self.assertEqual(
                    boundary["env"]["EXPECTED_RECOVERY_ROLE_ARN"],
                    "${{ vars.AWS_RECOVERY_ROLE_ARN }}",
                )
                self.assertIn(
                    "release/verify_release_control_plane.py", boundary["run"]
                )
                self.assertIn(
                    '--expected-account-id "$EXPECTED_AWS_ACCOUNT_ID"',
                    boundary["run"],
                )
                self.assertIn(
                    '--expected-caller-role-arn "$EXPECTED_RECOVERY_ROLE_ARN"',
                    boundary["run"],
                )


if __name__ == "__main__":
    unittest.main()
