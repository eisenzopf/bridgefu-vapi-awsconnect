from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def load(name: str) -> dict:
    value = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{name} is not a workflow mapping")
    return value


class ReleaseWorkflowHardeningTests(unittest.TestCase):
    def test_reaper_executes_only_trusted_event_revision_on_main(self):
        workflow = load("release-reaper.yml")
        source = (WORKFLOWS / "release-reaper.yml").read_text(encoding="utf-8")
        first_job = workflow["jobs"]["delete-cancelled-qualification-stacks"]
        checkout = next(
            step
            for step in first_job["steps"]
            if "actions/checkout@" in step.get("uses", "")
        )
        self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")
        self.assertNotIn("workflow_run.head_sha", checkout["with"]["ref"])
        self.assertIn(
            "github.event.workflow_run.head_branch == 'main'", first_job["if"]
        )
        for job in workflow["jobs"].values():
            self.assertIn("github.ref == 'refs/heads/main'", job["if"])
            self.assertEqual(job["runs-on"], "ubuntu-24.04")
            self.assertLess(job["timeout-minutes"], 180)
            credential = next(
                step
                for step in job["steps"]
                if "aws-actions/configure-aws-credentials@" in step.get("uses", "")
            )
            self.assertEqual(credential["with"]["role-duration-seconds"], 10800)
        self.assertIn(
            "run_with_recovery_deadline",
            (ROOT / "release/reap_qualification.sh").read_text(),
        )
        self.assertNotRegex(
            source,
            r"actions/checkout[^\n]*\n(?:.*\n){0,5}.*ref:.*workflow_run\.head_sha",
        )

    def test_all_github_hosted_runners_are_immutable_os_labels(self):
        for path in WORKFLOWS.glob("*.yml"):
            source = path.read_text(encoding="utf-8")
            with self.subTest(workflow=path.name):
                self.assertNotIn("runs-on: ubuntu-latest", source)
                for label in re.findall(r"runs-on:\s*([^\s]+)", source):
                    self.assertIn(label, {"ubuntu-24.04", "ubuntu-24.04-arm"})

    def test_partial_candidate_reruns_fail_before_cloud_mutation(self):
        workflow = load("candidate.yml")
        build = workflow["jobs"]["build-private-candidate"]
        self.assertEqual(
            build["outputs"]["originating_attempt"],
            "${{ steps.inputs.outputs.originating_attempt }}",
        )
        for name in ("qualify-oregon", "qualify-virginia", "seal-qualified-receipt"):
            first = workflow["jobs"][name]["steps"][0]
            self.assertEqual(first["name"], "Reject a partial workflow rerun")
            self.assertIn(
                'test "$GITHUB_RUN_ATTEMPT" = "$ORIGINATING_ATTEMPT"', first["run"]
            )

        remote = load("remote-qualification.yml")["jobs"]
        self.assertEqual(
            remote["sip-client"]["outputs"]["originating_attempt"],
            "${{ steps.origin.outputs.attempt }}",
        )
        first = remote["qualify"]["steps"][0]
        self.assertEqual(first["name"], "Reject a partial workflow rerun")
        self.assertIn(
            'test "$GITHUB_RUN_ATTEMPT" = "$ORIGINATING_ATTEMPT"', first["run"]
        )
        self.assertLess(remote["sip-client"]["timeout-minutes"], 180)

    def test_sessions_are_refreshed_immediately_before_mutation_contracts(self):
        candidate = load("candidate.yml")["jobs"]
        for job_name, region in (
            ("qualify-oregon", "Oregon"),
            ("qualify-virginia", "Virginia"),
        ):
            names = [step.get("name") for step in candidate[job_name]["steps"]]
            auth = names.index(f"Acquire fresh {region} qualification AWS session")
            verify = names.index(
                f"Verify {region} qualification control-plane bindings"
            )
            smoke = names.index(
                f"Run both {region} live smoke paths and prove teardown"
            )
            self.assertEqual((verify, smoke), (auth + 1, auth + 2))
        remote = [
            step.get("name")
            for step in load("remote-qualification.yml")["jobs"]["qualify"]["steps"]
        ]
        self.assertEqual(
            remote.index("Verify live qualification control-plane bindings"),
            remote.index("Acquire a fresh qualification AWS session for mutation") + 1,
        )
        self.assertEqual(
            remote.index("Run both live smoke paths and prove teardown"),
            remote.index("Verify live qualification control-plane bindings") + 1,
        )
        release = [
            step.get("name")
            for step in load("release.yml")["jobs"][
                "publish-exact-qualified-candidate"
            ]["steps"]
        ]
        auth = release.index(
            "Acquire a fresh publisher session for the publication mutation"
        )
        self.assertEqual(
            release[auth : auth + 3],
            [
                "Acquire a fresh publisher session for the publication mutation",
                "Reverify publisher AWS account and role before mutation",
                "Journal cancellation-safe publication ownership",
            ],
        )

    def test_all_python_install_inputs_are_hash_locked(self):
        sources = "\n".join(path.read_text() for path in WORKFLOWS.glob("*.yml"))
        for line in sources.splitlines():
            if "pip install" in line:
                self.assertIn("--require-hashes", line)
        self.assertIn("release/requirements-validation.lock", sources)
        self.assertIn("qualification/requirements-runner.lock", sources)
        for lock in (
            ROOT / "release/requirements-validation.lock",
            ROOT / "qualification/requirements-runner.lock",
        ):
            content = lock.read_text(encoding="utf-8")
            self.assertIn("--hash=sha256:", content)
            self.assertNotRegex(content, r"(?m)^[A-Za-z0-9_.-]+==[^\\\n]+$")

    def test_publication_is_not_complete_until_anonymous_hash_verification(self):
        source = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")
        anonymous = source.index("Verify exact public bytes without AWS credentials")
        verifier = source.index("release/verify_public_release.py", anonymous)
        complete = source.index(".publication_complete = true")
        self.assertLess(anonymous, verifier)
        self.assertLess(verifier, complete)
        for name in (
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_WEB_IDENTITY_TOKEN_FILE",
        ):
            self.assertIn(f"{name}: ''", source[anonymous:complete])

    def test_versioned_release_receipt_can_be_published_by_exact_version(self):
        source = (ROOT / "publisher" / "oidc-role.yaml").read_text(encoding="utf-8")
        policy = source[
            source.index("- Sid: PublishSignedReceiptAlongsideRelease") : source.index(
                "- Sid: ManageMutableLatestPointers"
            )
        ]
        self.assertIn("s3:PutObjectVersionTagging", policy)
        self.assertIn("/releases/*/qualification/receipt.json", policy)
        self.assertIn("/releases/*/qualification/receipt.sig", policy)


if __name__ == "__main__":
    unittest.main()
