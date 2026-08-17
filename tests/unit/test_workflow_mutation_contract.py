import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github" / "workflows"
MUTATION_MUTEX = "bridgefu-vapi-awsconnect-qualification-mutation"
PINNED_WORKFLOWS = (
    "candidate.yml",
    "ci.yml",
    "release-reaper.yml",
    "release.yml",
    "remote-qualification.yml",
)
ACTION_USE = re.compile(r"(?m)^\s*- uses:\s+([^\s@]+)@([^\s#]+)(?:\s+#\s+(.+))?$")


def workflow(name: str) -> dict:
    value = yaml.safe_load((WORKFLOW_DIR / name).read_text())
    if not isinstance(value, dict):
        raise AssertionError(f"{name} is not a workflow mapping")
    return value


class WorkflowMutationContractTests(unittest.TestCase):
    def test_candidate_and_manual_qualification_share_one_constant_mutex(self):
        candidate = workflow("candidate.yml")["concurrency"]
        remote = workflow("remote-qualification.yml")["concurrency"]
        for concurrency in (candidate, remote):
            self.assertEqual(concurrency["group"], MUTATION_MUTEX)
            self.assertIs(concurrency["cancel-in-progress"], False)
            self.assertNotIn("inputs.", concurrency["group"])
            self.assertNotIn("github.run", concurrency["group"])

    def test_qualification_recovery_joins_mutex_while_publication_stays_separate(self):
        recovery = workflow("release-reaper.yml")
        concurrency = recovery["concurrency"]
        group = concurrency["group"]
        self.assertIs(concurrency["cancel-in-progress"], False)
        self.assertIn(
            "github.event.workflow_run.name == 'Publish qualified release'", group
        )
        self.assertIn(MUTATION_MUTEX, group)
        self.assertIn("bridgefu-vapi-awsconnect-publication-recovery", group)
        self.assertNotIn("workflow_run.id", group)
        self.assertEqual(
            recovery["jobs"]["rollback-interrupted-publication"]["concurrency"],
            {
                "group": "bridgefu-vapi-awsconnect-release",
                "cancel-in-progress": False,
            },
        )
        self.assertEqual(
            set(recovery[True]["workflow_run"]["workflows"]),
            {
                "Build and qualify private candidate",
                "Publish qualified release",
                "Remote live qualification",
            },
        )

    def test_release_and_qualification_actions_are_immutable_sha_pins(self):
        for name in PINNED_WORKFLOWS:
            source = (WORKFLOW_DIR / name).read_text()
            uses = ACTION_USE.findall(source)
            self.assertTrue(uses, name)
            for action, revision, annotation in uses:
                with self.subTest(workflow=name, action=action):
                    self.assertRegex(revision, r"^[0-9a-f]{40}$")
                    self.assertRegex(annotation, r"^v\d")

    def test_validation_tool_versions_are_exact(self):
        source = (WORKFLOW_DIR / "ci.yml").read_text()
        requirements = (ROOT / "release" / "requirements-validation.txt").read_text()
        lock = (ROOT / "release" / "requirements-validation.lock").read_text()
        self.assertIn("cfn-lint==1.54.0", requirements)
        self.assertIn("ruff==0.12.4", requirements)
        self.assertIn("cfn-lint==1.54.0 \\", lock)
        self.assertIn("ruff==0.12.4 \\", lock)
        self.assertIn("--require-hashes", source)
        self.assertIn("release/requirements-validation.lock", source)
        self.assertNotRegex(requirements, r"(?:cfn-lint|ruff)[><~]")
        for name in ("ci.yml", "candidate.yml"):
            candidate = (WORKFLOW_DIR / name).read_text()
            self.assertIn("with: {version: '1.12.0'}", candidate)
            self.assertNotIn("hashicorp/setup-packer@main", candidate)


if __name__ == "__main__":
    unittest.main()
