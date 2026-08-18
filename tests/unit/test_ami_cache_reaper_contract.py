from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "prune_ami_cache.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "release-reaper.yml"


class AmiCacheReaperContractTests(unittest.TestCase):
    def test_reaper_is_syntax_valid_exact_and_bounded(self):
        text = SCRIPT.read_text()
        subprocess.run(["bash", "-n", SCRIPT], check=True)
        self.assertIn("max_age_seconds=$((14 * 24 * 60 * 60))", text)
        self.assertIn('test "$image_count" -le 25', text)
        self.assertIn('[[ "$build_sha256" = "$keep_build_sha256" ]]', text)
        self.assertIn("python release/ami_cache.py verify", text)
        self.assertLess(
            text.index("python release/ami_cache.py verify"),
            text.index("aws ec2 deregister-image"),
        )
        self.assertIn('--image-id "$ami_id"', text)
        self.assertIn('--snapshot-id "$snapshot_id"', text)
        self.assertNotIn("Name=tag:BridgefuRelease", text)
        self.assertNotIn("aws ec2 describe-images --owners self --region \"$region\"\n  >", text)

    def test_scheduled_reaper_uses_trusted_main_and_shared_mutex(self):
        value = yaml.safe_load(WORKFLOW.read_text())
        self.assertIn("schedule", value[True])
        self.assertIn("workflow_dispatch", value[True])
        job = value["jobs"]["prune-expired-private-ami-cache"]
        self.assertEqual(job["environment"], "release-recovery")
        self.assertIn("github.ref == 'refs/heads/main'", job["if"])
        checkout = job["steps"][0]
        self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")
        self.assertFalse(checkout["with"]["persist-credentials"])
        self.assertEqual(
            job["steps"][-1]["run"], "bash release/prune_ami_cache.sh"
        )
        self.assertIn(
            "bridgefu-vapi-awsconnect-qualification-mutation",
            value["concurrency"]["group"],
        )


if __name__ == "__main__":
    unittest.main()
