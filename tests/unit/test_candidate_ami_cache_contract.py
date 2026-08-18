from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class CandidateAmiCacheContractTests(unittest.TestCase):
    def setUp(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        self.build = workflow.split(
            "      - name: Build and copy private candidate AMIs\n", 1
        )[1].split("\n      - name:", 1)[0]
        self.packer = (ROOT / "image" / "bridgefu.pkr.hcl").read_text()

    def test_cache_hit_is_verified_before_any_candidate_copy(self):
        digest = "python release/ami_cache.py digest"
        lookup = "Name=tag:BridgefuAmiBuildSha256,Values=$ami_build_sha256"
        verifier = "python release/ami_cache.py verify"
        verification_call = 'verify_cache_ami "$cache_ami"'
        copy = 'source_ami="$(aws ec2 copy-image --region us-west-2'
        self.assertIn(digest, self.build)
        self.assertIn(lookup, self.build)
        self.assertIn('test "$cache_count" -le 1', self.build)
        self.assertIn(verifier, self.build)
        self.assertLess(self.build.index(digest), self.build.index(lookup))
        self.assertLess(self.build.index(lookup), self.build.index(verification_call))
        self.assertLess(self.build.index(verification_call), self.build.index(copy))
        self.assertIn('if [[ "$cache_count" = 1 ]]', self.build)
        self.assertIn("else\n            echo \"No exact AMI build cache", self.build)
        self.assertIn("packer build", self.build)
        self.assertIn('verify_cache_ami "$cache_ami"', self.build)

    def test_cache_and_candidate_have_disjoint_ownership(self):
        for tag in (
            "BridgefuAmiBuildCache",
            "BridgefuAmiBuildSha256",
            "BridgefuReleaseInput",
        ):
            self.assertIn(tag, self.packer)
        for tag in (
            "BridgefuCandidateId",
            "BridgefuRepositoryCommit",
        ):
            self.assertNotIn(tag, self.packer)
            self.assertIn(tag, self.build)
        self.assertNotIn("BridgefuRelease          =", self.packer)
        self.assertIn("BridgefuRelease", self.build)
        self.assertIn('--source-image-id "$cache_ami"', self.build)
        self.assertIn('--tag-specifications "$candidate_tag_specifications"', self.build)
        self.assertIn("journal_ami us-west-2 \"$source_ami\" '[]'", self.build)
        self.assertNotIn("journal_ami us-west-2 \"$cache_ami\"", self.build)

    def test_compiler_cache_never_receives_aws_credentials(self):
        self.assertNotIn("sccache", self.build.lower())
        self.assertNotIn("AWS_ACCESS_KEY_ID", self.packer)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", self.packer)
        self.assertNotIn("AWS_SESSION_TOKEN", self.packer)
        self.assertNotIn("instance_profile", self.packer)


if __name__ == "__main__":
    unittest.main()
