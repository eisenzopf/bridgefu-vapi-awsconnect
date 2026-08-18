from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "release" / "ami_cache.py"
SPEC = importlib.util.spec_from_file_location("ami_cache", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("AMI cache verifier could not be imported")
SUBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUBJECT)


class AmiCacheTests(unittest.TestCase):
    def cache_documents(self):
        build = "a" * 64
        account = "123456789012"
        commit = "b" * 40
        version = "0.1.22"
        tags = [
            {
                "Key": "Name",
                "Value": "bridgefu-vapi-awsconnect-build-aaaaaaaaaaaaaaaa",
            },
            {"Key": "ManagedBy", "Value": "bridgefu-vapi-awsconnect"},
            {
                "Key": "BridgefuAmiBuildCache",
                "Value": "bridgefu-ami-cache-v1",
            },
            {"Key": "BridgefuAmiBuildSha256", "Value": build},
            {"Key": "BridgefuCommit", "Value": commit},
            {"Key": "BridgefuReleaseInput", "Value": version},
            {"Key": "BridgefuRvoipVersion", "Value": "0.3.8"},
        ]
        image = {
            "Images": [
                {
                    "ImageId": "ami-0123456789abcdef0",
                    "OwnerId": account,
                    "Architecture": "arm64",
                    "State": "available",
                    "RootDeviceType": "ebs",
                    "VirtualizationType": "hvm",
                    "Tags": tags,
                    "BlockDeviceMappings": [
                        {"Ebs": {"SnapshotId": "snap-0123456789abcdef0"}}
                    ],
                }
            ]
        }
        snapshot = {
            "Snapshots": [
                {
                    "SnapshotId": "snap-0123456789abcdef0",
                    "OwnerId": account,
                    "State": "completed",
                    "Encrypted": False,
                    "Tags": tags[1:],
                }
            ]
        }
        return {
            "image_document": image,
            "image_permissions": {"LaunchPermissions": []},
            "snapshot_document": snapshot,
            "snapshot_permissions": {"CreateVolumePermissions": []},
            "account_id": account,
            "build_sha256": build,
            "bridgefu_commit": commit,
            "release_version": version,
        }

    def test_content_digest_is_deterministic_and_version_bound(self):
        first = SUBJECT.content_manifest(ROOT, "0.1.22")
        second = SUBJECT.content_manifest(ROOT, "0.1.22")
        other_version = SUBJECT.content_manifest(ROOT, "0.1.23")
        self.assertEqual(first, second)
        self.assertNotEqual(
            first["ami_build_sha256"], other_version["ami_build_sha256"]
        )
        self.assertEqual(first["schema"], "bridgefu-ami-content/v1")
        self.assertTrue(first["redacted"])
        self.assertEqual(
            {item["path"] for item in first["inputs"]},
            {
                "bridgefu.lock.json",
                "image/bridgefu.pkr.hcl",
                "image/build-inputs.json",
                "image/install.sh",
                *{
                    path.relative_to(ROOT).as_posix()
                    for path in (ROOT / "image" / "runtime").iterdir()
                    if path.is_file()
                },
            },
        )

    def test_content_digest_rejects_unreadable_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "image" / "runtime").mkdir(parents=True)
            for relative in SUBJECT.FIXED_INPUTS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x", encoding="utf-8")
            (root / "image" / "runtime" / "one").write_text("x")
            (root / "bridgefu.lock.json").write_text(json.dumps({"commit": "bad"}))
            with self.assertRaises(SUBJECT.AmiCacheError):
                SUBJECT.content_manifest(root, "0.1.22")

    def test_exact_private_cache_is_accepted(self):
        result = SUBJECT.verify_cache(**self.cache_documents())
        self.assertTrue(result["verified"])
        self.assertTrue(result["private"])
        self.assertEqual(result["ami_id"], "ami-0123456789abcdef0")

    def test_public_foreign_or_candidate_cache_is_rejected(self):
        cases = []
        public_image = self.cache_documents()
        public_image["image_permissions"] = {"LaunchPermissions": [{"Group": "all"}]}
        cases.append(public_image)
        public_snapshot = self.cache_documents()
        public_snapshot["snapshot_permissions"] = {
            "CreateVolumePermissions": [{"Group": "all"}]
        }
        cases.append(public_snapshot)
        candidate = self.cache_documents()
        candidate["image_document"]["Images"][0]["Tags"].append(
            {"Key": "BridgefuCandidateId", "Value": "candidate-foreign"}
        )
        cases.append(candidate)
        foreign = self.cache_documents()
        foreign["image_document"]["Images"][0]["OwnerId"] = "000000000000"
        cases.append(foreign)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(SUBJECT.AmiCacheError):
                SUBJECT.verify_cache(**copy.deepcopy(value))


if __name__ == "__main__":
    unittest.main()
