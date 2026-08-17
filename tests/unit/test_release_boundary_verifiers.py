from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from release import verify_candidate_receipt as candidate
from release import verify_public_release as public
from release import verify_qualification_relations as relations
from release import verify_release_buckets as buckets
from release import verify_release_control_plane as control


class FakeResponse:
    def __init__(self, url: str, content: bytes, status: int = 200):
        self.status = status
        self._url = url
        self._content = content

    def read(self, amount: int = -1) -> bytes:
        return self._content if amount < 0 else self._content[:amount]

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class FakeOpener:
    def __init__(self, content: bytes):
        self.content = content
        self.urls: list[str] = []

    def open(self, url: str, timeout: float) -> FakeResponse:
        self.urls.append(url)
        if timeout != 30.0:
            raise AssertionError("unexpected timeout")
        return FakeResponse(url, self.content)


def object_record(key: str, content: bytes) -> dict[str, Any]:
    return {
        "region": "us-east-1",
        "bucket": "bridgefu-vapi-awsconnect-123456789012-us-east-1",
        "key": key,
        "version_id": f"version-{key.replace('/', '-')}",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
    }


class PublicReleaseVerifierTests(unittest.TestCase):
    def test_anonymous_exact_versions_and_unversioned_latest_are_required(self):
        content = b"verified-public-bytes"
        receipt = {
            "schema": "bridgefu-qualified-candidate-receipt/v1",
            "release_objects": [object_record("releases/1.2.3/manifest.json", content)],
        }
        state = {
            "schema": "bridgefu-publication-state/v1",
            "release_receipt_objects": [
                object_record("releases/1.2.3/qualification/receipt.json", content)
            ],
            "latest_objects": [object_record("latest/manifest.json", content)],
        }
        opener = FakeOpener(content)
        with mock.patch.dict(os.environ, {}, clear=True):
            result = public.verify(receipt, state, opener)
        self.assertEqual(result["exact_version_downloads"], 3)
        self.assertEqual(result["unversioned_latest_downloads"], 1)
        self.assertEqual(len(opener.urls), 4)
        self.assertEqual(sum("?versionId=" in url for url in opener.urls), 3)
        self.assertEqual(sum("?versionId=" not in url for url in opener.urls), 1)

    def test_credentials_or_tampered_bytes_fail_closed(self):
        content = b"expected"
        receipt = {
            "schema": "bridgefu-qualified-candidate-receipt/v1",
            "release_objects": [object_record("releases/1/a", content)],
        }
        state = {
            "schema": "bridgefu-publication-state/v1",
            "release_receipt_objects": [object_record("releases/1/b", content)],
            "latest_objects": [object_record("latest/a", content)],
        }
        with mock.patch.dict(
            os.environ, {"AWS_ACCESS_KEY_ID": "not-anonymous"}, clear=True
        ):
            with self.assertRaises(public.PublicReleaseError):
                public.verify(receipt, state, FakeOpener(content))
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(public.PublicReleaseError):
                public.verify(receipt, state, FakeOpener(b"tampered"))


class FakeBucketCli:
    def __init__(self, *, block_public_policy: bool = False):
        self.block_public_policy = block_public_policy

    def json(self, *arguments: str, absent_ok: bool = False) -> Any:
        del absent_ok
        operation = arguments[:2]
        if operation == ("sts", "get-caller-identity"):
            return {
                "Account": "123456789012",
                "Arn": "arn:aws:sts::123456789012:assumed-role/release/session",
            }
        if operation == ("s3control", "get-public-access-block"):
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": self.block_public_policy,
                    "RestrictPublicBuckets": False,
                }
            }
        bucket = arguments[arguments.index("--bucket") + 1]
        region = (
            bucket.rsplit("-", 3)[-3]
            + "-"
            + bucket.rsplit("-", 3)[-2]
            + "-"
            + bucket.rsplit("-", 3)[-1]
        )
        if operation == ("s3api", "get-bucket-location"):
            return {"LocationConstraint": None if region == "us-east-1" else region}
        if operation == ("s3api", "get-bucket-versioning"):
            return {"Status": "Enabled"}
        if operation == ("s3api", "get-bucket-encryption"):
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                }
            }
        if operation == ("s3api", "get-bucket-ownership-controls"):
            return {
                "OwnershipControls": {
                    "Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]
                }
            }
        if operation == ("s3api", "get-public-access-block"):
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            }
        if operation == ("s3api", "get-bucket-policy"):
            return {"Policy": json.dumps(buckets._expected_policy(bucket, "aws"))}
        raise AssertionError(arguments)


class ReleaseBucketVerifierTests(unittest.TestCase):
    def test_live_bucket_contract_and_account_public_block(self):
        args = argparse.Namespace(
            expected_account_id="123456789012",
            bucket_prefix="bridgefu-vapi-awsconnect",
            regions_file=Path(__file__).resolve().parents[2]
            / "release"
            / "regions.json",
        )
        result = buckets.verify(args, FakeBucketCli())
        self.assertEqual(result["regions_verified"], ["us-east-1", "us-west-2"])
        with self.assertRaises(buckets.BucketContractError):
            buckets.verify(args, FakeBucketCli(block_public_policy=True))

    def test_extra_public_policy_statement_is_rejected(self):
        policy = buckets._expected_policy("safe-bucket", "aws")
        policy["Statement"].append(
            {
                "Sid": "UnexpectedPublicRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::safe-bucket/candidates/*",
                "Condition": {},
            }
        )
        with self.assertRaises(buckets.BucketContractError):
            buckets._verify_policy(policy, "safe-bucket", "aws")

    def test_duplicate_sid_cannot_hide_an_extra_public_statement(self):
        policy = buckets._expected_policy("safe-bucket", "aws")
        policy["Statement"].insert(
            0,
            {
                "Sid": "PublicQualifiedReleaseRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::safe-bucket/candidates/*",
                "Condition": {},
            },
        )
        with self.assertRaises(buckets.BucketContractError):
            buckets._verify_policy(policy, "safe-bucket", "aws")


class FakeIdentityCli:
    def __init__(self, user_id: str):
        self.user_id = user_id

    def json(self, *arguments: str) -> Any:
        if arguments[:2] != ("iam", "get-role"):
            raise AssertionError(arguments)
        return {
            "Role": {
                "Arn": "arn:aws:iam::123456789012:role/ExactRole",
                "RoleId": "AROAEXACTROLEID",
            }
        }


class ReleaseControlPlaneVerifierTests(unittest.TestCase):
    def test_sts_role_id_not_just_role_name_is_bound(self):
        identity = {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/ExactRole/session",
            "UserId": "AROAEXACTROLEID:session",
        }
        result = control._verify_role_identity(
            FakeIdentityCli(identity["UserId"]),
            identity,
            "arn:aws:iam::123456789012:role/ExactRole",
            "123456789012",
        )
        self.assertEqual(result["RoleId"], "AROAEXACTROLEID")
        forged = {**identity, "UserId": "AROADIFFERENT:session"}
        with self.assertRaises(control.ControlPlaneError):
            control._verify_role_identity(
                FakeIdentityCli(forged["UserId"]),
                forged,
                "arn:aws:iam::123456789012:role/ExactRole",
                "123456789012",
            )


class QualificationRelationVerifierTests(unittest.TestCase):
    def test_span_and_all_cross_artifact_relations_are_recomputed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ami = "ami-0123456789abcdef0"
            image_hash = hashlib.sha256(ami.encode()).hexdigest()
            execution = "bfq-w-123-1"
            counts = {key: 0 for key in relations.ZERO_RESOURCE_KEYS}
            proof = {
                "execution_id": execution,
                "required_observations": 3,
                "minimum_span_seconds": 60,
                "observations": [
                    {"observed_at": stamp, "resource_counts": counts, "redacted": True}
                    for stamp in (
                        "2026-08-17T00:00:10Z",
                        "2026-08-17T00:00:40Z",
                        "2026-08-17T00:01:10Z",
                    )
                ],
                "proven_at": "2026-08-17T00:01:11Z",
            }
            proof_path = root / "proof.json"
            proof_path.write_text(json.dumps(proof, separators=(",", ":")))
            proof_hash = hashlib.sha256(proof_path.read_bytes()).hexdigest()
            evidence = {
                "schema_version": 2,
                "release": "1.2.3",
                "bridgefu_commit": "a" * 40,
                "region": "us-west-2",
                "execution_id": execution,
                "started_at": "2026-08-17T00:00:00Z",
                "ended_at": "2026-08-17T00:01:13Z",
                "preflight": {
                    "execution_id": execution,
                    "region": "us-west-2",
                    "runtime_image_sha256": image_hash,
                    "instance_type": "c7g.2xlarge",
                    "vcpus": 8,
                    "memory_mib": 16384,
                },
                "runtime_deployment": {
                    "execution_id": execution,
                    "region": "us-west-2",
                    "runtime_image_sha256": image_hash,
                    "instance_type": "c7g.2xlarge",
                },
                "deployment_review": {"root_invocation_sha256": "b" * 64},
                "scenarios": [
                    {
                        "active_call_telemetry": {
                            "execution_id": execution,
                            "instance_type": "c7g.2xlarge",
                            "vcpus": 8,
                            "memory_mib": 16384,
                        }
                    }
                    for _ in range(2)
                ],
                "zero_resource_proof_sha256": proof_hash,
            }
            zero = {
                "execution_id": execution,
                "observed_at": "2026-08-17T00:01:12Z",
                "zero_resource_proof_sha256": proof_hash,
            }
            evidence_path, zero_path, regions_path = (
                root / "evidence.json",
                root / "zero.json",
                root / "regions.json",
            )
            evidence_path.write_text(json.dumps(evidence))
            zero_path.write_text(json.dumps(zero))
            regions_path.write_text(json.dumps({"us-west-2": {"ami_id": ami}}))
            args = argparse.Namespace(
                evidence=evidence_path,
                zero_state=zero_path,
                zero_resource_proof=proof_path,
                region_release=regions_path,
                release="1.2.3",
                bridgefu_commit="a" * 40,
                region="us-west-2",
                expected_execution_id=execution,
            )
            result = relations.verify(args)
            self.assertEqual(result["zero_observation_span_seconds"], 60)
            proof["observations"][-1]["observed_at"] = "2026-08-17T00:01:09Z"
            proof_path.write_text(json.dumps(proof, separators=(",", ":")))
            changed_hash = hashlib.sha256(proof_path.read_bytes()).hexdigest()
            evidence["zero_resource_proof_sha256"] = changed_hash
            zero["zero_resource_proof_sha256"] = changed_hash
            evidence_path.write_text(json.dumps(evidence))
            zero_path.write_text(json.dumps(zero))
            with self.assertRaises(relations.RelationError):
                relations.verify(args)


class CandidateReceiptVerifierTests(unittest.TestCase):
    def _fixture(self, root: Path, *, span_seconds: int) -> argparse.Namespace:
        release = "1.2.3"
        bridgefu_commit = "a" * 40
        run_id, run_attempt = 123, 1
        amis = {
            "us-west-2": "ami-0123456789abcdef0",
            "us-east-1": "ami-fedcba9876543210a",
        }
        receipt: dict[str, Any] = {
            "schema": "bridgefu-qualified-candidate-receipt/v1",
            "version": release,
            "bridgefu_commit": bridgefu_commit,
            "qualified_at": "2026-08-17T00:02:00Z",
            "workflow": {"run_id": run_id, "run_attempt": run_attempt},
            "regional_amis": {
                region: {"ami_id": ami} for region, ami in amis.items()
            },
            "qualification": {},
            "release_objects": [],
        }
        for region, ami in amis.items():
            region_root = root / region
            region_root.mkdir(parents=True)
            prefix = "w" if region == "us-west-2" else "e"
            execution = f"bfq-{prefix}-{run_id}-{run_attempt}"
            image_hash = hashlib.sha256(ami.encode("ascii")).hexdigest()
            counts = {key: 0 for key in relations.ZERO_RESOURCE_KEYS}
            final_stamp = (
                "2026-08-17T00:01:10Z"
                if span_seconds == 60
                else "2026-08-17T00:01:09Z"
            )
            proof = {
                "execution_id": execution,
                "required_observations": 3,
                "minimum_span_seconds": 60,
                "observations": [
                    {
                        "observed_at": stamp,
                        "resource_counts": counts,
                        "redacted": True,
                    }
                    for stamp in (
                        "2026-08-17T00:00:10Z",
                        "2026-08-17T00:00:40Z",
                        final_stamp,
                    )
                ],
                "proven_at": "2026-08-17T00:01:11Z",
            }
            proof_path = region_root / "zero-resource-proof.json"
            proof_path.write_text(json.dumps(proof, separators=(",", ":")))
            proof_hash = hashlib.sha256(proof_path.read_bytes()).hexdigest()
            evidence = {
                "schema_version": 2,
                "release": release,
                "bridgefu_commit": bridgefu_commit,
                "region": region,
                "execution_id": execution,
                "started_at": "2026-08-17T00:00:00Z",
                "ended_at": "2026-08-17T00:01:13Z",
                "preflight": {
                    "execution_id": execution,
                    "region": region,
                    "runtime_image_sha256": image_hash,
                    "instance_type": "c7g.2xlarge",
                    "vcpus": 8,
                    "memory_mib": 16384,
                },
                "runtime_deployment": {
                    "execution_id": execution,
                    "region": region,
                    "runtime_image_sha256": image_hash,
                    "instance_type": "c7g.2xlarge",
                },
                "deployment_review": {"root_invocation_sha256": "b" * 64},
                "scenarios": [
                    {
                        "id": scenario,
                        "active_call_telemetry": {
                            "execution_id": execution,
                            "instance_type": "c7g.2xlarge",
                            "vcpus": 8,
                            "memory_mib": 16384,
                        },
                    }
                    for scenario in candidate.SCENARIOS
                ],
                "zero_resource_proof_sha256": proof_hash,
            }
            zero = {
                "execution_id": execution,
                "observed_at": "2026-08-17T00:01:12Z",
                "zero_resource_proof_sha256": proof_hash,
            }
            evidence_path = region_root / "evidence.json"
            zero_path = region_root / "zero-state.json"
            evidence_path.write_text(json.dumps(evidence, separators=(",", ":")))
            zero_path.write_text(json.dumps(zero, separators=(",", ":")))
            evidence_hash = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            zero_hash = hashlib.sha256(zero_path.read_bytes()).hexdigest()
            receipt["qualification"][region] = {
                "evidence_schema_version": 2,
                "evidence_sha256": evidence_hash,
                "execution_id": execution,
                "required_checks_passed": True,
                "root_invocation_sha256": "b" * 64,
                "runtime_image_sha256": image_hash,
                "scenario_ids": candidate.SCENARIOS,
                "secure_preflight_passed": True,
                "zero_resource_proof": True,
                "zero_resource_proof_sha256": proof_hash,
                "zero_state_sha256": zero_hash,
            }
            for name, content in (
                ("evidence.json", evidence_path.read_bytes()),
                ("zero-state.json", zero_path.read_bytes()),
                ("zero-resource-proof.json", proof_path.read_bytes()),
            ):
                receipt["release_objects"].append(
                    object_record(
                        f"releases/{release}/qualification/{region}/{name}",
                        content,
                    )
                )
        receipt_path = root / "receipt.json"
        receipt_path.write_text(json.dumps(receipt, separators=(",", ":")))
        return argparse.Namespace(
            receipt=receipt_path,
            qualification_root=root,
            release=release,
            bridgefu_commit=bridgefu_commit,
        )

    def test_receipt_recomputes_relations_and_zero_resource_span(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self._fixture(Path(directory), span_seconds=60)
            result = candidate.verify(args)
            self.assertTrue(result["qualification_relations_verified"])
        with tempfile.TemporaryDirectory() as directory:
            args = self._fixture(Path(directory), span_seconds=59)
            with self.assertRaises(candidate.ReceiptError):
                candidate.verify(args)


if __name__ == "__main__":
    unittest.main()
