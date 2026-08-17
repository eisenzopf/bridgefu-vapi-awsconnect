#!/usr/bin/env python3
"""Verify the live S3 publication boundary before any release mutation."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ACCOUNT = re.compile(r"^[0-9]{12}$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
SUPPORTED_REGIONS = ("us-east-1", "us-west-2")


class BucketContractError(RuntimeError):
    """The live release bucket boundary does not match the reviewed contract."""


class AwsCli:
    def json(self, *arguments: str, absent_ok: bool = False) -> Any:
        process = subprocess.run(
            ["aws", *arguments, "--output", "json"],
            check=False,
            capture_output=True,
            text=True,
        )
        if process.returncode != 0:
            if absent_ok and (
                "NoSuchPublicAccessBlockConfiguration" in process.stderr
                or "NoSuchConfiguration" in process.stderr
            ):
                return None
            raise BucketContractError(
                f"AWS bucket control-plane read failed: {' '.join(arguments[:2])}"
            )
        try:
            return json.loads(process.stdout)
        except json.JSONDecodeError as error:
            raise BucketContractError("AWS returned invalid bucket JSON") from error


def _canonical_statement(statement: Any) -> dict[str, Any]:
    if not isinstance(statement, Mapping) or set(statement) != {
        "Sid",
        "Effect",
        "Principal",
        "Action",
        "Resource",
        "Condition",
    }:
        raise BucketContractError("bucket policy statement shape changed")
    actions = statement["Action"]
    resources = statement["Resource"]
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    if not isinstance(actions, list) or not isinstance(resources, list):
        raise BucketContractError("bucket policy action or resource is invalid")
    return {
        "Sid": statement["Sid"],
        "Effect": statement["Effect"],
        "Principal": statement["Principal"],
        "Action": sorted(actions),
        "Resource": sorted(resources),
        "Condition": statement["Condition"],
    }


def _expected_policy(bucket: str, partition: str) -> dict[str, Any]:
    bucket_arn = f"arn:{partition}:s3:::{bucket}"
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicQualifiedReleaseRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                "Resource": [f"{bucket_arn}/releases/*", f"{bucket_arn}/latest/*"],
                "Condition": {
                    "StringEquals": {
                        "s3:ExistingObjectTag/bridgefu-publication-status": "published"
                    }
                },
            },
            {
                "Sid": "RequireTls",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            },
        ],
    }


def _verify_policy(value: Any, bucket: str, partition: str) -> None:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as error:
            raise BucketContractError("bucket policy is invalid JSON") from error
    if not isinstance(value, Mapping) or set(value) != {"Version", "Statement"}:
        raise BucketContractError("bucket policy document shape changed")
    statements = value.get("Statement")
    if value.get("Version") != "2012-10-17" or not isinstance(statements, list):
        raise BucketContractError("bucket policy version or statements changed")
    canonical_statements = list(map(_canonical_statement, statements))
    if any(not isinstance(statement["Sid"], str) for statement in canonical_statements):
        raise BucketContractError("bucket policy statement ID is invalid")
    actual = {statement["Sid"]: statement for statement in canonical_statements}
    if len(actual) != len(canonical_statements):
        raise BucketContractError("bucket policy statement ID is duplicated")
    expected = {
        statement["Sid"]: statement
        for statement in map(
            _canonical_statement, _expected_policy(bucket, partition)["Statement"]
        )
    }
    if actual != expected:
        raise BucketContractError("bucket policy is not the exact public contract")


def _regions(path: Path) -> tuple[str, ...]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BucketContractError("regions file is unreadable") from error
    entries = document.get("regions") if isinstance(document, Mapping) else None
    if not isinstance(entries, list):
        raise BucketContractError("regions file is invalid")
    values = tuple(item.get("code") for item in entries if isinstance(item, Mapping))
    if set(values) != set(SUPPORTED_REGIONS) or len(values) != len(SUPPORTED_REGIONS):
        raise BucketContractError("release region set changed")
    return values


def verify(args: argparse.Namespace, cli: AwsCli) -> dict[str, Any]:
    account = args.expected_account_id
    if ACCOUNT.fullmatch(account) is None:
        raise BucketContractError("expected account ID is invalid")
    identity = cli.json("sts", "get-caller-identity")
    caller_arn = identity.get("Arn", "")
    if identity.get("Account") != account or not isinstance(caller_arn, str):
        raise BucketContractError("current AWS account changed")
    partition = caller_arn.split(":", 2)[1] if caller_arn.startswith("arn:") else ""
    if partition not in {"aws", "aws-us-gov", "aws-cn"}:
        raise BucketContractError("current AWS partition is invalid")

    account_block = cli.json(
        "s3control",
        "get-public-access-block",
        "--account-id",
        account,
        "--region",
        "us-east-1",
        absent_ok=True,
    )
    account_configuration = (
        account_block.get("PublicAccessBlockConfiguration", {})
        if isinstance(account_block, Mapping)
        else {}
    )
    if account_configuration.get("BlockPublicPolicy", False) is not False or (
        account_configuration.get("RestrictPublicBuckets", False) is not False
    ):
        raise BucketContractError("account public-access block prevents publication")

    verified: list[str] = []
    for region in _regions(args.regions_file):
        bucket = f"{args.bucket_prefix}-{account}-{region}"
        if BUCKET.fullmatch(bucket) is None:
            raise BucketContractError("derived bucket name is invalid")
        location = cli.json("s3api", "get-bucket-location", "--bucket", bucket)
        actual_location = location.get("LocationConstraint")
        if actual_location != (None if region == "us-east-1" else region):
            raise BucketContractError(f"{region} bucket location changed")
        versioning = cli.json(
            "s3api", "get-bucket-versioning", "--region", region, "--bucket", bucket
        )
        if versioning.get("Status") != "Enabled" or versioning.get(
            "MFADelete", "Disabled"
        ) not in {"Disabled", None}:
            raise BucketContractError(f"{region} bucket versioning changed")
        encryption = cli.json(
            "s3api",
            "get-bucket-encryption",
            "--region",
            region,
            "--bucket",
            bucket,
        )
        rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules")
        if not isinstance(rules, list) or len(rules) != 1:
            raise BucketContractError(f"{region} bucket encryption changed")
        rule = rules[0]
        default = rule.get("ApplyServerSideEncryptionByDefault", {})
        if (
            default != {"SSEAlgorithm": "AES256"}
            or rule.get("BucketKeyEnabled", False) is not False
        ):
            raise BucketContractError(f"{region} bucket encryption changed")
        ownership = cli.json(
            "s3api",
            "get-bucket-ownership-controls",
            "--region",
            region,
            "--bucket",
            bucket,
        )
        if ownership.get("OwnershipControls", {}).get("Rules") != [
            {"ObjectOwnership": "BucketOwnerEnforced"}
        ]:
            raise BucketContractError(f"{region} bucket ownership changed")
        public_block = cli.json(
            "s3api",
            "get-public-access-block",
            "--region",
            region,
            "--bucket",
            bucket,
        ).get("PublicAccessBlockConfiguration")
        if public_block != {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }:
            raise BucketContractError(f"{region} bucket public-access block changed")
        policy = cli.json(
            "s3api", "get-bucket-policy", "--region", region, "--bucket", bucket
        )
        _verify_policy(policy.get("Policy"), bucket, partition)
        verified.append(region)
    return {
        "schema_version": 1,
        "producer": "bridgefu-release-bucket-verifier@1",
        "account_verified": True,
        "regions_verified": sorted(verified),
        "bucket_policy_verified": True,
        "bucket_encryption_verified": True,
        "bucket_ownership_verified": True,
        "bucket_public_access_block_verified": True,
        "account_public_access_block_verified": True,
        "redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--bucket-prefix", default="bridgefu-vapi-awsconnect")
    parser.add_argument(
        "--regions-file", type=Path, default=Path("release/regions.json")
    )
    args = parser.parse_args()
    print(json.dumps(verify(args, AwsCli()), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BucketContractError as error:
        raise SystemExit(f"release bucket verification failed: {error}") from error
