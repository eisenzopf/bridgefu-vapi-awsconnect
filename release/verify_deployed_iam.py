#!/usr/bin/env python3
"""Verify security-critical deployed inline IAM policy statements.

The candidate workflow runs this after assuming its build role and before its
first AWS mutation.  Inputs are the decoded PolicyDocument objects returned by
``aws iam get-role-policy``.  Only bounded, non-secret deployment coordinates
are accepted.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PARTITION = re.compile(r"^aws(?:-us-gov|-cn)?$")
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
BUCKET_PREFIX = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


class IamContractError(ValueError):
    """A deployed inline policy does not match the reviewed contract."""


def _values(value: Any, label: str) -> tuple[str, ...]:
    values = [value] if isinstance(value, str) else value
    if (
        not isinstance(values, list)
        or not values
        or any(not isinstance(item, str) or not item for item in values)
    ):
        raise IamContractError(f"{label} is invalid")
    return tuple(sorted(values))


def _canonical_statement(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) - {
        "Sid",
        "Effect",
        "Action",
        "Resource",
        "Condition",
    }:
        raise IamContractError("IAM statement shape is invalid")
    sid = value.get("Sid")
    if not isinstance(sid, str) or not sid:
        raise IamContractError("IAM statement Sid is invalid")
    result: dict[str, Any] = {
        "Sid": sid,
        "Effect": value.get("Effect"),
        "Action": _values(value.get("Action"), "IAM statement Action"),
        "Resource": _values(value.get("Resource"), "IAM statement Resource"),
    }
    condition = value.get("Condition")
    if condition is not None:
        if not isinstance(condition, Mapping):
            raise IamContractError("IAM statement Condition is invalid")
        result["Condition"] = json.loads(
            json.dumps(condition, separators=(",", ":"), sort_keys=True)
        )
    return result


def _statement_map(document: Any) -> dict[str, dict[str, Any]]:
    if (
        not isinstance(document, Mapping)
        or document.get("Version") != "2012-10-17"
        or not isinstance(document.get("Statement"), list)
    ):
        raise IamContractError("IAM policy document is invalid")
    result: dict[str, dict[str, Any]] = {}
    for raw in document["Statement"]:
        statement = _canonical_statement(raw)
        sid = statement["Sid"]
        if sid in result:
            raise IamContractError(f"IAM statement Sid is duplicated: {sid}")
        result[sid] = statement
    return result


def _statement(
    sid: str,
    actions: str | list[str],
    resources: str | list[str],
    condition: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "Sid": sid,
        "Effect": "Allow",
        "Action": actions,
        "Resource": resources,
    }
    if condition is not None:
        value["Condition"] = dict(condition)
    return _canonical_statement(value)


def expected_contract(
    partition: str, account_id: str, bucket_prefix: str
) -> dict[str, dict[str, dict[str, Any]]]:
    if (
        not PARTITION.fullmatch(partition)
        or not ACCOUNT_ID.fullmatch(account_id)
        or not BUCKET_PREFIX.fullmatch(bucket_prefix)
    ):
        raise IamContractError("IAM contract coordinate is invalid")
    bucket = f"arn:{partition}:s3:::{bucket_prefix}-*"
    secret = f"arn:{partition}:secretsmanager:*:{account_id}:secret:"
    qualification = {
        statement["Sid"]: statement
        for statement in (
            _statement(
                "InspectGeneratedQualificationSecrets",
                ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"],
                [f"{secret}bridgefu-bfq-*", f"{secret}bridgefu/bfq-*"],
            ),
            _statement(
                "UpdateOnlyTaggedGeneratedQualificationSecrets",
                "secretsmanager:PutSecretValue",
                f"{secret}bridgefu/bfq-*",
                {
                    "StringEquals": {
                        "aws:ResourceTag/ManagedBy": "bridgefu-qualification"
                    }
                },
            ),
            _statement(
                "ManageOnlyOwnedQualificationWebMediaIngress",
                [
                    "ec2:AuthorizeSecurityGroupIngress",
                    "ec2:RevokeSecurityGroupIngress",
                ],
                f"arn:{partition}:ec2:*:{account_id}:security-group/*",
                {
                    "StringEquals": {
                        "aws:ResourceTag/Project": "bridgefu-vapi-awsconnect",
                        "aws:ResourceTag/ManagedBy": "bridgefu-cloudformation",
                    },
                    "StringLike": {
                        "aws:ResourceTag/BridgefuExecutionId": "bfq-*"
                    },
                },
            ),
            _statement(
                "StartOnlyTaggedQualificationPortForwarding",
                "ssm:StartSession",
                f"arn:{partition}:ec2:*:{account_id}:instance/*",
                {
                    "StringEquals": {
                        "ssm:resourceTag/Project": "bridgefu-vapi-awsconnect",
                        "ssm:resourceTag/ManagedBy": "bridgefu-cloudformation",
                    },
                    "StringLike": {
                        "ssm:resourceTag/BridgefuExecutionId": "bfq-*"
                    },
                },
            ),
            _statement(
                "UseOnlyAwsPortForwardingDocument",
                "ssm:StartSession",
                f"arn:{partition}:ssm:*::document/AWS-StartPortForwardingSession",
            ),
            _statement(
                "UseOnlyOwnQualificationSessions",
                [
                    "ssm:ResumeSession",
                    "ssm:TerminateSession",
                ],
                f"arn:{partition}:ssm:*:{account_id}:session/${{aws:userid}}-*",
            ),
            _statement(
                "OpenQualificationSessionDataChannel",
                "ssmmessages:OpenDataChannel",
                "*",
            ),
            _statement(
                "WriteOnlyOwnedQualificationHandoffContext",
                ["dynamodb:DeleteItem", "dynamodb:PutItem"],
                f"arn:{partition}:dynamodb:*:{account_id}:table/bridgefu-bfq-*",
                {
                    "ForAllValues:StringLike": {
                        "dynamodb:LeadingKeys": "bf1_*"
                    }
                },
            ),
        )
    }
    recovery_read_prefix = [
        f"{bucket}/candidates/runs/*",
        f"{bucket}/candidates/candidate-*/*",
        f"{bucket}/candidates/qualified/*",
        f"{bucket}/candidates/publications/*",
    ]
    # Expand the one placeholder into the exact reviewed ownership journal set.
    journal_names = [
        "vapi-phone.json",
        "vapi-phone-intent.json",
        "vapi-phone-request.json",
        "vapi-direct-tool.json",
        "vapi-direct-tool-intent.json",
        "vapi-direct-tool-request.json",
        "vapi-direct-assistant.json",
        "vapi-direct-assistant-intent.json",
        "vapi-direct-assistant-request.json",
        "acm-validation-records.json",
    ]
    recovery_read = (
        recovery_read_prefix
        + [f"{bucket}/qualification/bfq-*/ownership/{name}" for name in journal_names]
        + [f"{bucket}/releases/*", f"{bucket}/latest/*"]
    )
    recovery = {
        statement["Sid"]: statement
        for statement in (
            _statement(
                "ListRecoveryPrefixes",
                ["s3:ListBucket", "s3:ListBucketVersions"],
                bucket,
                {
                    "StringLike": {
                        "s3:prefix": [
                            "candidates/runs/*",
                            "candidates/candidate-*/*",
                            "candidates/qualified/*",
                            "candidates/publications/*",
                            "qualification/bfq-*/*",
                            "releases/*",
                            "latest/*",
                        ]
                    }
                },
            ),
            _statement(
                "ReadRecoveryJournalsAndReceipts",
                ["s3:GetObject", "s3:GetObjectVersion"],
                recovery_read,
            ),
            _statement(
                "SealExactRecoveryOwnershipBeforeCleanup",
                "s3:PutObject",
                [
                    f"{bucket}/candidates/runs/*/state.json",
                    f"{bucket}/candidates/publications/*/state.json",
                    f"{bucket}/qualification/bfq-*/ownership/vapi-phone.json",
                    f"{bucket}/qualification/bfq-*/ownership/vapi-direct-tool.json",
                    f"{bucket}/qualification/bfq-*/ownership/vapi-direct-assistant.json",
                    f"{bucket}/qualification/bfq-*/ownership/acm-validation-records.json",
                ],
            ),
            _statement(
                "ReadExactQualificationVapiIdentityBindings",
                "secretsmanager:GetSecretValue",
                [
                    f"{secret}bridgefu-bfq-*-vapi-identity-*",
                    f"{secret}bridgefu/bfq-*/qualification/direct-vapi-identity-*",
                ],
            ),
            _statement(
                "UnbindOnlyTaggedDirectQualificationVapiIdentity",
                "secretsmanager:PutSecretValue",
                f"{secret}bridgefu/bfq-*/qualification/direct-vapi-identity-*",
                {
                    "StringEquals": {
                        "aws:ResourceTag/ManagedBy": "bridgefu-qualification"
                    }
                },
            ),
        )
    }
    return {"qualification": qualification, "recovery": recovery}


def verify_policy_document(
    document: Any, expected: Mapping[str, Mapping[str, Any]], label: str
) -> None:
    deployed = _statement_map(document)
    for sid, required in expected.items():
        actual = deployed.get(sid)
        if actual is None:
            raise IamContractError(f"{label} IAM statement is missing: {sid}")
        if actual != required:
            raise IamContractError(f"{label} IAM statement changed: {sid}")


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise IamContractError("IAM policy input is unreadable") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qualification-policy", required=True, type=Path)
    parser.add_argument("--recovery-policy", required=True, type=Path)
    parser.add_argument("--partition", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--artifact-bucket-prefix", required=True)
    args = parser.parse_args()
    contract = expected_contract(
        args.partition, args.account_id, args.artifact_bucket_prefix
    )
    verify_policy_document(
        _read(args.qualification_policy), contract["qualification"], "qualification"
    )
    verify_policy_document(
        _read(args.recovery_policy), contract["recovery"], "recovery"
    )
    print(
        json.dumps(
            {
                "schema_version": 1,
                "producer": "bridgefu-deployed-iam-contract@1",
                "qualification_policy_verified": True,
                "recovery_policy_verified": True,
                "redacted": True,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
