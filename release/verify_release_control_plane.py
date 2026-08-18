#!/usr/bin/env python3
"""Fail closed when the deployed GitHub/AWS release control plane drifts.

This verifier deliberately reads the live CloudFormation and IAM control plane.
It binds the current STS session to the exact role output by the reviewed stack,
binds security-critical parameters across both stacks, and verifies every role
that the caller is authorized to use is in sync with the exact checked-in
template.  It never prints policy documents, trust documents, or secret ARNs.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

ACCOUNT = re.compile(r"^[0-9]{12}$")
ROLE_ARN = re.compile(r"^arn:(aws(?:-us-gov|-cn)?):iam::([0-9]{12}):role/(.{1,512})$")
KMS_ARN = re.compile(
    r"^arn:(aws(?:-us-gov|-cn)?):kms:us-east-1:([0-9]{12}):key/[0-9a-f-]{36}$"
)
SECRET_ARN = re.compile(
    r"^arn:(aws(?:-us-gov|-cn)?):secretsmanager:(us-west-2|us-east-1):"
    r"([0-9]{12}):secret:[A-Za-z0-9/_+=.@-]+$"
)

PUBLISHER_STACK = "bridgefu-vapi-awsconnect-publisher"
QUALIFICATION_STACK = "bridgefu-vapi-awsconnect-qualification"
STACK_REGION = "us-east-1"


class ControlPlaneError(RuntimeError):
    """The live release control plane is not exactly the reviewed contract."""


class AwsCli:
    def json(self, *arguments: str) -> Any:
        process = subprocess.run(
            ["aws", *arguments, "--output", "json"],
            check=False,
            capture_output=True,
            text=True,
        )
        if process.returncode != 0:
            raise ControlPlaneError(
                f"AWS control-plane read failed: {' '.join(arguments[:2])}"
            )
        try:
            return json.loads(process.stdout)
        except json.JSONDecodeError as error:
            raise ControlPlaneError("AWS returned invalid JSON") from error


def _one(items: Sequence[Any], label: str) -> Any:
    if len(items) != 1:
        raise ControlPlaneError(f"{label} is missing or ambiguous")
    return items[0]


def _string_map(items: Any, key: str, value: str, label: str) -> dict[str, str]:
    if not isinstance(items, list):
        raise ControlPlaneError(f"{label} is invalid")
    result: dict[str, str] = {}
    for item in items:
        if not isinstance(item, Mapping):
            raise ControlPlaneError(f"{label} is invalid")
        item_key, item_value = item.get(key), item.get(value)
        if not isinstance(item_key, str) or not isinstance(item_value, str):
            raise ControlPlaneError(f"{label} is invalid")
        if item_key in result:
            raise ControlPlaneError(f"{label} contains a duplicate key")
        result[item_key] = item_value
    return result


def _stack(cli: AwsCli, name: str) -> dict[str, Any]:
    response = cli.json(
        "cloudformation",
        "describe-stacks",
        "--region",
        STACK_REGION,
        "--stack-name",
        name,
    )
    stack = _one(response.get("Stacks", []), f"{name} stack")
    if not isinstance(stack, dict) or stack.get("StackName") != name:
        raise ControlPlaneError(f"{name} stack identity changed")
    return stack


def _exact_template(cli: AwsCli, stack: str, path: Path) -> None:
    body = cli.json(
        "cloudformation",
        "get-template",
        "--region",
        STACK_REGION,
        "--stack-name",
        stack,
        "--template-stage",
        "Original",
    ).get("TemplateBody")
    if not isinstance(body, str):
        raise ControlPlaneError(f"{stack} original template is not textual")
    try:
        expected = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ControlPlaneError(f"cannot read reviewed template for {stack}") from error
    if body.rstrip("\n") != expected.rstrip("\n"):
        raise ControlPlaneError(f"{stack} is not the exact reviewed template")


def _role_arn(value: str, account: str, label: str) -> tuple[str, str]:
    match = ROLE_ARN.fullmatch(value)
    if match is None or match.group(2) != account:
        raise ControlPlaneError(f"{label} ARN is invalid or in the wrong account")
    return match.group(1), match.group(3)


def _expected_oidc(partition: str, account: str) -> str:
    return (
        f"arn:{partition}:iam::{account}:oidc-provider/"
        "token.actions.githubusercontent.com"
    )


def _trust_for_github(
    provider: str,
    owner: str,
    owner_id: str,
    repository: str,
    repository_id: str,
    environment: str,
    workflow: str | list[str],
    *,
    reference: str,
    reference_operator: str = "StringEquals",
    include_environment_claim: bool = True,
) -> dict[str, Any]:
    string_equals: dict[str, Any] = {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": (
            f"repo:{owner}@{owner_id}/{repository}@{repository_id}:"
            f"environment:{environment}"
        ),
        "token.actions.githubusercontent.com:workflow": workflow,
    }
    if include_environment_claim:
        string_equals["token.actions.githubusercontent.com:environment"] = environment
    condition: dict[str, Any] = {"StringEquals": string_equals}
    if reference_operator == "StringEquals":
        string_equals["token.actions.githubusercontent.com:ref"] = reference
    else:
        condition[reference_operator] = {
            "token.actions.githubusercontent.com:ref": reference
        }
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": provider},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": condition,
            }
        ],
    }


def _canonical(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _verify_role(
    cli: AwsCli,
    *,
    stack: str,
    logical_id: str,
    role_arn: str,
    account: str,
    inline_policy_names: list[str],
    attached_policy_arns: list[str],
    trust: Mapping[str, Any],
    max_session_duration: int,
) -> dict[str, Any]:
    _, role_path_and_name = _role_arn(role_arn, account, logical_id)
    role_name = role_path_and_name.rsplit("/", 1)[-1]
    drift = _detect_resource_drift(cli, stack, logical_id)
    if drift.get("StackResourceDriftStatus") != "IN_SYNC":
        raise ControlPlaneError(f"{logical_id} has CloudFormation drift")
    role = cli.json("iam", "get-role", "--role-name", role_name).get("Role")
    if not isinstance(role, Mapping) or role.get("Arn") != role_arn:
        raise ControlPlaneError(f"{logical_id} live role ARN changed")
    if role.get("MaxSessionDuration") != max_session_duration:
        raise ControlPlaneError(f"{logical_id} MaxSessionDuration changed")
    if _canonical(role.get("AssumeRolePolicyDocument")) != _canonical(trust):
        raise ControlPlaneError(f"{logical_id} trust policy changed")
    inline = cli.json("iam", "list-role-policies", "--role-name", role_name)
    if sorted(inline.get("PolicyNames", [])) != sorted(inline_policy_names):
        raise ControlPlaneError(f"{logical_id} inline policy set changed")
    attached = cli.json("iam", "list-attached-role-policies", "--role-name", role_name)
    live_attached = sorted(
        item.get("PolicyArn") for item in attached.get("AttachedPolicies", [])
    )
    if live_attached != sorted(attached_policy_arns):
        raise ControlPlaneError(f"{logical_id} attached policy set changed")
    for policy_name in inline_policy_names:
        document = cli.json(
            "iam",
            "get-role-policy",
            "--role-name",
            role_name,
            "--policy-name",
            policy_name,
        ).get("PolicyDocument")
        if not isinstance(document, Mapping):
            raise ControlPlaneError(f"{logical_id} inline policy is unreadable")
    return dict(role)


def _detect_resource_drift(
    cli: AwsCli,
    stack: str,
    logical_id: str,
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> Mapping[str, Any]:
    """Wait through CloudFormation's bounded post-operation drift-detection race."""
    for attempt in range(19):
        try:
            response = cli.json(
                "cloudformation",
                "detect-stack-resource-drift",
                "--region",
                STACK_REGION,
                "--stack-name",
                stack,
                "--logical-resource-id",
                logical_id,
            )
            drift = response.get("StackResourceDrift", {})
            if not isinstance(drift, Mapping):
                raise ControlPlaneError("resource drift result is invalid")
            return drift
        except ControlPlaneError:
            if attempt == 18:
                raise
            sleep(5)
    raise AssertionError("unreachable drift retry state")


def verify(args: argparse.Namespace, cli: AwsCli) -> dict[str, Any]:
    if ACCOUNT.fullmatch(args.expected_account_id) is None:
        raise ControlPlaneError("expected account ID is invalid")
    account = args.expected_account_id
    identity = cli.json("sts", "get-caller-identity")
    if identity.get("Account") != account:
        raise ControlPlaneError("current AWS account is not the expected account")

    publisher = _stack(cli, PUBLISHER_STACK)
    qualification = _stack(cli, QUALIFICATION_STACK)
    _exact_template(cli, PUBLISHER_STACK, args.publisher_template)
    _exact_template(cli, QUALIFICATION_STACK, args.qualification_template)
    publisher_parameters = _string_map(
        publisher.get("Parameters"),
        "ParameterKey",
        "ParameterValue",
        "publisher parameters",
    )
    qualification_parameters = _string_map(
        qualification.get("Parameters"),
        "ParameterKey",
        "ParameterValue",
        "qualification parameters",
    )
    publisher_outputs = _string_map(
        publisher.get("Outputs"), "OutputKey", "OutputValue", "publisher outputs"
    )
    qualification_outputs = _string_map(
        qualification.get("Outputs"),
        "OutputKey",
        "OutputValue",
        "qualification outputs",
    )
    if publisher_outputs.get("PublisherPolicyContractVersion") != (
        "2026-08-18-review-normalization-and-cleanup-v7"
    ) or qualification_outputs.get("QualificationPolicyContractVersion") != (
        "2026-08-18-complete-qualification-api-intents-v6"
    ):
        raise ControlPlaneError("deployed policy contract version changed")

    fixed_publisher = {
        "GitHubRepositoryOwner": "eisenzopf",
        "GitHubRepositoryOwnerId": "9158070",
        "GitHubRepositoryName": "bridgefu-vapi-awsconnect",
        "GitHubRepositoryId": "1328315150",
        "GitHubEnvironment": "production-release",
        "GitHubRecoveryEnvironment": "release-recovery",
        "ArtifactBucketPrefix": "bridgefu-vapi-awsconnect",
    }
    fixed_qualification = {
        "GitHubRepositoryOwner": "eisenzopf",
        "GitHubRepositoryOwnerId": "9158070",
        "GitHubRepositoryName": "bridgefu-vapi-awsconnect",
        "GitHubRepositoryId": "1328315150",
        "GitHubEnvironment": "live-qualification",
        "ArtifactBucketPrefix": "bridgefu-vapi-awsconnect",
    }
    for key, value in fixed_publisher.items():
        if publisher_parameters.get(key) != value:
            raise ControlPlaneError(f"publisher parameter changed: {key}")
    for key, value in fixed_qualification.items():
        if qualification_parameters.get(key) != value:
            raise ControlPlaneError(f"qualification parameter changed: {key}")

    candidate_arn = publisher_outputs.get("CandidateBuilderRoleArn", "")
    publish_arn = publisher_outputs.get("PublisherRoleArn", "")
    recovery_arn = publisher_outputs.get("RecoveryRoleArn", "")
    runner_arn = qualification_outputs.get("QualificationRunnerRoleArn", "")
    cfn_arn = qualification_outputs.get("QualificationCloudFormationServiceRoleArn", "")
    partition, _ = _role_arn(candidate_arn, account, "candidate role")
    for label, value in (
        ("publisher role", publish_arn),
        ("recovery role", recovery_arn),
        ("qualification runner role", runner_arn),
        ("qualification CloudFormation role", cfn_arn),
    ):
        value_partition, _ = _role_arn(value, account, label)
        if value_partition != partition:
            raise ControlPlaneError(f"{label} partition changed")
    if runner_arn != (
        f"arn:{partition}:iam::{account}:role/"
        "bridgefu-vapi-awsconnect-qualification-runner"
    ) or cfn_arn != (
        f"arn:{partition}:iam::{account}:role/"
        "bridgefu-vapi-awsconnect-qualification-cloudformation"
    ):
        raise ControlPlaneError("fixed qualification role output changed")

    signing_key = publisher_outputs.get("SigningKeyArn", "")
    key_match = KMS_ARN.fullmatch(signing_key)
    if key_match is None or key_match.group(2) != account:
        raise ControlPlaneError("publisher signing key output changed")
    if qualification_parameters.get("ReleaseSigningKeyArn") != signing_key:
        raise ControlPlaneError("qualification signing key is not publisher output")
    if args.expected_signing_key_arn and args.expected_signing_key_arn != signing_key:
        raise ControlPlaneError("configured signing key is not publisher output")
    if (
        args.expected_cloudformation_role_arn
        and args.expected_cloudformation_role_arn != cfn_arn
    ):
        raise ControlPlaneError(
            "configured CloudFormation role is not the stack output"
        )

    oidc = _expected_oidc(partition, account)
    if (
        publisher_parameters.get("GitHubOidcProviderArn") != oidc
        or qualification_parameters.get("GitHubOidcProviderArn") != oidc
    ):
        raise ControlPlaneError("GitHub OIDC provider binding changed")
    for region, publisher_key, qualification_key in (
        ("us-west-2", "VapiApiKeySecretArnUsWest2", "VapiApiKeySecretArn"),
        (
            "us-east-1",
            "VapiApiKeySecretArnUsEast1",
            "VapiApiKeySecretArnUsEast1",
        ),
    ):
        value = publisher_parameters.get(publisher_key, "")
        match = SECRET_ARN.fullmatch(value)
        if match is None or match.group(2) != region or match.group(3) != account:
            raise ControlPlaneError(f"publisher {region} secret binding is invalid")
        if qualification_parameters.get(qualification_key) != value:
            raise ControlPlaneError(f"qualification {region} secret binding differs")
        configured = {
            "us-west-2": args.expected_vapi_secret_west,
            "us-east-1": args.expected_vapi_secret_east,
        }[region]
        if configured and configured != value:
            raise ControlPlaneError(
                f"configured {region} secret is not the stack parameter"
            )
    hosted_zone = publisher_parameters.get("QualificationPublicHostedZoneId", "")
    if (
        not re.fullmatch(r"Z[A-Z0-9]{1,31}", hosted_zone)
        or qualification_parameters.get("QualificationPublicHostedZoneId")
        != hosted_zone
    ):
        raise ControlPlaneError("qualification hosted-zone binding changed")
    if args.expected_hosted_zone_id and args.expected_hosted_zone_id != hosted_zone:
        raise ControlPlaneError("configured hosted zone is not the stack parameter")

    expected_callers = {
        "candidate": candidate_arn,
        "qualification": runner_arn,
        "publisher": publish_arn,
        "recovery": recovery_arn,
    }
    if args.expected_caller_role_arn != expected_callers[args.mode]:
        raise ControlPlaneError("configured caller role is not the stack output")
    caller_role = _verify_role_identity(
        cli, identity, args.expected_caller_role_arn, account
    )

    owner = fixed_publisher["GitHubRepositoryOwner"]
    owner_id = fixed_publisher["GitHubRepositoryOwnerId"]
    repository = fixed_publisher["GitHubRepositoryName"]
    repository_id = fixed_publisher["GitHubRepositoryId"]
    trusts = {
        "CandidateBuilderRole": _trust_for_github(
            oidc,
            owner,
            owner_id,
            repository,
            repository_id,
            "production-release",
            "Build and qualify private candidate",
            reference="refs/heads/main",
        ),
        "PublisherRole": _trust_for_github(
            oidc,
            owner,
            owner_id,
            repository,
            repository_id,
            "production-release",
            "Publish qualified release",
            reference="refs/tags/v*",
            reference_operator="StringLike",
        ),
        "RecoveryRole": _trust_for_github(
            oidc,
            owner,
            owner_id,
            repository,
            repository_id,
            "release-recovery",
            "Reap incomplete release work",
            reference="refs/heads/main",
        ),
        "QualificationRunnerRole": _trust_for_github(
            oidc,
            owner,
            owner_id,
            repository,
            repository_id,
            "live-qualification",
            ["Build and qualify private candidate", "Remote live qualification"],
            reference="refs/heads/main",
            include_environment_claim=False,
        ),
        "QualificationCloudFormationServiceRole": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudformation.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    }
    role_specs = {
        "CandidateBuilderRole": (
            PUBLISHER_STACK,
            candidate_arn,
            ["BuildPrivateCandidate"],
            [],
            10800,
        ),
        "PublisherRole": (
            PUBLISHER_STACK,
            publish_arn,
            ["PublishExactQualifiedCandidate"],
            [],
            10800,
        ),
        "RecoveryRole": (
            PUBLISHER_STACK,
            recovery_arn,
            ["ReapOnlyOwnedReleaseAttempts"],
            [],
            10800,
        ),
        "QualificationRunnerRole": (
            QUALIFICATION_STACK,
            runner_arn,
            ["DisposableQualificationOrchestration"],
            [],
            10800,
        ),
        "QualificationCloudFormationServiceRole": (
            QUALIFICATION_STACK,
            cfn_arn,
            [],
            [f"arn:{partition}:iam::aws:policy/AdministratorAccess"],
            3600,
        ),
    }
    selected = {
        "candidate": list(role_specs),
        "qualification": [
            "QualificationRunnerRole",
            "QualificationCloudFormationServiceRole",
        ],
        "publisher": ["PublisherRole"],
        "recovery": ["RecoveryRole"],
    }[args.mode]
    for logical_id in selected:
        stack_name, role_arn, inline, attached, duration = role_specs[logical_id]
        _verify_role(
            cli,
            stack=stack_name,
            logical_id=logical_id,
            role_arn=role_arn,
            account=account,
            inline_policy_names=inline,
            attached_policy_arns=attached,
            trust=trusts[logical_id],
            max_session_duration=duration,
        )

    return {
        "schema_version": 1,
        "producer": "bridgefu-release-control-plane-verifier@1",
        "mode": args.mode,
        "account_verified": True,
        "caller_role_verified": caller_role.get("Arn") == args.expected_caller_role_arn,
        "stack_templates_verified": True,
        "stack_parameters_verified": True,
        "role_trust_and_policy_sets_verified": True,
        "redacted": True,
    }


def _verify_role_identity(
    cli: AwsCli, identity: Mapping[str, Any], expected_role_arn: str, account: str
) -> dict[str, Any]:
    _, role_path_and_name = _role_arn(expected_role_arn, account, "caller role")
    role_name = role_path_and_name.rsplit("/", 1)[-1]
    role = cli.json("iam", "get-role", "--role-name", role_name).get("Role")
    if not isinstance(role, Mapping) or role.get("Arn") != expected_role_arn:
        raise ControlPlaneError("configured caller role does not exist exactly")
    role_id = role.get("RoleId")
    user_id = identity.get("UserId")
    caller_arn = identity.get("Arn")
    if (
        not isinstance(role_id, str)
        or not isinstance(user_id, str)
        or not user_id.startswith(f"{role_id}:")
        or not isinstance(caller_arn, str)
        or not re.fullmatch(
            rf"arn:[^:]+:sts::{account}:assumed-role/{re.escape(role_name)}/[^/]+",
            caller_arn,
        )
    ):
        raise ControlPlaneError("current STS session is not the configured caller role")
    return dict(role)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("candidate", "qualification", "publisher", "recovery"),
        required=True,
    )
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-caller-role-arn", required=True)
    parser.add_argument("--expected-signing-key-arn", default="")
    parser.add_argument("--expected-cloudformation-role-arn", default="")
    parser.add_argument("--expected-vapi-secret-west", default="")
    parser.add_argument("--expected-vapi-secret-east", default="")
    parser.add_argument("--expected-hosted-zone-id", default="")
    parser.add_argument(
        "--publisher-template", type=Path, default=Path("publisher/oidc-role.yaml")
    )
    parser.add_argument(
        "--qualification-template",
        type=Path,
        default=Path("publisher/qualification-role.yaml"),
    )
    args = parser.parse_args()
    print(json.dumps(verify(args, AwsCli()), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ControlPlaneError as error:
        raise SystemExit(
            f"release control-plane verification failed: {error}"
        ) from error
