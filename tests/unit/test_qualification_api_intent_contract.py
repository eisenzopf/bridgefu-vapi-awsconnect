from __future__ import annotations

import ast
import unittest
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    ROOT / "qualification" / "controller.py",
    ROOT / "qualification" / "deployment_review.py",
    ROOT / "qualification" / "release_safeguards.py",
)
ROLE = ROOT / "publisher" / "qualification-role.yaml"


class CloudFormationLoader(yaml.SafeLoader):
    pass


def construct_cloudformation_tag(
    loader: CloudFormationLoader, _tag_suffix: str, node: yaml.Node
) -> Any:
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


CloudFormationLoader.add_multi_constructor("!", construct_cloudformation_tag)


AWS_SERVICES = {
    "acm",
    "apigatewayv2",
    "backup",
    "cloudformation",
    "cloudwatch",
    "connect",
    "dynamodb",
    "ec2",
    "iam",
    "lambda",
    "logs",
    "polly",
    "resourcegroupstaggingapi",
    "route53",
    "s3",
    "s3api",
    "secretsmanager",
    "service-quotas",
    "sns",
    "ssm",
    "sts",
}

# These calls are assembled from the bounded EC2 resource-type table rather than
# a literal service/operation list. Keep them visible to the same policy audit.
DYNAMIC_OPERATIONS = {
    ("ec2", "describe-addresses"),
    ("ec2", "describe-internet-gateways"),
    ("ec2", "describe-nat-gateways"),
    ("ec2", "describe-network-interfaces"),
    ("ec2", "describe-route-tables"),
    ("ec2", "describe-security-groups"),
    ("ec2", "describe-subnets"),
    ("ec2", "describe-volumes"),
    ("ec2", "describe-vpc-endpoints"),
    ("ec2", "describe-vpcs"),
}

SPECIAL_ACTIONS = {
    ("apigatewayv2", "get-api"): {"apigateway:GET"},
    ("cloudformation", "wait"): {"cloudformation:DescribeStacks"},
    ("resourcegroupstaggingapi", "get-resources"): {"tag:GetResources"},
    ("s3", "cp"): {"s3:GetObject", "s3:PutObject"},
    ("s3", "rm"): {"s3:DeleteObject"},
    ("s3api", "delete-objects"): {
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
    },
    ("s3api", "list-object-versions"): {"s3:ListBucketVersions"},
    ("s3api", "put-object"): {"s3:PutObject"},
    ("ssm", "start-session"): {
        "ssm:ResumeSession",
        "ssm:StartSession",
        "ssm:TerminateSession",
        "ssmmessages:OpenDataChannel",
    },
    # AWS documents GetCallerIdentity as callable without an explicit allow.
    ("sts", "get-caller-identity"): set(),
}
PREFIXES = {
    "service-quotas": "servicequotas",
}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def literal(value: ast.AST) -> str | None:
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def source_operations() -> set[tuple[str, str]]:
    operations = set(DYNAMIC_OPERATIONS)
    for path in SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.List):
                continue
            values = [literal(item) for item in node.elts[:3]]
            if len(values) >= 3 and values[0] == "aws":
                service, operation = values[1:3]
            elif len(values) >= 2:
                service, operation = values[:2]
            else:
                continue
            if service in AWS_SERVICES and operation is not None:
                operations.add((service, operation))
    return operations


def api_action(operation: tuple[str, str]) -> set[str]:
    if operation in SPECIAL_ACTIONS:
        return SPECIAL_ACTIONS[operation]
    service, command = operation
    prefix = PREFIXES.get(service, service)
    action = "".join(part.capitalize() for part in command.split("-"))
    return {f"{prefix}:{action}"}


def qualification_statements() -> list[dict[str, Any]]:
    loader = CloudFormationLoader(ROLE.read_text(encoding="utf-8"))
    try:
        document = loader.get_single_data()
    finally:
        loader.dispose()
    return document["Resources"]["QualificationRunnerRole"]["Properties"][
        "Policies"
    ][0]["PolicyDocument"]["Statement"]


def actions(statements: Iterable[dict[str, Any]]) -> set[str]:
    return {
        str(action)
        for statement in statements
        if statement.get("Effect") == "Allow"
        for action in as_list(statement.get("Action"))
    }


class QualificationApiIntentContractTests(unittest.TestCase):
    def test_every_controller_api_intent_is_allowed_by_the_runner_role(self):
        required = {
            action
            for operation in source_operations()
            for action in api_action(operation)
        }
        self.assertEqual(required - actions(qualification_statements()), set())

    def test_port_forwarding_is_limited_to_owned_instances_and_sessions(self):
        statements = {item["Sid"]: item for item in qualification_statements()}
        instance = statements["StartOnlyTaggedQualificationPortForwarding"]
        self.assertEqual(instance["Action"], "ssm:StartSession")
        self.assertEqual(
            instance["Condition"],
            {
                "StringEquals": {
                    "ssm:resourceTag/Project": "bridgefu-vapi-awsconnect",
                    "ssm:resourceTag/ManagedBy": "bridgefu-cloudformation",
                },
                "StringLike": {"ssm:resourceTag/BridgefuExecutionId": "bfq-*"},
            },
        )
        document = statements["UseOnlyAwsPortForwardingDocument"]
        self.assertEqual(document["Action"], "ssm:StartSession")
        self.assertTrue(
            str(document["Resource"]).endswith(
                ":ssm:*::document/AWS-StartPortForwardingSession"
            )
        )
        session = statements["UseOnlyOwnQualificationSessions"]
        self.assertEqual(
            set(session["Action"]),
            {
                "ssm:ResumeSession",
                "ssm:TerminateSession",
            },
        )
        self.assertIn("session/${!aws:userid}-*", session["Resource"])
        channel = statements["OpenQualificationSessionDataChannel"]
        self.assertEqual(channel["Action"], "ssmmessages:OpenDataChannel")
        self.assertEqual(channel["Resource"], "*")

    def test_handoff_context_writes_are_limited_to_one_use_keys(self):
        statement = next(
            item
            for item in qualification_statements()
            if item["Sid"] == "WriteOnlyOwnedQualificationHandoffContext"
        )
        self.assertEqual(
            set(statement["Action"]),
            {"dynamodb:DeleteItem", "dynamodb:PutItem"},
        )
        self.assertIn(":table/bridgefu-bfq-*", statement["Resource"])
        self.assertEqual(
            statement["Condition"],
            {"ForAllValues:StringLike": {"dynamodb:LeadingKeys": "bf1_*"}},
        )


if __name__ == "__main__":
    unittest.main()
