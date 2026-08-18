from __future__ import annotations

import copy
import sys
import unittest
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from qualification import deployment_review as review

REGION = "us-west-2"
ACCOUNT = "123456789012"
BUCKET = "bridgefu-vapi-awsconnect-123456789012-us-east-1"
NAMES = (
    "qualification-root",
    "disposable",
    "product",
    "configuration",
    "network",
    "handoff-service",
    "connect",
    "runtime",
    "vapi",
    "observability",
)
PARAMETERS = (
    ("DeploymentId", "bfq-test-1234"),
    (
        "VapiApiKeySecretArn",
        "arn:aws:secretsmanager:us-west-2:123456789012:secret:test",
    ),
    ("PublicHostedZoneId", "Z1234567890"),
    ("SipHostname", "bfq-test-1234.example.com"),
    ("InstanceType", "c7g.2xlarge"),
)


def template_url(name: str, version: str | None = None) -> str:
    version_id = version or f"version-{name}"
    return (
        f"https://{BUCKET}.s3.us-east-1.amazonaws.com/"
        f"releases/0.1.20/{name}.yaml?versionId={version_id}"
    )


def change_set_arn(name: str) -> str:
    return (
        f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:"
        f"changeSet/{name}/00000000-0000-4000-8000-{NAMES.index(name):012d}"
    )


def stack_arn(name: str) -> str:
    return (
        f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:"
        f"stack/{name}/10000000-0000-4000-8000-{NAMES.index(name):012d}"
    )


class ExactCreateHierarchy:
    def __init__(self) -> None:
        self.children = {
            "qualification-root": {
                "Disposable": "disposable",
                "Candidate": "product",
            },
            "product": {
                "Configuration": "configuration",
                "Network": "network",
                "HandoffService": "handoff-service",
                "Connect": "connect",
                "Runtime": "runtime",
                "Vapi": "vapi",
                "Observability": "observability",
            },
        }
        self.parents = {
            child: parent
            for parent, children in self.children.items()
            for child in children.values()
        }
        self.templates = {name: self._template(name) for name in NAMES}
        self.remote_templates = copy.deepcopy(self.templates)
        self.descriptions = {name: self._description(name) for name in NAMES}
        self.stacks = {name: self._stack(name) for name in NAMES}
        self.calls: list[tuple[str, ...]] = []

    def _template(self, name: str) -> dict[str, Any]:
        resources: dict[str, Any] = {
            "Marker": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Type": "String", "Value": name},
            }
        }
        for logical_id, child in self.children.get(name, {}).items():
            resources[logical_id] = {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {"TemplateURL": template_url(child)},
            }
        return {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"sealed {name}",
            "Resources": resources,
        }

    def _description(self, name: str) -> dict[str, Any]:
        parent = self.parents.get(name)
        changes = []
        for logical_id, child in self.children.get(name, {}).items():
            changes.append(
                {
                    "Type": "Resource",
                    "ResourceChange": {
                        "Action": "Add",
                        "LogicalResourceId": logical_id,
                        "ResourceType": "AWS::CloudFormation::Stack",
                        "ChangeSetId": change_set_arn(child),
                    },
                }
            )
        value = {
            "ChangeSetId": change_set_arn(name),
            "StackId": stack_arn(name),
            "Status": "CREATE_COMPLETE",
            "ExecutionStatus": "AVAILABLE" if parent is None else "UNAVAILABLE",
            "IncludeNestedStacks": True,
            "ParentChangeSetId": change_set_arn(parent) if parent else None,
            "RootChangeSetId": change_set_arn("qualification-root") if parent else None,
            "Changes": changes,
        }
        if parent is None:
            value.update(
                {
                    "ChangeSetName": "qualification-root",
                    "StackName": "qualification-root",
                    "Parameters": [
                        {"ParameterKey": key, "ParameterValue": nested}
                        for key, nested in PARAMETERS
                    ],
                    "Capabilities": ["CAPABILITY_NAMED_IAM"],
                    "Tags": [
                        {"Key": "ManagedBy", "Value": "bridgefu-qualification"},
                        {"Key": "BridgefuExecutionId", "Value": "bfq-test-1234"},
                    ],
                    "OnStackFailure": "DO_NOTHING",
                    "NotificationARNs": [],
                    "RollbackConfiguration": {},
                    "ImportExistingResources": False,
                }
            )
        return value

    def _stack(self, name: str) -> dict[str, Any]:
        parent = self.parents.get(name)
        value = {
            "StackId": stack_arn(name),
            "StackStatus": "REVIEW_IN_PROGRESS",
            "ParentId": stack_arn(parent) if parent else None,
            "RootId": stack_arn("qualification-root") if parent else None,
        }
        if parent is None:
            value["RoleARN"] = (
                "arn:aws:iam::123456789012:role/BridgefuQualificationCloudFormation"
            )
        return value

    def catalog(self) -> tuple[review.SealedTemplate, ...]:
        return tuple(
            review.SealedTemplate(template_url(name), self.templates[name])
            for name in NAMES
        )

    def json(
        self, arguments: list[str], timeout: int | None = None
    ) -> Mapping[str, Any]:
        del timeout
        call = tuple(arguments)
        self.calls.append(call)
        service, operation = call[:2]
        if service != "cloudformation":
            raise AssertionError(call)
        identity = (
            call[call.index("--change-set-name") + 1]
            if "--change-set-name" in call
            else call[call.index("--stack-name") + 1]
        )
        if operation == "describe-change-set":
            name = next(name for name in NAMES if change_set_arn(name) == identity)
            return copy.deepcopy(self.descriptions[name])
        if operation == "get-template":
            name = next(name for name in NAMES if change_set_arn(name) == identity)
            return {
                "TemplateBody": copy.deepcopy(self.remote_templates[name]),
                "StagesAvailable": ["Original", "Processed"],
            }
        if operation == "describe-stacks":
            name = next(name for name in NAMES if stack_arn(name) == identity)
            return {"Stacks": [copy.deepcopy(self.stacks[name])]}
        raise AssertionError(call)


def run_review(
    aws: ExactCreateHierarchy,
    *,
    catalog: tuple[review.SealedTemplate, ...] | None = None,
    expected_change_set_type: str = "CREATE",
) -> review.DeploymentReview:
    return review.review_create_change_set(
        aws=aws,
        root_change_set_arn=change_set_arn("qualification-root"),
        root_stack_id=stack_arn("qualification-root"),
        root_template_url=template_url("qualification-root"),
        sealed_catalog=catalog or aws.catalog(),
        expected_change_set_type=expected_change_set_type,
        expected_region=REGION,
        expected_account_id=ACCOUNT,
        expected_root_invocation=root_invocation(),
    )


def root_invocation() -> review.RootInvocation:
    return review.RootInvocation(
        change_set_name="qualification-root",
        stack_name="qualification-root",
        parameters=PARAMETERS,
        role_arn=("arn:aws:iam::123456789012:role/BridgefuQualificationCloudFormation"),
        capabilities=("CAPABILITY_NAMED_IAM",),
        tags=(
            ("ManagedBy", "bridgefu-qualification"),
            ("BridgefuExecutionId", "bfq-test-1234"),
        ),
        on_stack_failure="DO_NOTHING",
    )


class DeploymentReviewTests(unittest.TestCase):
    def test_parser_accepts_all_ten_release_source_templates(self):
        paths = [
            ROOT / "cloudformation" / "template.yaml",
            *sorted((ROOT / "cloudformation" / "nested").glob("*.yaml")),
            ROOT / "qualification" / "cloudformation" / "disposable-connect.yaml",
            ROOT / "qualification" / "cloudformation" / "template.yaml",
        ]
        self.assertEqual(len(paths), 10)
        for path in paths:
            parsed = review.parse_template_body(path.read_text(encoding="utf-8"))
            self.assertIsInstance(parsed.get("Resources"), dict, path)

    def test_exact_ten_template_create_hierarchy_passes_with_redacted_proof(self):
        aws = ExactCreateHierarchy()
        result = run_review(aws)

        self.assertEqual(
            result.root_change_set_arn, change_set_arn("qualification-root")
        )
        self.assertEqual(result.root_stack_id, stack_arn("qualification-root"))
        self.assertEqual(
            result.proof,
            {
                "producer": review.PRODUCER,
                "version": 1,
                "result": "pass",
                "change_set_type": "CREATE",
                "template_count": 10,
                "nested_change_set_count": 9,
                "max_depth": 2,
                "catalog_sha256": result.proof["catalog_sha256"],
                "hierarchy_sha256": result.proof["hierarchy_sha256"],
                "root_invocation_sha256": result.proof["root_invocation_sha256"],
                "root_change_set_fingerprint": result.proof[
                    "root_change_set_fingerprint"
                ],
                "root_stack_fingerprint": result.proof["root_stack_fingerprint"],
            },
        )
        rendered = str(result.proof)
        self.assertNotIn("arn:aws", rendered)
        self.assertNotIn("version-", rendered)
        self.assertEqual(len(result.proof["catalog_sha256"]), 64)
        self.assertEqual(len(result.proof["hierarchy_sha256"]), 64)

        described = [
            call
            for call in aws.calls
            if call[:2] == ("cloudformation", "describe-change-set")
        ]
        fetched = [
            call for call in aws.calls if call[:2] == ("cloudformation", "get-template")
        ]
        self.assertTrue(all(call[3].startswith("arn:aws:") for call in described))
        self.assertTrue(all(call[3].startswith("arn:aws:") for call in fetched))
        self.assertTrue(
            all(call[-2:] == ("--template-stage", "Original") for call in fetched)
        )

    def test_semantically_equivalent_yaml_get_template_body_passes(self):
        aws = ExactCreateHierarchy()
        aws.remote_templates["configuration"] = """
Resources:
  Marker:
    Properties: {Value: configuration, Type: String}
    Type: AWS::SSM::Parameter
Description: sealed configuration
AWSTemplateFormatVersion: '2010-09-09'
"""
        run_review(aws)

    def test_caller_must_bind_create_request_type(self):
        aws = ExactCreateHierarchy()
        with self.assertRaisesRegex(
            review.DeploymentReviewError, "restricted to CREATE"
        ):
            run_review(aws, expected_change_set_type="UPDATE")
        self.assertEqual(aws.calls, [])

    def test_expected_region_is_bound_before_aws_reads(self):
        aws = ExactCreateHierarchy()
        with self.assertRaisesRegex(review.DeploymentReviewError, "identities differ"):
            review.review_create_change_set(
                aws=aws,
                root_change_set_arn=change_set_arn("qualification-root"),
                root_stack_id=stack_arn("qualification-root"),
                root_template_url=template_url("qualification-root"),
                sealed_catalog=aws.catalog(),
                expected_change_set_type="CREATE",
                expected_region="us-east-1",
                expected_account_id=ACCOUNT,
                expected_root_invocation=root_invocation(),
            )
        self.assertEqual(aws.calls, [])

    def test_expected_account_is_bound_before_aws_reads(self):
        aws = ExactCreateHierarchy()
        with self.assertRaisesRegex(review.DeploymentReviewError, "identities differ"):
            review.review_create_change_set(
                aws=aws,
                root_change_set_arn=change_set_arn("qualification-root"),
                root_stack_id=stack_arn("qualification-root"),
                root_template_url=template_url("qualification-root"),
                sealed_catalog=aws.catalog(),
                expected_change_set_type="CREATE",
                expected_region=REGION,
                expected_account_id="999999999999",
                expected_root_invocation=root_invocation(),
            )
        self.assertEqual(aws.calls, [])

    def test_invalid_expected_coordinates_fail_before_aws_reads(self):
        aws = ExactCreateHierarchy()
        with self.assertRaisesRegex(
            review.DeploymentReviewError, "coordinates are invalid"
        ):
            review.review_create_change_set(
                aws=aws,
                root_change_set_arn=change_set_arn("qualification-root"),
                root_stack_id=stack_arn("qualification-root"),
                root_template_url=template_url("qualification-root"),
                sealed_catalog=aws.catalog(),
                expected_change_set_type="CREATE",
                expected_region="eu-west-1",
                expected_account_id="not-an-account",
                expected_root_invocation=root_invocation(),
            )
        self.assertEqual(aws.calls, [])

    def test_root_invocation_fields_are_bound_exactly(self):
        mutations = {
            "Parameters": [{"ParameterKey": "DeploymentId", "ParameterValue": "wrong"}],
            "Capabilities": [],
            "Tags": [],
            "OnStackFailure": "ROLLBACK",
            "NotificationARNs": ["arn:aws:sns:us-west-2:123456789012:unexpected"],
            "ImportExistingResources": True,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                aws = ExactCreateHierarchy()
                aws.descriptions["qualification-root"][field] = value
                with self.assertRaisesRegex(
                    review.DeploymentReviewError, "invocation differs"
                ):
                    run_review(aws)

        aws = ExactCreateHierarchy()
        aws.stacks["qualification-root"]["RoleARN"] = (
            "arn:aws:iam::123456789012:role/Wrong"
        )
        with self.assertRaisesRegex(review.DeploymentReviewError, "invocation differs"):
            run_review(aws)

    def test_aws_null_normalization_of_false_import_flag_is_accepted(self):
        aws = ExactCreateHierarchy()
        aws.descriptions["qualification-root"]["ImportExistingResources"] = None
        run_review(aws)

    def test_only_null_or_false_import_flag_is_accepted(self):
        for value in (True, 0, "false", [], {}):
            with self.subTest(value=value):
                aws = ExactCreateHierarchy()
                aws.descriptions["qualification-root"][
                    "ImportExistingResources"
                ] = value
                with self.assertRaisesRegex(
                    review.DeploymentReviewError, "invocation differs"
                ):
                    run_review(aws)

    def test_wrong_nested_url_version_is_rejected(self):
        aws = ExactCreateHierarchy()
        wrong = template_url("disposable", "wrong-version")
        aws.templates["qualification-root"]["Resources"]["Disposable"]["Properties"][
            "TemplateURL"
        ] = wrong
        aws.remote_templates["qualification-root"] = copy.deepcopy(
            aws.templates["qualification-root"]
        )
        with self.assertRaisesRegex(review.DeploymentReviewError, "unsealed template"):
            run_review(aws)

    def test_missing_child_change_set_id_is_rejected(self):
        aws = ExactCreateHierarchy()
        del aws.descriptions["qualification-root"]["Changes"][0]["ResourceChange"][
            "ChangeSetId"
        ]
        with self.assertRaises(review.DeploymentReviewError):
            run_review(aws)

    def test_wrong_parent_change_set_linkage_is_rejected(self):
        aws = ExactCreateHierarchy()
        aws.descriptions["configuration"]["ParentChangeSetId"] = change_set_arn(
            "qualification-root"
        )
        with self.assertRaisesRegex(review.DeploymentReviewError, "linkage"):
            run_review(aws)

    def test_wrong_root_change_set_linkage_is_rejected(self):
        aws = ExactCreateHierarchy()
        aws.descriptions["configuration"]["RootChangeSetId"] = change_set_arn("product")
        with self.assertRaisesRegex(review.DeploymentReviewError, "linkage"):
            run_review(aws)

    def test_wrong_nested_stack_linkage_is_rejected(self):
        aws = ExactCreateHierarchy()
        aws.stacks["configuration"]["ParentId"] = stack_arn("qualification-root")
        with self.assertRaisesRegex(review.DeploymentReviewError, "stack linkage"):
            run_review(aws)

    def test_wrong_root_stack_id_is_rejected(self):
        aws = ExactCreateHierarchy()
        aws.descriptions["qualification-root"]["StackId"] = stack_arn("product")
        with self.assertRaisesRegex(review.DeploymentReviewError, "identity or status"):
            run_review(aws)

    def test_non_create_complete_change_set_is_rejected(self):
        aws = ExactCreateHierarchy()
        aws.descriptions["runtime"]["Status"] = "FAILED"
        with self.assertRaisesRegex(review.DeploymentReviewError, "identity or status"):
            run_review(aws)

    def test_create_change_set_cannot_contain_update_action(self):
        aws = ExactCreateHierarchy()
        aws.descriptions["product"]["Changes"][0]["ResourceChange"]["Action"] = "Modify"
        with self.assertRaisesRegex(review.DeploymentReviewError, "non-Add"):
            run_review(aws)

    def test_root_must_be_available_review_in_progress_create(self):
        aws = ExactCreateHierarchy()
        aws.stacks["qualification-root"]["StackStatus"] = "CREATE_IN_PROGRESS"
        with self.assertRaisesRegex(
            review.DeploymentReviewError, "CREATE review stack"
        ):
            run_review(aws)

    def test_semantic_template_drift_is_rejected(self):
        aws = ExactCreateHierarchy()
        aws.remote_templates["connect"]["Description"] = "unsealed mutation"
        with self.assertRaisesRegex(review.DeploymentReviewError, "differs"):
            run_review(aws)

    def test_orphan_catalog_member_is_rejected(self):
        aws = ExactCreateHierarchy()
        catalog = list(aws.catalog())
        catalog[-1] = review.SealedTemplate(
            template_url("foreign"), catalog[-1].parsed_template
        )
        with self.assertRaises(review.DeploymentReviewError):
            run_review(aws, catalog=tuple(catalog))

    def test_duplicate_catalog_member_is_rejected(self):
        aws = ExactCreateHierarchy()
        catalog = list(aws.catalog())
        catalog[-1] = catalog[-2]
        with self.assertRaisesRegex(review.DeploymentReviewError, "duplicate template"):
            run_review(aws, catalog=tuple(catalog))

    def test_missing_catalog_member_is_rejected(self):
        aws = ExactCreateHierarchy()
        with self.assertRaisesRegex(review.DeploymentReviewError, "exactly ten"):
            run_review(aws, catalog=aws.catalog()[:-1])

    def test_duplicate_child_template_is_rejected(self):
        aws = ExactCreateHierarchy()
        product_url = template_url("product")
        aws.templates["qualification-root"]["Resources"]["Disposable"]["Properties"][
            "TemplateURL"
        ] = product_url
        aws.remote_templates["qualification-root"] = copy.deepcopy(
            aws.templates["qualification-root"]
        )
        with self.assertRaisesRegex(review.DeploymentReviewError, "duplicated"):
            run_review(aws)

    def test_duplicate_child_change_set_id_is_rejected(self):
        aws = ExactCreateHierarchy()
        changes = aws.descriptions["qualification-root"]["Changes"]
        changes[1]["ResourceChange"]["ChangeSetId"] = changes[0]["ResourceChange"][
            "ChangeSetId"
        ]
        with self.assertRaisesRegex(review.DeploymentReviewError, "duplicated"):
            run_review(aws)

    def test_orphan_child_change_set_edge_is_rejected(self):
        aws = ExactCreateHierarchy()
        aws.descriptions["configuration"]["Changes"].append(
            {
                "Type": "Resource",
                "ResourceChange": {
                    "Action": "Add",
                    "LogicalResourceId": "UnsealedChild",
                    "ResourceType": "AWS::CloudFormation::Stack",
                    "ChangeSetId": change_set_arn("runtime"),
                },
            }
        )
        with self.assertRaisesRegex(review.DeploymentReviewError, "orphan"):
            run_review(aws)

    def test_present_physical_stack_id_must_match_child(self):
        aws = ExactCreateHierarchy()
        aws.descriptions["qualification-root"]["Changes"][0]["ResourceChange"][
            "PhysicalResourceId"
        ] = stack_arn("product")
        with self.assertRaisesRegex(review.DeploymentReviewError, "physical linkage"):
            run_review(aws)

    def test_nested_stack_without_literal_url_is_rejected(self):
        aws = ExactCreateHierarchy()
        dynamic_url = {"Fn::Sub": "https://${Bucket}/child.yaml"}
        aws.templates["qualification-root"]["Resources"]["Disposable"]["Properties"][
            "TemplateURL"
        ] = dynamic_url
        aws.remote_templates["qualification-root"] = copy.deepcopy(
            aws.templates["qualification-root"]
        )
        with self.assertRaisesRegex(review.DeploymentReviewError, "must be literal"):
            run_review(aws)

    def test_child_change_set_id_must_be_full_arn(self):
        aws = ExactCreateHierarchy()
        aws.descriptions["product"]["Changes"][0]["ResourceChange"]["ChangeSetId"] = (
            "configuration-change-set"
        )
        with self.assertRaisesRegex(
            review.DeploymentReviewError, "identity is invalid"
        ):
            run_review(aws)


if __name__ == "__main__":
    unittest.main()
