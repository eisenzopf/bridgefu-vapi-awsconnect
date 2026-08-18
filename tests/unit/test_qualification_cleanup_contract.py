from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "qualification_controller_cleanup_contract",
    ROOT / "qualification" / "controller.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("qualification controller could not be imported")
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


class ProbeRunner:
    def __init__(self, error: str) -> None:
        self.error = error

    def probe(self, arguments, timeout=60):
        return 255, "", self.error


class QualificationCleanupContractTests(unittest.TestCase):
    def test_deleted_stack_history_is_absent_but_live_states_remain_present(self):
        stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/bridgefu-bfq-test1234/stack-1234"
        )

        class Aws:
            def __init__(self, status):
                self.status = status

            def exists(self, arguments):
                self.arguments = arguments
                return True

            def json(self, arguments, timeout=120):
                self.arguments = arguments
                self.timeout = timeout
                return {
                    "Stacks": [
                        {
                            "StackId": stack_id,
                            "StackName": "bridgefu-bfq-test1234",
                            "StackStatus": self.status,
                        }
                    ]
                }

        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.aws = Aws("DELETE_COMPLETE")
        self.assertFalse(controller.cloudformation_stack_is_live(stack_id))
        self.assertEqual(
            controller.aws.arguments,
            [
                "cloudformation",
                "describe-stacks",
                "--stack-name",
                stack_id,
            ],
        )

        for status in (
            "REVIEW_IN_PROGRESS",
            "CREATE_COMPLETE",
            "DELETE_IN_PROGRESS",
            "DELETE_FAILED",
        ):
            with self.subTest(status=status):
                controller.aws = Aws(status)
                self.assertTrue(controller.cloudformation_stack_is_live(stack_id))

        controller.aws = mock.Mock()
        controller.aws.exists.return_value = False
        self.assertFalse(controller.cloudformation_stack_is_live(stack_id))
        controller.aws.json.assert_not_called()

    def test_unexecuted_nested_review_uses_exact_delete_change_set(self):
        root_change_set = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "changeSet/bridgefu-bfq-test1234-review/change-1234"
        )
        root_stack = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/bridgefu-bfq-test1234/stack-1234"
        )
        child_change_set = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "changeSet/child-review/change-5678"
        )
        child_stack = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/child-review/stack-5678"
        )

        class Aws:
            def __init__(self):
                self.change_set_deleted = False
                self.stack_deleted = False
                self.text_calls = []

            def json(self, arguments, timeout=120):
                self.assert_timeout = timeout
                if arguments[:2] == ["cloudformation", "describe-stacks"]:
                    return {
                        "Stacks": [
                            {
                                "StackId": root_stack,
                                "StackName": "bridgefu-bfq-test1234",
                                "StackStatus": "REVIEW_IN_PROGRESS",
                            }
                        ]
                    }
                if arguments[:2] == ["cloudformation", "describe-change-set"]:
                    return {
                        "ChangeSetId": root_change_set,
                        "StackId": root_stack,
                        "ParentChangeSetId": None,
                        "RootChangeSetId": None,
                        "ExecutionStatus": "AVAILABLE",
                        "Status": "CREATE_COMPLETE",
                        "IncludeNestedStacks": True,
                    }
                if arguments[:2] == ["cloudformation", "list-stack-resources"]:
                    return {"StackResourceSummaries": []}
                raise AssertionError(arguments)

            def text(self, arguments, timeout=900):
                self.text_calls.append((arguments, timeout))
                if arguments[:2] == ["cloudformation", "delete-change-set"]:
                    self.change_set_deleted = True
                elif arguments[:2] == ["cloudformation", "delete-stack"]:
                    self.stack_deleted = True
                else:
                    raise AssertionError(arguments)
                return ""

            def exists(self, arguments):
                if arguments[1] == "describe-change-set":
                    return not self.change_set_deleted
                if arguments[1] == "describe-stacks":
                    return not self.stack_deleted
                raise AssertionError(arguments)

        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.args = SimpleNamespace(
            execution_id="bfq-test1234",
            region="us-west-2",
            expected_account_id="123456789012",
        )
        controller.stack_name = "bridgefu-bfq-test1234"
        controller.root_change_set_arn = root_change_set
        controller.reviewed_change_set_arns = (root_change_set, child_change_set)
        controller.reviewed_stack_ids = (root_stack, child_stack)
        controller.aws = Aws()

        self.assertTrue(controller.delete_unexecuted_change_set_hierarchy(root_stack))
        self.assertEqual(
            controller.aws.text_calls,
            [
                (
                    [
                        "cloudformation",
                        "delete-change-set",
                        "--change-set-name",
                        root_change_set,
                    ],
                    180,
                ),
                (
                    [
                        "cloudformation",
                        "delete-stack",
                        "--stack-name",
                        root_stack,
                    ],
                    180,
                ),
            ],
        )

    def test_partial_outputs_track_versioned_acm_journal_bucket(self):
        output = Path(CONTROLLER.tempfile.mkdtemp(prefix="acm-journal-test-"))
        root_stack = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/bridgefu-bfq-test1234/stack-1234"
        )
        journal = {
            "schema_version": 1,
            "producer": CONTROLLER.ACM_OWNERSHIP_PRODUCER,
            "execution_id": "bfq-test1234",
            "region": "us-west-2",
            "public_hosted_zone_id": "Z123",
            "certificate_arn": (
                "arn:aws:acm:us-west-2:123456789012:certificate/abc-123"
            ),
            "record_sets": [],
            "ownership_sha256": "a" * 64,
            "created_at": "2026-08-16T20:00:00Z",
            "redacted": True,
        }

        class Aws:
            def json(self, arguments, timeout=120):
                if arguments[:2] == ["cloudformation", "describe-stacks"]:
                    return {
                        "Stacks": [
                            {
                                "StackId": root_stack,
                                "StackStatus": "CREATE_FAILED",
                            }
                        ]
                    }
                if arguments[:2] == ["s3api", "put-object"]:
                    self.put_arguments = arguments
                    return {"VersionId": "journal-version-1", "ETag": "redacted"}
                raise AssertionError(arguments)

        try:
            controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
            controller.args = SimpleNamespace(
                execution_id="bfq-test1234",
                region="us-west-2",
                hosted_zone_id="Z123",
                hosted_zone_name="example.com",
                output=output,
            )
            controller.created_stack = True
            controller.change_set_execution_attempted = True
            controller.stack_id = root_stack
            controller.stack_name = "bridgefu-bfq-test1234"
            controller.outputs = {}
            controller.acm_validation_discovery_complete = False
            controller.acm_validation_journal = None
            controller.acm_validation_journal_object = None
            controller.acm_validation_journal_bucket = None
            controller.acm_validation_journal_key = None
            controller.acm_validation_journal_version_id = None
            controller.aws = Aws()
            with (
                mock.patch.object(
                    controller, "resolve_existing_stack_id", return_value=root_stack
                ),
                mock.patch.object(
                    CONTROLLER,
                    "discover_acm_validation_ownership",
                    return_value=journal,
                ),
                mock.patch.object(
                    CONTROLLER,
                    "discover_stack_output",
                    return_value="bridgefu-artifacts-test",
                ),
            ):
                controller.ensure_acm_validation_journal()

            self.assertEqual(
                controller.outputs["ArtifactBucket"], "bridgefu-artifacts-test"
            )
            self.assertEqual(
                controller.acm_validation_journal_bucket,
                "bridgefu-artifacts-test",
            )
            self.assertEqual(
                controller.acm_validation_journal_key,
                "qualification/bfq-test1234/ownership/acm-validation-records.json",
            )
            self.assertEqual(
                controller.acm_validation_journal_version_id,
                "journal-version-1",
            )
            controller.outputs = {}
            self.assertEqual(
                controller.qualification_artifact_bucket(),
                "bridgefu-artifacts-test",
            )
        finally:
            CONTROLLER.shutil.rmtree(output, ignore_errors=True)

    def test_acm_zero_result_is_not_final_while_stack_is_in_progress(self):
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.created_stack = True
        controller.change_set_execution_attempted = True
        controller.stack_id = (
            "arn:aws:cloudformation:us-west-2:123456789012:"
            "stack/bridgefu-bfq-test1234/01234567-89ab-cdef-0123-456789abcdef"
        )
        controller.acm_validation_discovery_complete = False
        controller.stack_name = "bridgefu-bfq-test1234"
        controller.outputs = {}
        controller.args = SimpleNamespace(
            execution_id="bfq-test1234",
            hosted_zone_id="Z123",
            hosted_zone_name="example.com",
        )
        controller.aws = mock.Mock()
        controller.aws.exists.return_value = True
        controller.aws.json.return_value = {
            "Stacks": [{"StackStatus": "CREATE_IN_PROGRESS"}]
        }
        with (
            mock.patch.object(
                CONTROLLER, "discover_acm_validation_ownership", return_value=None
            ),
            self.assertRaisesRegex(
                CONTROLLER.QualificationError, "not stable while stack changes"
            ),
        ):
            controller.ensure_acm_validation_journal()
        self.assertFalse(controller.acm_validation_discovery_complete)

    def test_route53_no_such_hosted_zone_is_exact_absence(self):
        aws = CONTROLLER.Aws(
            "us-west-2",
            ProbeRunner(
                "An error occurred (NoSuchHostedZone) when calling the GetHostedZone operation: No hosted zone found with ID: Z123"
            ),
        )
        self.assertFalse(aws.exists(["route53", "get-hosted-zone", "--id", "Z123"]))
        ambiguous = CONTROLLER.Aws(
            "us-west-2", ProbeRunner("network error: resource not found")
        )
        with self.assertRaisesRegex(
            CONTROLLER.QualificationError, "existence check failed"
        ):
            ambiguous.exists(["route53", "get-hosted-zone", "--id", "Z123"])

    def test_cloudformation_change_set_not_found_is_exact_absence(self):
        for code in ("ChangeSetNotFound", "ChangeSetNotFoundException"):
            with self.subTest(code=code):
                aws = CONTROLLER.Aws(
                    "us-west-2",
                    ProbeRunner(
                        "aws: [ERROR]: An error occurred "
                        f"({code}) when calling the DescribeChangeSet operation: "
                        "ChangeSet [arn:aws:cloudformation:us-west-2:123456789012:"
                        "changeSet/test/id] does not exist"
                    ),
                )
                self.assertFalse(
                    aws.exists(
                        [
                            "cloudformation",
                            "describe-change-set",
                            "--change-set-name",
                            "arn:aws:cloudformation:us-west-2:123456789012:"
                            "changeSet/test/id",
                        ]
                    )
                )

    def test_early_cleanup_initializes_vapi_for_exact_output_ids(self):
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.outputs = {"VapiAssistantId": "assistant_1234"}
        controller.temp_phone_id = None
        controller.vapi = None
        controller.aws = mock.Mock()
        controller.aws.secret.return_value = "private-test-key"
        controller.args = SimpleNamespace(vapi_secret_arn=mock.sentinel.secret_arn)
        with mock.patch.object(CONTROLLER, "Vapi") as vapi_class:
            controller.initialize_cleanup_vapi_verifier()
        vapi_class.assert_called_once_with("private-test-key")
        self.assertIs(controller.vapi, vapi_class.return_value)

    def test_primary_and_cleanup_failures_are_both_preserved(self):
        combined = CONTROLLER.combine_failures(
            CONTROLLER.QualificationError("live smoke failed"),
            CONTROLLER.QualificationError("ACM record remains"),
        )
        self.assertEqual(
            str(combined),
            "live smoke failed; cleanup failed: ACM record remains",
        )

    def test_acm_exact_record_cleanup_refuses_changed_record(self):
        owned = {
            "execution_id": "bfq-test1234",
            "region": "us-west-2",
            "public_hosted_zone_id": "Z123",
            "certificate_arn": "arn:aws:acm:us-west-2:123456789012:certificate/abc-123",
            "record_sets": [
                {
                    "name": "_abc.bfq-test1234.example.com.",
                    "type": "CNAME",
                    "ttl": 300,
                    "resource_records": ["_proof.acm-validations.aws."],
                }
            ],
        }
        journal = {
            "schema_version": 1,
            "producer": CONTROLLER.ACM_OWNERSHIP_PRODUCER,
            **owned,
            "ownership_sha256": CONTROLLER.canonical_sha256(owned),
            "created_at": "2026-08-11T04:20:00Z",
            "redacted": True,
        }
        changed = {
            **owned["record_sets"][0],
            "resource_records": ["_customer-value.example.com."],
        }
        with mock.patch.object(CONTROLLER, "route53_record_set", return_value=changed):
            with self.assertRaisesRegex(
                CONTROLLER.QualificationError, "changed after ownership seal"
            ):
                CONTROLLER.delete_acm_validation_records_exact(mock.Mock(), journal)

    def test_acm_discovery_binds_certificate_tags_and_exact_dns_values(self):
        certificate_arn = "arn:aws:acm:us-west-2:123456789012:certificate/abc-123"

        class Aws:
            region = "us-west-2"

            def json(self, arguments, timeout=900):
                if arguments[:2] == ["cloudformation", "list-stack-resources"]:
                    return {
                        "StackResourceSummaries": [
                            {
                                "ResourceType": "AWS::CertificateManager::Certificate",
                                "PhysicalResourceId": certificate_arn,
                            }
                        ]
                    }
                if arguments[:2] == ["acm", "list-tags-for-certificate"]:
                    return {
                        "Tags": [
                            {"Key": "Project", "Value": "bridgefu-vapi-awsconnect"},
                            {"Key": "ManagedBy", "Value": "bridgefu-cloudformation"},
                            {"Key": "BridgefuExecutionId", "Value": "bfq-test1234"},
                            {"Key": "BridgefuRecipe", "Value": CONTROLLER.RECIPE},
                        ]
                    }
                if arguments[:2] == ["acm", "describe-certificate"]:
                    return {
                        "Certificate": {
                            "DomainValidationOptions": [
                                {
                                    "ResourceRecord": {
                                        "Name": "_abc.bfq-test1234.example.com.",
                                        "Type": "CNAME",
                                        "Value": "_proof.acm-validations.aws.",
                                    }
                                },
                                {
                                    "ResourceRecord": {
                                        "Name": "_def.control.bfq-test1234.example.com.",
                                        "Type": "CNAME",
                                        "Value": "_proof2.acm-validations.aws.",
                                    }
                                },
                            ]
                        }
                    }
                if arguments[:2] == ["route53", "list-resource-record-sets"]:
                    name = arguments[arguments.index("--start-record-name") + 1]
                    value = (
                        "_proof2.acm-validations.aws."
                        if ".control." in name
                        else "_proof.acm-validations.aws."
                    )
                    return {
                        "ResourceRecordSets": [
                            {
                                "Name": name,
                                "Type": "CNAME",
                                "TTL": 300,
                                "ResourceRecords": [{"Value": value}],
                            }
                        ]
                    }
                raise AssertionError(arguments)

        journal = CONTROLLER.discover_acm_validation_ownership(
            Aws(),
            "bridgefu-bfq-test1234",
            "bfq-test1234",
            "Z123",
            "bfq-test1234.example.com",
        )
        self.assertIsNotNone(journal)
        self.assertEqual(journal["certificate_arn"], certificate_arn)
        self.assertEqual(len(journal["record_sets"]), 2)
        CONTROLLER.validate_acm_validation_ownership(journal)

        class WrongManagedBy(Aws):
            def json(self, arguments, timeout=900):
                value = super().json(arguments, timeout)
                if arguments[:2] == ["acm", "list-tags-for-certificate"]:
                    value["Tags"] = [
                        item for item in value["Tags"] if item["Key"] != "ManagedBy"
                    ] + [{"Key": "ManagedBy", "Value": "bridgefu-qualification"}]
                return value

        with self.assertRaisesRegex(
            CONTROLLER.QualificationError, "certificate ownership is invalid"
        ):
            CONTROLLER.discover_acm_validation_ownership(
                WrongManagedBy(),
                "bridgefu-bfq-test1234",
                "bfq-test1234",
                "Z123",
                "bfq-test1234.example.com",
            )


if __name__ == "__main__":
    unittest.main()
