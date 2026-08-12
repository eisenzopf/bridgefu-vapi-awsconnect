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
    def test_acm_zero_result_is_not_final_while_stack_is_in_progress(self):
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.created_stack = True
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
                        item
                        for item in value["Tags"]
                        if item["Key"] != "ManagedBy"
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
