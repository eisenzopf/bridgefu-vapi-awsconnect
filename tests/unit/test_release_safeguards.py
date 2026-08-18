from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import unittest
from pathlib import Path
from typing import Any

import jsonschema

from qualification import release_safeguards as safeguards

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "qualification" / "schemas"
ACCOUNT_ID = "123456789012"
REGION = "us-west-2"
HOSTED_ZONE_ID = "Z1234567890"
HOSTED_ZONE_NAME = "example.com"
SIP_HOSTNAME = "bfq-test.example.com"
RUNTIME_IMAGE_ID = "ami-0123456789abcdef0"
RELEASE = "0.1.20"
INSTANCE_TYPE = "c7g.2xlarge"
EXECUTION_ID = "bfq-test-1234"
NAME_SERVERS = ["ns-1.awsdns.com.", "ns-2.awsdns.net."]


def validate_schema(value: Any, name: str) -> None:
    schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(value)


class PreflightAws:
    def __init__(self) -> None:
        self.account_id = ACCOUNT_ID
        self.private_zone = False
        self.occupied_record_names: set[str] = set()
        self.next_route53_record_names: dict[str, str] = {}
        self.image_owner_id = ACCOUNT_ID
        self.image_release = RELEASE
        self.offered_zones = {"us-west-2a", "us-west-2b"}
        self.calls: list[tuple[str, ...]] = []
        self.quotas = {
            safeguards.VPC_QUOTA_CODE: 20,
            safeguards.INTERNET_GATEWAY_QUOTA_CODE: 20,
            safeguards.EIP_QUOTA_CODE: 20,
            safeguards.CONNECT_INSTANCE_QUOTA_CODE: 10,
            safeguards.STANDARD_VCPU_QUOTA_CODE: 256,
        }

    def json(self, command: list[str], timeout: int | None = None) -> dict[str, Any]:
        del timeout
        self.calls.append(tuple(command))
        service, operation = command[:2]
        if (service, operation) == ("sts", "get-caller-identity"):
            return {"Account": self.account_id, "Arn": "redacted", "UserId": "redacted"}
        if (service, operation) == ("iam", "get-role"):
            return {
                "Role": {
                    "Arn": (
                        f"arn:aws:iam::{ACCOUNT_ID}:role/"
                        "BridgefuQualificationCloudFormation"
                    )
                }
            }
        if (service, operation) == ("secretsmanager", "describe-secret"):
            return {
                "ARN": (
                    f"arn:aws:secretsmanager:{REGION}:{ACCOUNT_ID}:"
                    "secret:bridgefu/vapi-key-AbCdEf"
                )
            }
        if (service, operation) == ("route53", "get-hosted-zone"):
            return {
                "HostedZone": {
                    "Id": f"/hostedzone/{HOSTED_ZONE_ID}",
                    "Name": f"{HOSTED_ZONE_NAME}.",
                    "Config": {"PrivateZone": self.private_zone},
                },
                "DelegationSet": {"NameServers": list(NAME_SERVERS)},
            }
        if (service, operation) == ("route53", "list-resource-record-sets"):
            name = command[command.index("--start-record-name") + 1]
            if command[command.index("--max-items") + 1] != "1":
                raise AssertionError("DNS vacancy lookup must inspect one record")
            if name in self.occupied_record_names:
                return {"ResourceRecordSets": [{"Name": name, "Type": "A"}]}
            if name in self.next_route53_record_names:
                return {
                    "ResourceRecordSets": [
                        {
                            "Name": self.next_route53_record_names[name],
                            "Type": "CNAME",
                        }
                    ],
                    "NextToken": "opaque-safe-pagination-token",
                }
            return {"ResourceRecordSets": []}
        if (service, operation) == ("ec2", "describe-images"):
            return {
                "Images": [
                    {
                        "ImageId": RUNTIME_IMAGE_ID,
                        "OwnerId": self.image_owner_id,
                        "State": "available",
                        "Architecture": "arm64",
                        "RootDeviceType": "ebs",
                        "Tags": [
                            {"Key": "ManagedBy", "Value": "bridgefu-vapi-awsconnect"},
                            {"Key": "BridgefuRelease", "Value": self.image_release},
                        ],
                    }
                ]
            }
        if (service, operation) == ("ec2", "describe-instance-type-offerings"):
            return {
                "InstanceTypeOfferings": [
                    {
                        "InstanceType": INSTANCE_TYPE,
                        "LocationType": "availability-zone",
                        "Location": zone,
                    }
                    for zone in sorted(self.offered_zones)
                ]
            }
        if (service, operation) == ("ec2", "describe-instance-types"):
            return {
                "InstanceTypes": [
                    {
                        "InstanceType": INSTANCE_TYPE,
                        "VCpuInfo": {"DefaultVCpus": 8},
                        "MemoryInfo": {"SizeInMiB": 16384},
                        "ProcessorInfo": {"SupportedArchitectures": ["arm64"]},
                    }
                ]
            }
        if (service, operation) == ("ec2", "describe-availability-zones"):
            return {
                "AvailabilityZones": [
                    {
                        "ZoneName": "us-west-2a",
                        "ZoneType": "availability-zone",
                    },
                    {
                        "ZoneName": "us-west-2b",
                        "ZoneType": "availability-zone",
                    },
                ]
            }
        inventory = {
            ("ec2", "describe-vpcs"): {"Vpcs": []},
            ("ec2", "describe-internet-gateways"): {"InternetGateways": []},
            ("ec2", "describe-addresses"): {"Addresses": []},
            ("connect", "list-instances"): {"InstanceSummaryList": []},
            ("ec2", "describe-instances"): {"Reservations": []},
        }
        if (service, operation) in inventory:
            return copy.deepcopy(inventory[(service, operation)])
        if (service, operation) == ("service-quotas", "get-service-quota"):
            code = command[command.index("--quota-code") + 1]
            return {"Quota": {"Value": float(self.quotas[code])}}
        raise AssertionError(f"unexpected AWS command: {command}")


def run_preflight(
    aws: PreflightAws,
    *,
    role_account: str = ACCOUNT_ID,
    secret_account: str = ACCOUNT_ID,
    secret_region: str = REGION,
    resolve_ns: Any = None,
) -> dict[str, Any]:
    resolver = (
        resolve_ns if resolve_ns is not None else lambda _name: list(NAME_SERVERS)
    )
    return safeguards.validate_preflight(
        aws,
        execution_id=EXECUTION_ID,
        expected_account_id=ACCOUNT_ID,
        region=REGION,
        cloudformation_role_arn=(
            f"arn:aws:iam::{role_account}:role/BridgefuQualificationCloudFormation"
        ),
        vapi_secret_arn=(
            f"arn:aws:secretsmanager:{secret_region}:{secret_account}:"
            "secret:bridgefu/vapi-key-AbCdEf"
        ),
        hosted_zone_id=HOSTED_ZONE_ID,
        hosted_zone_name=HOSTED_ZONE_NAME,
        sip_hostname=SIP_HOSTNAME,
        runtime_image_id=RUNTIME_IMAGE_ID,
        release=RELEASE,
        instance_type=INSTANCE_TYPE,
        resolve_ns=resolver,
    )


class Route53RecordAws:
    def __init__(
        self,
        records: list[dict[str, Any]],
        *,
        next_page_marker: str | None = None,
    ):
        self.records = records
        self.next_page_marker = next_page_marker
        self.command: list[str] | None = None

    def json(self, command: list[str], timeout: int | None = None) -> dict[str, Any]:
        del timeout
        self.command = command
        result: dict[str, Any] = {"ResourceRecordSets": copy.deepcopy(self.records)}
        if self.next_page_marker is not None:
            result["NextToken"] = self.next_page_marker
        return result


class Route53VacancyTests(unittest.TestCase):
    def test_unrelated_acm_validation_record_does_not_invalidate_vacancy(self) -> None:
        aws = Route53RecordAws(
            [
                {
                    "Name": "_249e3f07bf33c5327ff0df02a46c3eec.kb.example.com.",
                    "Type": "CNAME",
                }
            ],
            next_page_marker="opaque-safe-pagination-marker",
        )

        self.assertEqual(
            safeguards.exact_route53_records(
                aws, HOSTED_ZONE_ID, "bfq-test.example.com"
            ),
            [],
        )
        self.assertIsNotNone(aws.command)
        command = aws.command or []
        self.assertEqual(command[command.index("--max-items") + 1], "1")

    def test_unrelated_escaped_wildcard_does_not_invalidate_vacancy(self) -> None:
        aws = Route53RecordAws(
            [{"Name": r"\052.preview.example.com.", "Type": "A"}],
            next_page_marker="opaque-safe-pagination-marker",
        )

        self.assertEqual(
            safeguards.exact_route53_records(
                aws, HOSTED_ZONE_ID, "bfq-test.example.com"
            ),
            [],
        )

    def test_exact_record_is_reported_occupied(self) -> None:
        aws = Route53RecordAws(
            [{"Name": "BFQ-Test.Example.Com.", "Type": "AAAA"}],
            next_page_marker="opaque-safe-pagination-marker",
        )

        self.assertEqual(
            safeguards.exact_route53_records(
                aws, HOSTED_ZONE_ID, "bfq-test.example.com"
            ),
            [{"name": "bfq-test.example.com.", "type": "AAAA"}],
        )

    def test_exact_acm_validation_record_is_reported_occupied(self) -> None:
        name = "_249e3f07bf33c5327ff0df02a46c3eec.bfq-test.example.com"
        aws = Route53RecordAws(
            [{"Name": f"{name}.", "Type": "CNAME"}],
            next_page_marker="opaque-safe-pagination-marker",
        )

        self.assertEqual(
            safeguards.exact_route53_records(aws, HOSTED_ZONE_ID, name),
            [{"name": f"{name}.", "type": "CNAME"}],
        )

    def test_route53_record_name_rejects_nonleading_underscore(self) -> None:
        with self.assertRaisesRegex(
            safeguards.SafeguardError, "Route53 record name is invalid"
        ):
            safeguards.exact_route53_records(
                Route53RecordAws([]),
                HOSTED_ZONE_ID,
                "bfq_test.example.com",
            )


class TelemetryAws:
    def __init__(
        self,
        *,
        cpu_peak: float = 59.0,
        memory_peak: float = 59.0,
        sparse: bool = False,
        startup_events: int = 0,
    ) -> None:
        self.cpu_peak = cpu_peak
        self.memory_peak = memory_peak
        self.sparse = sparse
        self.startup_events = startup_events

    def json(self, command: list[str], timeout: int | None = None) -> dict[str, Any]:
        del timeout
        service, operation = command[:2]
        if (service, operation) == ("cloudwatch", "get-metric-statistics"):
            metric = command[command.index("--metric-name") + 1]
            timestamps = ["2026-08-16T20:00:05Z"]
            if not self.sparse:
                timestamps.append("2026-08-16T20:00:25Z")
            if metric == "cpu_usage_idle":
                minimum = 100.0 - self.cpu_peak
                maximum = max(minimum, 80.0)
            elif metric == "mem_used_percent":
                minimum = min(20.0, self.memory_peak)
                maximum = self.memory_peak
            else:
                raise AssertionError(f"unexpected metric: {metric}")
            return {
                "Datapoints": [
                    {
                        "Timestamp": timestamp,
                        "Minimum": minimum,
                        "Maximum": maximum,
                    }
                    for timestamp in timestamps
                ]
            }
        if (service, operation) == ("logs", "filter-log-events"):
            return {
                "events": [
                    {"eventId": f"event-{index}"}
                    for index in range(self.startup_events)
                ]
            }
        raise AssertionError(f"unexpected AWS command: {command}")


def collect_telemetry(aws: TelemetryAws) -> dict[str, Any]:
    return safeguards.collect_active_call_telemetry(
        aws,
        execution_id=EXECUTION_ID,
        instance_id="i-0123456789abcdef0",
        instance_type=INSTANCE_TYPE,
        vcpus=8,
        memory_mib=16384,
        runtime_log_group="/bridgefu/qualification/runtime",
        window_started_at="2026-08-16T20:00:00Z",
        window_ended_at="2026-08-16T20:00:30Z",
        deadline_seconds=0,
        sleep=lambda _seconds: None,
        monotonic=lambda: 0.0,
    )


class Clock:
    def __init__(self) -> None:
        self.seconds = 0.0
        self.base = dt.datetime(2026, 8, 16, 20, 0, tzinfo=dt.UTC)

    def monotonic(self) -> float:
        return self.seconds

    def sleep(self, seconds: float) -> None:
        self.seconds += seconds

    def observed_at(self) -> str:
        return (
            (self.base + dt.timedelta(seconds=self.seconds))
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )


class ReleaseSafeguardTests(unittest.TestCase):
    def test_preflight_validates_the_complete_success_evidence_schema(self) -> None:
        aws = PreflightAws()
        evidence = run_preflight(aws)

        self.assertTrue(evidence["passed"])
        self.assertTrue(all(evidence["checks"].values()))
        self.assertEqual(
            evidence["runtime_image_sha256"],
            hashlib.sha256(RUNTIME_IMAGE_ID.encode("ascii")).hexdigest(),
        )
        offering = next(
            call
            for call in aws.calls
            if call[:2] == ("ec2", "describe-instance-type-offerings")
        )
        self.assertEqual(
            offering[offering.index("--location-type") + 1], "availability-zone"
        )
        validate_schema(evidence, "preflight-v1.schema.json")

    def test_preflight_rejects_wrong_active_account_before_other_aws_reads(
        self,
    ) -> None:
        aws = PreflightAws()
        aws.account_id = "210987654321"

        with self.assertRaisesRegex(safeguards.SafeguardError, "active AWS account"):
            run_preflight(aws)

        self.assertEqual(aws.calls, [("sts", "get-caller-identity")])

    def test_preflight_rejects_role_and_secret_identity_mismatches(self) -> None:
        cases = (
            ({"role_account": "210987654321"}, "CloudFormation service role"),
            ({"secret_account": "210987654321"}, "Vapi secret"),
            ({"secret_region": "us-east-1"}, "Vapi secret"),
        )
        for arguments, message in cases:
            with self.subTest(arguments=arguments):
                aws = PreflightAws()
                with self.assertRaisesRegex(safeguards.SafeguardError, message):
                    run_preflight(aws, **arguments)
                self.assertEqual(aws.calls, [("sts", "get-caller-identity")])

    def test_preflight_rejects_private_misdelegated_or_occupied_dns(self) -> None:
        private = PreflightAws()
        private.private_zone = True
        with self.assertRaisesRegex(safeguards.SafeguardError, "exact public zone"):
            run_preflight(private)

        misdelegated = PreflightAws()
        with self.assertRaisesRegex(safeguards.SafeguardError, "delegation"):
            run_preflight(
                misdelegated,
                resolve_ns=lambda _name: ["ns-3.awsdns.org.", "ns-4.awsdns.co.uk."],
            )

        occupied = PreflightAws()
        occupied.occupied_record_names.add(f"{SIP_HOSTNAME}.")
        with self.assertRaisesRegex(safeguards.SafeguardError, "not vacant"):
            run_preflight(occupied)

    def test_preflight_rejects_candidate_ami_owner_or_release_drift(self) -> None:
        cases = (("image_owner_id", "210987654321"), ("image_release", "0.1.19"))
        for attribute, value in cases:
            with self.subTest(attribute=attribute):
                aws = PreflightAws()
                setattr(aws, attribute, value)
                with self.assertRaisesRegex(safeguards.SafeguardError, "candidate AMI"):
                    run_preflight(aws)

    def test_preflight_requires_one_unit_of_quota_reserve_after_deployment(
        self,
    ) -> None:
        aws = PreflightAws()
        aws.quotas[safeguards.EIP_QUOTA_CODE] = 1

        with self.assertRaisesRegex(safeguards.SafeguardError, "elastic_ips"):
            run_preflight(aws)

        internet_gateway = PreflightAws()
        internet_gateway.quotas[safeguards.INTERNET_GATEWAY_QUOTA_CODE] = 1
        with self.assertRaisesRegex(safeguards.SafeguardError, "internet_gateways"):
            run_preflight(internet_gateway)

    def test_preflight_requires_the_runtime_type_in_both_selected_zones(self) -> None:
        aws = PreflightAws()
        aws.offered_zones.remove("us-west-2a")

        with self.assertRaisesRegex(
            safeguards.SafeguardError, "every selected availability zone"
        ):
            run_preflight(aws)

        offering_call = next(
            call
            for call in aws.calls
            if call[:2] == ("ec2", "describe-instance-type-offerings")
        )
        self.assertIn("--location-type", offering_call)
        self.assertEqual(
            offering_call[offering_call.index("--location-type") + 1],
            "availability-zone",
        )
        self.assertIn("Name=location,Values=us-west-2a,us-west-2b", offering_call)
        self.assertFalse(
            any(
                call[:2]
                in {
                    ("ec2", "describe-nat-gateways"),
                    ("ec2", "describe-subnets"),
                }
                for call in aws.calls
            )
        )

    def test_deployed_runtime_is_exact_and_schema_valid(self) -> None:
        class Aws:
            @staticmethod
            def json(command, timeout=120):
                self.assertEqual(
                    command,
                    [
                        "ec2",
                        "describe-instances",
                        "--instance-ids",
                        "i-0123456789abcdef0",
                    ],
                )
                self.assertEqual(timeout, 120)
                return {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-0123456789abcdef0",
                                    "ImageId": RUNTIME_IMAGE_ID,
                                    "InstanceType": INSTANCE_TYPE,
                                    "Architecture": "arm64",
                                    "State": {"Name": "running"},
                                    "Placement": {"AvailabilityZone": "us-west-2a"},
                                    "Tags": [
                                        {
                                            "Key": "Project",
                                            "Value": "bridgefu-vapi-awsconnect",
                                        },
                                        {
                                            "Key": "ManagedBy",
                                            "Value": "bridgefu-cloudformation",
                                        },
                                        {
                                            "Key": "BridgefuExecutionId",
                                            "Value": EXECUTION_ID,
                                        },
                                        {
                                            "Key": "BridgefuRecipe",
                                            "Value": (
                                                "vapi-amazon-connect-screen-pop@1"
                                            ),
                                        },
                                    ],
                                }
                            ]
                        }
                    ]
                }

        proof = safeguards.validate_deployed_runtime(
            Aws(),
            execution_id=EXECUTION_ID,
            region=REGION,
            expected_account_id=ACCOUNT_ID,
            instance_id="i-0123456789abcdef0",
            runtime_image_id=RUNTIME_IMAGE_ID,
            instance_type=INSTANCE_TYPE,
            expected_recipe="vapi-amazon-connect-screen-pop@1",
        )

        self.assertEqual(
            proof["runtime_image_sha256"],
            hashlib.sha256(RUNTIME_IMAGE_ID.encode("ascii")).hexdigest(),
        )
        validate_schema(proof, "runtime-deployment-v1.schema.json")

    def test_deployed_runtime_rejects_a_different_candidate_ami(self) -> None:
        class Aws:
            @staticmethod
            def json(_command, timeout=120):
                del timeout
                return {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-0123456789abcdef0",
                                    "ImageId": "ami-11111111111111111",
                                    "InstanceType": INSTANCE_TYPE,
                                    "Architecture": "arm64",
                                    "State": {"Name": "running"},
                                    "Placement": {"AvailabilityZone": "us-west-2a"},
                                    "Tags": [],
                                }
                            ]
                        }
                    ]
                }

        with self.assertRaisesRegex(safeguards.SafeguardError, "candidate contract"):
            safeguards.validate_deployed_runtime(
                Aws(),
                execution_id=EXECUTION_ID,
                region=REGION,
                expected_account_id=ACCOUNT_ID,
                instance_id="i-0123456789abcdef0",
                runtime_image_id=RUNTIME_IMAGE_ID,
                instance_type=INSTANCE_TYPE,
                expected_recipe="vapi-amazon-connect-screen-pop@1",
            )

    def test_active_call_telemetry_passes_and_validates_its_schema(self) -> None:
        evidence = collect_telemetry(TelemetryAws())

        self.assertEqual(evidence["host_cpu_peak_percent"], 59.0)
        self.assertEqual(evidence["host_memory_peak_percent"], 59.0)
        self.assertEqual(evidence["cpu_sample_count"], 2)
        self.assertEqual(evidence["memory_sample_count"], 2)
        self.assertTrue(evidence["passed"])
        validate_schema(evidence, "active-call-telemetry-v1.schema.json")

    def test_active_call_telemetry_rejects_exactly_sixty_percent(self) -> None:
        for aws in (
            TelemetryAws(cpu_peak=60.0),
            TelemetryAws(memory_peak=60.0),
        ):
            with self.subTest(aws=aws):
                with self.assertRaisesRegex(
                    safeguards.SafeguardError, "capacity or restart gate"
                ):
                    collect_telemetry(aws)

    def test_active_call_telemetry_rejects_sparse_samples(self) -> None:
        with self.assertRaisesRegex(
            safeguards.SafeguardError, "samples did not converge"
        ):
            collect_telemetry(TelemetryAws(sparse=True))

    def test_active_call_telemetry_rejects_a_bridgefu_start_event(self) -> None:
        with self.assertRaisesRegex(
            safeguards.SafeguardError, "capacity or restart gate"
        ):
            collect_telemetry(TelemetryAws(startup_events=1))

    def test_zero_resource_proof_requires_three_observations_spanning_a_minute(
        self,
    ) -> None:
        clock = Clock()
        observations = 0

        def observe() -> dict[str, Any]:
            nonlocal observations
            observations += 1
            return safeguards.normalize_zero_observation(
                safeguards.empty_resource_counts(), observed_at=clock.observed_at()
            )

        proof = safeguards.stable_zero_resource_proof(
            observe,
            execution_id=EXECUTION_ID,
            ownership_sha256="a" * 64,
            owned_resource_count=17,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
        )

        self.assertEqual(observations, 3)
        self.assertEqual(len(proof["observations"]), 3)
        first = safeguards._parse_timestamp(
            proof["observations"][0]["observed_at"], "first"
        )
        last = safeguards._parse_timestamp(
            proof["observations"][-1]["observed_at"], "last"
        )
        self.assertGreaterEqual((last - first).total_seconds(), 60)
        validate_schema(proof, "zero-resource-proof-v1.schema.json")

    def test_zero_resource_proof_resets_after_a_nonempty_observation(self) -> None:
        clock = Clock()
        calls = 0

        def observe() -> dict[str, Any]:
            nonlocal calls
            calls += 1
            counts = safeguards.empty_resource_counts()
            if calls == 2:
                counts["ec2_instances"] = 1
            return safeguards.normalize_zero_observation(
                counts, observed_at=clock.observed_at()
            )

        proof = safeguards.stable_zero_resource_proof(
            observe,
            execution_id=EXECUTION_ID,
            ownership_sha256="b" * 64,
            owned_resource_count=1,
            sleep=clock.sleep,
            monotonic=clock.monotonic,
        )

        self.assertEqual(calls, 5)
        self.assertEqual(
            [item["observed_at"] for item in proof["observations"]],
            [
                "2026-08-16T20:00:35Z",
                "2026-08-16T20:01:05Z",
                "2026-08-16T20:01:35Z",
            ],
        )

    def test_zero_resource_proof_cannot_pass_with_only_two_observations(self) -> None:
        clock = Clock()

        def observe() -> dict[str, Any]:
            return safeguards.normalize_zero_observation(
                safeguards.empty_resource_counts(), observed_at=clock.observed_at()
            )

        with self.assertRaisesRegex(safeguards.SafeguardError, "did not converge"):
            safeguards.stable_zero_resource_proof(
                observe,
                execution_id=EXECUTION_ID,
                ownership_sha256="c" * 64,
                owned_resource_count=0,
                timeout_seconds=59,
                sleep=clock.sleep,
                monotonic=clock.monotonic,
            )

    def test_stack_inventory_rejects_an_unknown_resource_type(self) -> None:
        class Aws:
            def json(
                self, command: list[str], timeout: int | None = None
            ) -> dict[str, Any]:
                del timeout
                if command[1] == "describe-stacks":
                    return {
                        "Stacks": [
                            {
                                "StackId": (
                                    "arn:aws:cloudformation:us-west-2:123456789012:"
                                    "stack/bfq-test/01234567-89ab-cdef-0123-456789abcdef"
                                )
                            }
                        ]
                    }
                if command[1] == "list-stack-resources":
                    return {
                        "StackResourceSummaries": [
                            {
                                "ResourceType": "AWS::Mystery::UnmodeledThing",
                                "PhysicalResourceId": "mystery-1234",
                            }
                        ]
                    }
                raise AssertionError(f"unexpected AWS command: {command}")

        with self.assertRaisesRegex(safeguards.SafeguardError, "unmodeled"):
            safeguards.stack_ownership_inventory(Aws(), "bfq-test-stack")

    def test_tag_inventory_reads_every_bounded_page(self) -> None:
        class Aws:
            def __init__(self) -> None:
                self.calls: list[list[str]] = []

            def json(
                self, command: list[str], timeout: int | None = None
            ) -> dict[str, Any]:
                del timeout
                self.calls.append(command)
                if "--pagination-token" not in command:
                    return {
                        "ResourceTagMappingList": [
                            {"ResourceARN": "arn:aws:ec2:us-west-2:123:instance/i-1"}
                        ],
                        "PaginationToken": "more-results-exist",
                    }
                self.assert_token(command)
                return {
                    "ResourceTagMappingList": [
                        {"ResourceARN": "arn:aws:ec2:us-west-2:123:instance/i-2"}
                    ],
                    "PaginationToken": "",
                }

            @staticmethod
            def assert_token(command: list[str]) -> None:
                offset = command.index("--pagination-token")
                if command[offset + 1] != "more-results-exist":
                    raise AssertionError("wrong pagination token")

        aws = Aws()
        self.assertEqual(
            safeguards.tagged_resource_arns(aws, EXECUTION_ID),
            [
                "arn:aws:ec2:us-west-2:123:instance/i-1",
                "arn:aws:ec2:us-west-2:123:instance/i-2",
            ],
        )
        self.assertEqual(len(aws.calls), 2)
        self.assertTrue(all("--no-paginate" in call for call in aws.calls))

    def test_tag_inventory_rejects_a_repeated_pagination_token(self) -> None:
        class Aws:
            def json(
                self, command: list[str], timeout: int | None = None
            ) -> dict[str, Any]:
                del command, timeout
                return {
                    "ResourceTagMappingList": [],
                    "PaginationToken": "repeated-token",
                }

        with self.assertRaisesRegex(safeguards.SafeguardError, "inventory is invalid"):
            safeguards.tagged_resource_arns(Aws(), EXECUTION_ID)


if __name__ == "__main__":
    unittest.main()
