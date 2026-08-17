#!/usr/bin/env python3
"""Verify cross-artifact qualification relations before signing a candidate."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SHA256 = re.compile(r"^[0-9a-f]{64}$")
AMI = re.compile(r"^ami-[0-9a-f]{17}$")
REGIONS = {"us-east-1", "us-west-2"}
ZERO_RESOURCE_KEYS = {
    "acm_certificates",
    "api_gateway_apis",
    "backup_resources",
    "cloudformation_stacks",
    "cloudwatch_alarms",
    "cloudwatch_dashboards",
    "cloudwatch_log_groups",
    "connect_resources",
    "dynamodb_tables",
    "ec2_elastic_ips",
    "ec2_instances",
    "ec2_network_interfaces",
    "ec2_security_groups",
    "ec2_volumes",
    "ec2_vpc_endpoints",
    "ec2_vpcs",
    "execution_tagged_resources",
    "iam_resources",
    "lambda_functions",
    "other_stack_resources",
    "route53_private_zones",
    "route53_public_records",
    "s3_object_versions",
    "secrets",
    "sns_resources",
    "vapi_resources",
}


class RelationError(RuntimeError):
    """Sealed qualification artifacts do not describe one exact execution."""


def _read(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RelationError(f"{label} is unreadable") from error
    if not isinstance(value, Mapping):
        raise RelationError(f"{label} is invalid")
    return value


def _instant(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise RelationError(f"{label} timestamp is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise RelationError(f"{label} timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise RelationError(f"{label} timestamp is not UTC")
    return parsed


def verify_documents(
    *,
    evidence: Mapping[str, Any],
    zero: Mapping[str, Any],
    proof: Mapping[str, Any],
    proof_bytes: bytes,
    regions: Mapping[str, Any],
    release: str,
    bridgefu_commit: str,
    region: str,
    expected_execution_id: str,
) -> dict[str, Any]:
    """Verify an exact in-memory qualification artifact set."""
    if region not in REGIONS:
        raise RelationError("region is unsupported")
    runtime = evidence.get("runtime_deployment")
    preflight = evidence.get("preflight")
    scenarios = evidence.get("scenarios")
    if (
        evidence.get("schema_version") != 2
        or evidence.get("release") != release
        or evidence.get("bridgefu_commit") != bridgefu_commit
        or evidence.get("region") != region
        or not isinstance(evidence.get("execution_id"), str)
        or not isinstance(runtime, Mapping)
        or not isinstance(preflight, Mapping)
        or not isinstance(scenarios, list)
        or len(scenarios) != 2
    ):
        raise RelationError("evidence identity changed")
    execution = evidence["execution_id"]
    if execution != expected_execution_id:
        raise RelationError(
            "evidence execution is not the originating workflow execution"
        )
    region_record = regions.get(region)
    ami = region_record.get("ami_id") if isinstance(region_record, Mapping) else None
    if not isinstance(ami, str) or AMI.fullmatch(ami) is None:
        raise RelationError("regional candidate AMI is invalid")
    image_hash = hashlib.sha256(ami.encode("ascii")).hexdigest()
    if (
        preflight.get("execution_id") != execution
        or preflight.get("region") != region
        or preflight.get("runtime_image_sha256") != image_hash
        or runtime.get("execution_id") != execution
        or runtime.get("region") != region
        or runtime.get("runtime_image_sha256") != image_hash
        or runtime.get("instance_type") != preflight.get("instance_type")
    ):
        raise RelationError("runtime deployment is not bound to the candidate AMI")
    for scenario in scenarios:
        telemetry = (
            scenario.get("active_call_telemetry")
            if isinstance(scenario, Mapping)
            else None
        )
        if (
            not isinstance(telemetry, Mapping)
            or telemetry.get("execution_id") != execution
            or telemetry.get("instance_type") != preflight.get("instance_type")
            or telemetry.get("vcpus") != preflight.get("vcpus")
            or telemetry.get("memory_mib") != preflight.get("memory_mib")
        ):
            raise RelationError("active-call telemetry is not bound to the runtime")
    proof_hash = hashlib.sha256(proof_bytes).hexdigest()
    if (
        zero.get("execution_id") != execution
        or proof.get("execution_id") != execution
        or zero.get("zero_resource_proof_sha256") != proof_hash
        or evidence.get("zero_resource_proof_sha256") != proof_hash
    ):
        raise RelationError("zero-resource artifacts are not bound to the execution")
    observations = proof.get("observations")
    if (
        proof.get("required_observations") != 3
        or proof.get("minimum_span_seconds") != 60
        or not isinstance(observations, list)
        or len(observations) != 3
    ):
        raise RelationError("zero-resource observation contract changed")
    instants = [
        _instant(observation.get("observed_at"), "zero-resource observation")
        if isinstance(observation, Mapping)
        else _instant(None, "zero-resource observation")
        for observation in observations
    ]
    for observation in observations:
        counts = observation.get("resource_counts")
        if (
            observation.get("redacted") is not True
            or not isinstance(counts, Mapping)
            or set(counts) != ZERO_RESOURCE_KEYS
            or any(type(value) is not int or value != 0 for value in counts.values())
        ):
            raise RelationError("zero-resource observation is not exhaustive and empty")
    if not (instants[0] < instants[1] < instants[2]):
        raise RelationError("zero-resource observations are not strictly increasing")
    span_seconds = (instants[-1] - instants[0]).total_seconds()
    if span_seconds < 60:
        raise RelationError("zero-resource observation span is shorter than 60 seconds")
    proven_at = _instant(proof.get("proven_at"), "zero-resource proof")
    zero_observed_at = _instant(zero.get("observed_at"), "zero-state observation")
    evidence_started_at = _instant(evidence.get("started_at"), "evidence start")
    evidence_ended_at = _instant(evidence.get("ended_at"), "evidence end")
    if (
        proven_at < instants[-1]
        or zero_observed_at < proven_at
        or evidence_started_at > instants[0]
        or evidence_ended_at < zero_observed_at
    ):
        raise RelationError("zero-resource proof timestamps are inconsistent")
    deployment_review = evidence.get("deployment_review")
    root_invocation_sha256 = (
        deployment_review.get("root_invocation_sha256")
        if isinstance(deployment_review, Mapping)
        else None
    )
    if (
        not isinstance(root_invocation_sha256, str)
        or SHA256.fullmatch(root_invocation_sha256) is None
    ):
        raise RelationError("deployment review invocation binding is invalid")
    return {
        "schema_version": 1,
        "producer": "bridgefu-qualification-relational-verifier@1",
        "execution_id": execution,
        "region": region,
        "runtime_image_sha256": image_hash,
        "root_invocation_sha256": root_invocation_sha256,
        "zero_resource_proof_sha256": proof_hash,
        "zero_observation_span_seconds": span_seconds,
        "relations_verified": True,
        "redacted": True,
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    evidence = _read(args.evidence, "evidence")
    zero = _read(args.zero_state, "zero-state observation")
    proof = _read(args.zero_resource_proof, "zero-resource proof")
    regions = _read(args.region_release, "region release")
    try:
        proof_bytes = args.zero_resource_proof.read_bytes()
    except OSError as error:
        raise RelationError("zero-resource proof bytes are unreadable") from error
    return verify_documents(
        evidence=evidence,
        zero=zero,
        proof=proof,
        proof_bytes=proof_bytes,
        regions=regions,
        release=args.release,
        bridgefu_commit=args.bridgefu_commit,
        region=args.region,
        expected_execution_id=args.expected_execution_id,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--zero-state", type=Path, required=True)
    parser.add_argument("--zero-resource-proof", type=Path, required=True)
    parser.add_argument("--region-release", type=Path, required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--bridgefu-commit", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--expected-execution-id", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RelationError as error:
        raise SystemExit(
            f"qualification relation verification failed: {error}"
        ) from error
