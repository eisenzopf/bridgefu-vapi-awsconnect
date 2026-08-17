#!/usr/bin/env python3
"""Verify a candidate receipt's exact relations before KMS signing."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

try:
    from . import verify_qualification_relations as qualification_relations
except ImportError:  # pragma: no cover - direct script execution
    import verify_qualification_relations as qualification_relations

SHA256 = re.compile(r"^[0-9a-f]{64}$")
AMI = re.compile(r"^ami-[0-9a-f]{17}$")
REGIONS = ("us-west-2", "us-east-1")
SCENARIOS = ["bridgefu-web-sdk-handoff", "vapi-sip-transfer"]
QUALIFICATION_KEYS = {
    "evidence_schema_version",
    "evidence_sha256",
    "execution_id",
    "required_checks_passed",
    "root_invocation_sha256",
    "runtime_image_sha256",
    "scenario_ids",
    "secure_preflight_passed",
    "zero_resource_proof",
    "zero_resource_proof_sha256",
    "zero_state_sha256",
}


class ReceiptError(RuntimeError):
    """A candidate receipt does not bind the exact qualified artifacts."""


def _read(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReceiptError(f"{label} is unreadable") from error
    if not isinstance(value, Mapping):
        raise ReceiptError(f"{label} is invalid")
    return value


def _sha256(path: Path) -> tuple[str, int]:
    try:
        content = path.read_bytes()
    except OSError as error:
        raise ReceiptError("qualification artifact is unreadable") from error
    return hashlib.sha256(content).hexdigest(), len(content)


def _instant(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ReceiptError(f"{label} is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReceiptError(f"{label} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise ReceiptError(f"{label} is not UTC")
    return parsed


def _exact_object(
    records: Any, *, key: str, expected_hash: str, expected_size: int
) -> None:
    if not isinstance(records, list):
        raise ReceiptError("release object list is invalid")
    matches = [
        record
        for record in records
        if isinstance(record, Mapping)
        and record.get("region") == "us-east-1"
        and record.get("key") == key
    ]
    if len(matches) != 1:
        raise ReceiptError("qualification artifact object is missing or ambiguous")
    record = matches[0]
    if (
        set(record)
        != {"region", "bucket", "key", "version_id", "sha256", "size_bytes"}
        or record.get("sha256") != expected_hash
        or record.get("size_bytes") != expected_size
        or not isinstance(record.get("bucket"), str)
        or not isinstance(record.get("version_id"), str)
        or not record["version_id"]
    ):
        raise ReceiptError("qualification artifact object binding changed")


def verify(args: argparse.Namespace) -> dict[str, Any]:
    receipt = _read(args.receipt, "candidate receipt")
    if (
        receipt.get("schema") != "bridgefu-qualified-candidate-receipt/v1"
        or receipt.get("version") != args.release
        or receipt.get("bridgefu_commit") != args.bridgefu_commit
    ):
        raise ReceiptError("candidate receipt identity changed")
    qualification = receipt.get("qualification")
    regional_amis = receipt.get("regional_amis")
    workflow = receipt.get("workflow")
    if (
        not isinstance(qualification, Mapping)
        or set(qualification) != set(REGIONS)
        or not isinstance(regional_amis, Mapping)
        or set(regional_amis) != set(REGIONS)
        or not isinstance(workflow, Mapping)
        or set(workflow) != {"run_id", "run_attempt"}
        or type(workflow.get("run_id")) is not int
        or workflow["run_id"] <= 0
        or type(workflow.get("run_attempt")) is not int
        or workflow["run_attempt"] <= 0
    ):
        raise ReceiptError("candidate receipt region set changed")
    qualified_at = _instant(receipt.get("qualified_at"), "qualified_at")
    latest_evidence_end: dt.datetime | None = None
    for region in REGIONS:
        directory = args.qualification_root / region
        evidence_path = directory / "evidence.json"
        zero_state_path = directory / "zero-state.json"
        zero_proof_path = directory / "zero-resource-proof.json"
        evidence = _read(evidence_path, f"{region} evidence")
        zero = _read(zero_state_path, f"{region} zero state")
        proof = _read(zero_proof_path, f"{region} zero-resource proof")
        evidence_hash, evidence_size = _sha256(evidence_path)
        zero_hash, zero_size = _sha256(zero_state_path)
        proof_hash, proof_size = _sha256(zero_proof_path)
        entry = qualification[region]
        regional_ami = regional_amis[region]
        ami = regional_ami.get("ami_id") if isinstance(regional_ami, Mapping) else None
        if not isinstance(entry, Mapping) or set(entry) != QUALIFICATION_KEYS:
            raise ReceiptError(f"{region} qualification receipt shape changed")
        if not isinstance(ami, str) or AMI.fullmatch(ami) is None:
            raise ReceiptError(f"{region} candidate AMI is invalid")
        image_hash = hashlib.sha256(ami.encode("ascii")).hexdigest()
        execution_prefix = "w" if region == "us-west-2" else "e"
        expected_execution = (
            f"bfq-{execution_prefix}-{workflow['run_id']}-{workflow['run_attempt']}"
        )
        try:
            relation = qualification_relations.verify_documents(
                evidence=evidence,
                zero=zero,
                proof=proof,
                proof_bytes=zero_proof_path.read_bytes(),
                regions=regional_amis,
                release=args.release,
                bridgefu_commit=args.bridgefu_commit,
                region=region,
                expected_execution_id=expected_execution,
            )
        except (OSError, qualification_relations.RelationError) as error:
            raise ReceiptError(
                f"{region} qualification artifact relations changed"
            ) from error
        deployment_review = evidence.get("deployment_review")
        root_hash = (
            deployment_review.get("root_invocation_sha256")
            if isinstance(deployment_review, Mapping)
            else None
        )
        scenario_ids = sorted(
            scenario.get("id")
            for scenario in evidence.get("scenarios", [])
            if isinstance(scenario, Mapping)
        )
        runtime = evidence.get("runtime_deployment")
        if (
            entry.get("execution_id") != evidence.get("execution_id")
            or entry.get("execution_id") != relation.get("execution_id")
            or entry.get("evidence_sha256") != evidence_hash
            or entry.get("zero_state_sha256") != zero_hash
            or entry.get("zero_resource_proof_sha256") != proof_hash
            or entry.get("zero_resource_proof_sha256")
            != evidence.get("zero_resource_proof_sha256")
            or entry.get("zero_resource_proof_sha256")
            != zero.get("zero_resource_proof_sha256")
            or entry.get("runtime_image_sha256") != image_hash
            or entry.get("runtime_image_sha256")
            != relation.get("runtime_image_sha256")
            or entry.get("runtime_image_sha256")
            != (
                runtime.get("runtime_image_sha256")
                if isinstance(runtime, Mapping)
                else None
            )
            or entry.get("root_invocation_sha256") != root_hash
            or entry.get("root_invocation_sha256")
            != relation.get("root_invocation_sha256")
            or entry.get("evidence_schema_version") != 2
            or entry.get("scenario_ids") != scenario_ids
            or entry.get("scenario_ids") != SCENARIOS
            or entry.get("secure_preflight_passed") is not True
            or entry.get("required_checks_passed") is not True
            or entry.get("zero_resource_proof") is not True
            or SHA256.fullmatch(str(root_hash or "")) is None
        ):
            raise ReceiptError(f"{region} qualification receipt relation changed")
        for name, artifact_hash, artifact_size in (
            ("evidence.json", evidence_hash, evidence_size),
            ("zero-state.json", zero_hash, zero_size),
            ("zero-resource-proof.json", proof_hash, proof_size),
        ):
            _exact_object(
                receipt.get("release_objects"),
                key=f"releases/{args.release}/qualification/{region}/{name}",
                expected_hash=artifact_hash,
                expected_size=artifact_size,
            )
        evidence_end = _instant(evidence.get("ended_at"), f"{region} evidence end")
        latest_evidence_end = (
            evidence_end
            if latest_evidence_end is None
            else max(latest_evidence_end, evidence_end)
        )
    if latest_evidence_end is None or qualified_at < latest_evidence_end:
        raise ReceiptError("receipt was qualified before its evidence ended")
    return {
        "schema_version": 1,
        "producer": "bridgefu-candidate-receipt-verifier@1",
        "regions_verified": sorted(REGIONS),
        "qualification_relations_verified": True,
        "release_object_relations_verified": True,
        "qualified_at_verified": True,
        "redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--qualification-root", type=Path, required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--bridgefu-commit", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReceiptError as error:
        raise SystemExit(f"candidate receipt verification failed: {error}") from error
