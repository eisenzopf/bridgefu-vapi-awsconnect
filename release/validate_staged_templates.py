#!/usr/bin/env python3
"""Verify and remotely validate every exact, versioned release template."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

STAGED_SCHEMA = "bridgefu-staged-release-objects/v1"
REGIONS_SCHEMA = "bridgefu-vapi-awsconnect-regions/v1"
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")
VERSION_ID = re.compile(r"^[A-Za-z0-9._+/=-]{1,1024}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
CANDIDATE_ID = re.compile(r"^candidate-[A-Za-z0-9.-]{8,96}$")
REGION = re.compile(r"^us-(?:east|west)-[1-9][0-9]*$")
NESTED_TEMPLATES = (
    "configuration.yaml",
    "network.yaml",
    "handoff-service.yaml",
    "connect.yaml",
    "runtime.yaml",
    "vapi.yaml",
    "observability.yaml",
)
EXACT_TEMPLATES = (
    "cloudformation/template.yaml",
    *(f"cloudformation/nested/{name}" for name in NESTED_TEMPLATES),
    "qualification/cloudformation/disposable-connect.yaml",
    "qualification/cloudformation/template.yaml",
)


class StagedTemplateError(RuntimeError):
    """Raised before an unreviewed template can reach CloudFormation."""


AwsJson = Callable[[Sequence[str]], Mapping[str, Any]]


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def run_aws_json(arguments: Sequence[str]) -> Mapping[str, Any]:
    result = subprocess.run(
        ["aws", *arguments, "--output", "json"],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        raise StagedTemplateError("AWS rejected exact template verification")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise StagedTemplateError("AWS returned invalid template verification data") from error
    if not isinstance(value, Mapping):
        raise StagedTemplateError("AWS returned invalid template verification data")
    return value


def load_supported_regions(path: Path) -> tuple[str, ...]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise StagedTemplateError("supported-region catalog is invalid") from error
    if not isinstance(value, Mapping) or value.get("schema") != REGIONS_SCHEMA:
        raise StagedTemplateError("supported-region catalog schema is invalid")
    entries = value.get("regions")
    if not isinstance(entries, list) or not entries:
        raise StagedTemplateError("supported-region catalog is empty")
    regions: list[str] = []
    for entry in entries:
        code = entry.get("code") if isinstance(entry, Mapping) else None
        if not isinstance(code, str) or REGION.fullmatch(code) is None:
            raise StagedTemplateError("supported-region catalog contains an invalid region")
        regions.append(code)
    if len(regions) != len(set(regions)):
        raise StagedTemplateError("supported-region catalog contains duplicate regions")
    if set(regions) != {"us-west-2", "us-east-1"}:
        raise StagedTemplateError("supported-region catalog must contain both US regions")
    return tuple(regions)


def load_exact_template_records(
    path: Path,
    *,
    release_version: str,
    bucket: str,
) -> tuple[dict[str, Any], ...]:
    if VERSION.fullmatch(release_version) is None or BUCKET.fullmatch(bucket) is None:
        raise StagedTemplateError("release template identity is invalid")
    try:
        journal = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise StagedTemplateError("staged-object journal is invalid") from error
    if not isinstance(journal, Mapping) or journal.get("schema") != STAGED_SCHEMA:
        raise StagedTemplateError("staged-object journal schema is invalid")
    objects = journal.get("objects")
    if not isinstance(objects, list) or not 1 <= len(objects) <= 100:
        raise StagedTemplateError("staged-object journal has invalid bounds")
    expected_keys = {
        f"releases/{release_version}/{relative}" for relative in EXACT_TEMPLATES
    }
    selected: dict[str, dict[str, Any]] = {}
    for item in objects:
        if not isinstance(item, Mapping) or set(item) != {
            "region",
            "bucket",
            "key",
            "version_id",
            "sha256",
            "size_bytes",
        }:
            raise StagedTemplateError("staged-object journal entry is invalid")
        key = item.get("key")
        if key not in expected_keys:
            continue
        if (
            item.get("region") != "us-east-1"
            or item.get("bucket") != bucket
            or not isinstance(item.get("version_id"), str)
            or VERSION_ID.fullmatch(item["version_id"]) is None
            or not isinstance(item.get("sha256"), str)
            or SHA256.fullmatch(item["sha256"]) is None
            or not isinstance(item.get("size_bytes"), int)
            or isinstance(item.get("size_bytes"), bool)
            or not 1 <= item["size_bytes"] <= 1_048_576
        ):
            raise StagedTemplateError("staged template record is invalid")
        if key in selected:
            raise StagedTemplateError("staged template record is ambiguous")
        selected[key] = dict(item)
    if set(selected) != expected_keys or len(selected) != 10:
        raise StagedTemplateError("staged-object journal does not seal all ten templates")
    return tuple(selected[key] for key in sorted(selected))


def exact_template_url(record: Mapping[str, Any]) -> str:
    key = urllib.parse.quote(str(record["key"]), safe="/")
    version_id = urllib.parse.quote(str(record["version_id"]), safe="")
    return (
        f"https://{record['bucket']}.s3.us-east-1.amazonaws.com/{key}"
        f"?versionId={version_id}"
    )


def verify_and_validate(
    *,
    records: Sequence[Mapping[str, Any]],
    candidate_id: str,
    regions: Sequence[str],
    aws_json: AwsJson = run_aws_json,
) -> None:
    if CANDIDATE_ID.fullmatch(candidate_id) is None:
        raise StagedTemplateError("candidate identity is invalid")
    if len(records) != 10 or len(regions) != len(set(regions)):
        raise StagedTemplateError("exact template validation set is incomplete")
    reviewed_urls: list[str] = []
    with tempfile.TemporaryDirectory(prefix="bridgefu-template-review-") as directory:
        root = Path(directory)
        for index, record in enumerate(records):
            head_arguments = [
                "s3api",
                "head-object",
                "--region",
                "us-east-1",
                "--bucket",
                str(record["bucket"]),
                "--key",
                str(record["key"]),
                "--version-id",
                str(record["version_id"]),
            ]
            head = aws_json(head_arguments)
            expected_metadata = {
                "sha256": record["sha256"],
                "candidate-id": candidate_id,
            }
            if (
                head.get("VersionId") != record["version_id"]
                or head.get("ContentLength") != record["size_bytes"]
                or head.get("Metadata") != expected_metadata
            ):
                raise StagedTemplateError("exact staged template HEAD does not match journal")
            destination = root / f"template-{index}.yaml"
            fetched = aws_json(
                [
                    "s3api",
                    "get-object",
                    "--region",
                    "us-east-1",
                    "--bucket",
                    str(record["bucket"]),
                    "--key",
                    str(record["key"]),
                    "--version-id",
                    str(record["version_id"]),
                    str(destination),
                ]
            )
            if (
                fetched.get("VersionId") != record["version_id"]
                or fetched.get("ContentLength") != record["size_bytes"]
                or fetched.get("Metadata") != expected_metadata
                or not destination.is_file()
                or destination.stat().st_size != record["size_bytes"]
                or sha256_file(destination) != record["sha256"]
            ):
                raise StagedTemplateError("downloaded staged template does not match journal")
            template_url = exact_template_url(record)
            if template_url in reviewed_urls:
                raise StagedTemplateError("exact staged template URL is duplicated")
            reviewed_urls.append(template_url)
    if len(reviewed_urls) != 10:
        raise StagedTemplateError("not every exact template URL was validated")
    for template_url in reviewed_urls:
        for region in regions:
            if REGION.fullmatch(region) is None:
                raise StagedTemplateError("template validation region is invalid")
            aws_json(
                [
                    "cloudformation",
                    "validate-template",
                    "--region",
                    region,
                    "--template-url",
                    template_url,
                ]
            )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--staged-objects", required=True, type=Path)
    value.add_argument("--regions", required=True, type=Path)
    value.add_argument("--release-version", required=True)
    value.add_argument("--candidate-id", required=True)
    value.add_argument("--bucket", required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        records = load_exact_template_records(
            args.staged_objects,
            release_version=args.release_version,
            bucket=args.bucket,
        )
        verify_and_validate(
            records=records,
            candidate_id=args.candidate_id,
            regions=load_supported_regions(args.regions),
        )
    except StagedTemplateError as error:
        print(f"template validation failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
