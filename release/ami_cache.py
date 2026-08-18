#!/usr/bin/env python3
"""Compute and verify the private, content-addressed Bridgefu AMI cache."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SCHEMA = "bridgefu-ami-content/v1"
CACHE_TAG = "bridgefu-ami-cache-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
AMI = re.compile(r"^ami-[0-9a-f]{17}$")
SNAPSHOT = re.compile(r"^snap-[0-9a-f]{17}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")
FIXED_INPUTS = (
    "bridgefu.lock.json",
    "image/bridgefu.pkr.hcl",
    "image/build-inputs.json",
    "image/install.sh",
)


class AmiCacheError(ValueError):
    """The AMI cache input or remote object is not exactly owned."""


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AmiCacheError(f"{label} is not an object")
    return value


def _json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        return _mapping(json.loads(path.read_text(encoding="utf-8")), label)
    except (OSError, json.JSONDecodeError) as error:
        raise AmiCacheError(f"{label} is unreadable") from error


def _runtime_inputs(root: Path) -> list[str]:
    directory = root / "image" / "runtime"
    if not directory.is_dir() or directory.is_symlink():
        raise AmiCacheError("runtime input directory is invalid")
    inputs: list[str] = []
    for path in sorted(directory.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        if not path.is_file() or path.is_symlink():
            raise AmiCacheError("runtime inputs contain a non-regular file")
        inputs.append(path.relative_to(root).as_posix())
    if not inputs:
        raise AmiCacheError("runtime inputs are empty")
    return inputs


def content_manifest(root: Path, release_version: str) -> dict[str, Any]:
    if not VERSION.fullmatch(release_version):
        raise AmiCacheError("release version is invalid")
    root = root.resolve()
    paths = [*FIXED_INPUTS, *_runtime_inputs(root)]
    if len(paths) != len(set(paths)):
        raise AmiCacheError("AMI inputs are duplicated")
    digest = hashlib.sha256()
    digest.update(f"{SCHEMA}\0".encode())
    digest.update(f"release_version\0{release_version}\0".encode())
    records: list[dict[str, Any]] = []
    for relative in paths:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise AmiCacheError(f"AMI input is not a regular file: {relative}")
        data = path.read_bytes()
        file_digest = hashlib.sha256(data).hexdigest()
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        records.append(
            {"path": relative, "sha256": file_digest, "size_bytes": len(data)}
        )
    lock = _json(root / "bridgefu.lock.json", "Bridgefu lock")
    bridgefu_commit = lock.get("commit")
    cargo_lock_sha256 = lock.get("cargo_lock_sha256")
    if (
        not isinstance(bridgefu_commit, str)
        or not re.fullmatch(r"[0-9a-f]{40}", bridgefu_commit)
        or not isinstance(cargo_lock_sha256, str)
        or not SHA256.fullmatch(cargo_lock_sha256)
    ):
        raise AmiCacheError("Bridgefu lock identity is invalid")
    return {
        "schema": SCHEMA,
        "release_version": release_version,
        "bridgefu_commit": bridgefu_commit,
        "bridgefu_cargo_lock_sha256": cargo_lock_sha256,
        "ami_build_sha256": digest.hexdigest(),
        "inputs": records,
        "redacted": True,
    }


def _tags(value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, list):
        raise AmiCacheError(f"{label} tags are invalid")
    result: dict[str, str] = {}
    for item in value:
        tag = _mapping(item, f"{label} tag")
        if set(tag) != {"Key", "Value"}:
            raise AmiCacheError(f"{label} tag shape is invalid")
        key, entry = tag["Key"], tag["Value"]
        if not isinstance(key, str) or not isinstance(entry, str) or key in result:
            raise AmiCacheError(f"{label} tags are ambiguous")
        result[key] = entry
    return result


def verify_cache(
    *,
    image_document: Mapping[str, Any],
    image_permissions: Mapping[str, Any],
    snapshot_document: Mapping[str, Any],
    snapshot_permissions: Mapping[str, Any],
    account_id: str,
    build_sha256: str,
    bridgefu_commit: str,
    release_version: str,
) -> dict[str, Any]:
    if not ACCOUNT.fullmatch(account_id) or not SHA256.fullmatch(build_sha256):
        raise AmiCacheError("cache identity is invalid")
    images = image_document.get("Images")
    if not isinstance(images, list) or len(images) != 1:
        raise AmiCacheError("cache AMI is not unique")
    image = _mapping(images[0], "cache AMI")
    image_id = image.get("ImageId")
    if (
        not isinstance(image_id, str)
        or not AMI.fullmatch(image_id)
        or image.get("OwnerId") != account_id
        or image.get("Architecture") != "arm64"
        or image.get("State") != "available"
        or image.get("RootDeviceType") != "ebs"
        or image.get("VirtualizationType") != "hvm"
    ):
        raise AmiCacheError("cache AMI shape is invalid")
    tags = _tags(image.get("Tags"), "cache AMI")
    expected_tags = {
        "ManagedBy": "bridgefu-vapi-awsconnect",
        "BridgefuAmiBuildCache": CACHE_TAG,
        "BridgefuAmiBuildSha256": build_sha256,
        "BridgefuCommit": bridgefu_commit,
        "BridgefuReleaseInput": release_version,
        "BridgefuRvoipVersion": "0.3.8",
    }
    expected_name = f"bridgefu-vapi-awsconnect-build-{build_sha256[:16]}"
    if tags != {**expected_tags, "Name": expected_name}:
        raise AmiCacheError("cache AMI tags do not match the content identity")
    if any(
        forbidden in tags
        for forbidden in (
            "BridgefuCandidateId",
            "BridgefuRepositoryCommit",
            "BridgefuRelease",
        )
    ):
        raise AmiCacheError("cache AMI has candidate or release ownership")
    permissions = image_permissions.get("LaunchPermissions")
    if permissions != []:
        raise AmiCacheError("cache AMI is not private")
    mappings = image.get("BlockDeviceMappings")
    if not isinstance(mappings, list) or len(mappings) != 1:
        raise AmiCacheError("cache AMI block-device shape is invalid")
    ebs = _mapping(_mapping(mappings[0], "cache block device").get("Ebs"), "EBS")
    snapshot_id = ebs.get("SnapshotId")
    if not isinstance(snapshot_id, str) or not SNAPSHOT.fullmatch(snapshot_id):
        raise AmiCacheError("cache snapshot identity is invalid")
    snapshots = snapshot_document.get("Snapshots")
    if not isinstance(snapshots, list) or len(snapshots) != 1:
        raise AmiCacheError("cache snapshot is not unique")
    snapshot = _mapping(snapshots[0], "cache snapshot")
    if (
        snapshot.get("SnapshotId") != snapshot_id
        or snapshot.get("OwnerId") != account_id
        or snapshot.get("State") != "completed"
        or snapshot.get("Encrypted") is not False
    ):
        raise AmiCacheError("cache snapshot shape is invalid")
    snapshot_tags = _tags(snapshot.get("Tags"), "cache snapshot")
    # Packer propagates the AMI Name tag to the backing snapshot even when the
    # explicit snapshot_tags map contains only the shared ownership tags. Bind
    # that deterministic name just as strictly as the AMI name instead of
    # rejecting the real AWS response shape.
    if snapshot_tags != {**expected_tags, "Name": expected_name}:
        raise AmiCacheError("cache snapshot tags do not match the content identity")
    if snapshot_permissions.get("CreateVolumePermissions") != []:
        raise AmiCacheError("cache snapshot is not private")
    return {
        "schema_version": 1,
        "producer": "bridgefu-ami-cache-verifier@1",
        "ami_id": image_id,
        "snapshot_id": snapshot_id,
        "ami_build_sha256": build_sha256,
        "private": True,
        "verified": True,
        "redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    digest = subparsers.add_parser("digest")
    digest.add_argument("--root", type=Path, required=True)
    digest.add_argument("--release-version", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--image", type=Path, required=True)
    verify.add_argument("--image-permissions", type=Path, required=True)
    verify.add_argument("--snapshot", type=Path, required=True)
    verify.add_argument("--snapshot-permissions", type=Path, required=True)
    verify.add_argument("--account-id", required=True)
    verify.add_argument("--build-sha256", required=True)
    verify.add_argument("--bridgefu-commit", required=True)
    verify.add_argument("--release-version", required=True)
    args = parser.parse_args()
    try:
        if args.command == "digest":
            result = content_manifest(args.root, args.release_version)
        else:
            result = verify_cache(
                image_document=_json(args.image, "cache AMI response"),
                image_permissions=_json(
                    args.image_permissions, "cache AMI permission response"
                ),
                snapshot_document=_json(args.snapshot, "cache snapshot response"),
                snapshot_permissions=_json(
                    args.snapshot_permissions, "cache snapshot permission response"
                ),
                account_id=args.account_id,
                build_sha256=args.build_sha256,
                bridgefu_commit=args.bridgefu_commit,
                release_version=args.release_version,
            )
    except AmiCacheError as error:
        print(f"AMI cache verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
