#!/usr/bin/env python3
"""Download every published object anonymously and verify its exact bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

SHA256 = re.compile(r"^[0-9a-f]{64}$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
REGIONS = {"us-east-1", "us-west-2"}
MAX_OBJECTS = 512
MAX_OBJECT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
CREDENTIAL_ENVIRONMENT = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_ROLE_ARN",
    "AWS_ROLE_SESSION_NAME",
}


class PublicReleaseError(RuntimeError):
    """The unauthenticated public artifact surface is incomplete or changed."""


class Response(Protocol):
    status: int

    def read(self, amount: int = -1) -> bytes: ...

    def geturl(self) -> str: ...

    def __enter__(self) -> Response: ...

    def __exit__(self, *args: object) -> None: ...


class UrlOpener:
    def open(self, url: str, timeout: float) -> Response:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": "bridgefu-public-release-verifier/1",
            },
            method="GET",
        )
        return urllib.request.urlopen(request, timeout=timeout)  # noqa: S310


def _read_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PublicReleaseError(f"{label} is unreadable") from error
    if not isinstance(value, Mapping):
        raise PublicReleaseError(f"{label} is invalid")
    return value


def _record(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "region",
        "bucket",
        "key",
        "version_id",
        "sha256",
        "size_bytes",
    }:
        raise PublicReleaseError(f"{label} record shape changed")
    result = dict(value)
    if (
        result["region"] not in REGIONS
        or not isinstance(result["bucket"], str)
        or BUCKET.fullmatch(result["bucket"]) is None
        or not isinstance(result["key"], str)
        or len(result["key"]) > 1024
        or result["key"].startswith("/")
        or ".." in result["key"].split("/")
        or not isinstance(result["version_id"], str)
        or not 1 <= len(result["version_id"]) <= 1024
        or not isinstance(result["sha256"], str)
        or SHA256.fullmatch(result["sha256"]) is None
        or not isinstance(result["size_bytes"], int)
        or isinstance(result["size_bytes"], bool)
        or not 0 < result["size_bytes"] <= MAX_OBJECT_BYTES
    ):
        raise PublicReleaseError(f"{label} record is invalid")
    return result


def _url(record: Mapping[str, Any], *, exact_version: bool) -> str:
    key = urllib.parse.quote(record["key"], safe="/")
    base = f"https://{record['bucket']}.s3.{record['region']}.amazonaws.com/{key}"
    if not exact_version:
        return base
    return f"{base}?versionId={urllib.parse.quote(record['version_id'], safe='')}"


def _download_exact(
    opener: UrlOpener, record: Mapping[str, Any], *, exact_version: bool
) -> None:
    url = _url(record, exact_version=exact_version)
    try:
        with opener.open(url, timeout=30.0) as response:
            if response.status != 200 or response.geturl() != url:
                raise PublicReleaseError("public object returned a redirect or non-200")
            content = response.read(record["size_bytes"] + 1)
    except PublicReleaseError:
        raise
    except Exception as error:
        raise PublicReleaseError("anonymous public object download failed") from error
    if len(content) != record["size_bytes"]:
        raise PublicReleaseError("anonymous public object size changed")
    if hashlib.sha256(content).hexdigest() != record["sha256"]:
        raise PublicReleaseError("anonymous public object hash changed")


def verify(
    receipt: Mapping[str, Any], state: Mapping[str, Any], opener: UrlOpener
) -> dict[str, Any]:
    if any(os.environ.get(name) for name in CREDENTIAL_ENVIRONMENT):
        raise PublicReleaseError("AWS credential environment must be empty")
    if (
        receipt.get("schema") != "bridgefu-qualified-candidate-receipt/v1"
        or state.get("schema") != "bridgefu-publication-state/v1"
    ):
        raise PublicReleaseError("receipt or publication state schema changed")
    arrays: list[tuple[str, Any, bool]] = [
        ("release object", receipt.get("release_objects"), False),
        ("release receipt object", state.get("release_receipt_objects"), False),
        ("latest object", state.get("latest_objects"), True),
    ]
    records: list[tuple[dict[str, Any], bool]] = []
    identities: set[tuple[str, str, str, str]] = set()
    for label, values, require_latest in arrays:
        if not isinstance(values, list) or not values:
            raise PublicReleaseError(f"{label} list is empty or invalid")
        for raw in values:
            item = _record(raw, label)
            identity = (
                item["region"],
                item["bucket"],
                item["key"],
                item["version_id"],
            )
            if identity in identities:
                raise PublicReleaseError("public object record is duplicated")
            identities.add(identity)
            records.append((item, require_latest))
    if len(records) > MAX_OBJECTS:
        raise PublicReleaseError("public object count exceeds bound")
    if sum(record["size_bytes"] for record, _ in records) > MAX_TOTAL_BYTES:
        raise PublicReleaseError("public object byte total exceeds bound")
    for record, require_latest in records:
        _download_exact(opener, record, exact_version=True)
        if require_latest:
            _download_exact(opener, record, exact_version=False)
    return {
        "schema_version": 1,
        "producer": "bridgefu-public-release-verifier@1",
        "anonymous": True,
        "exact_version_downloads": len(records),
        "unversioned_latest_downloads": sum(latest for _, latest in records),
        "all_hashes_verified": True,
        "redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--publication-state", type=Path, required=True)
    args = parser.parse_args()
    result = verify(
        _read_json(args.receipt, "qualified receipt"),
        _read_json(args.publication_state, "publication state"),
        UrlOpener(),
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except PublicReleaseError as error:
        raise SystemExit(f"public release verification failed: {error}") from error
