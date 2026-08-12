#!/usr/bin/env python3
"""Assemble an immutable regional CloudFormation release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
import urllib.parse
from pathlib import Path

from build_lambdas import build as build_lambdas

VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")
AMI = re.compile(r"^ami-[0-9a-f]{17}$")
GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
S3_PREFIX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*[A-Za-z0-9]$")
OUTPUT_MARKER = ".bridgefu-vapi-awsconnect-release"
LAMBDA_ARTIFACTS = (
    "configuration.zip",
    "vapi_provisioner.zip",
    "prepare_handoff.zip",
    "transfer_destination.zip",
    "connect_lookup.zip",
)
NESTED_TEMPLATES = (
    "configuration.yaml",
    "network.yaml",
    "handoff-service.yaml",
    "connect.yaml",
    "runtime.yaml",
    "vapi.yaml",
    "observability.yaml",
)
OBJECT_VERSIONS_SCHEMA = "bridgefu-release-object-versions/v1"


def token_for(region: str) -> str:
    return region.upper().replace("-", "_")


def load_region_release(root: Path, path: Path | None) -> dict[str, dict[str, str]]:
    catalog = json.loads((root / "release" / "regions.json").read_text())
    supported = [item["code"] for item in catalog["regions"]]
    if path is None:
        return {
            region: {
                "ami_id": "ami-00000000000000000",
                "bucket": f"bridgefu-vapi-awsconnect-{region}",
            }
            for region in supported
        }
    supplied = json.loads(path.read_text())
    if set(supplied) != set(supported):
        raise SystemExit(
            "--regions-file must contain exactly the regions in release/regions.json"
        )
    for region, release in supplied.items():
        if not AMI.fullmatch(release.get("ami_id", "")):
            raise SystemExit(f"invalid immutable AMI ID for {region}")
        if not re.fullmatch(
            r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", release.get("bucket", "")
        ):
            raise SystemExit(f"invalid artifact bucket for {region}")
    return supplied


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _object_version(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9._+/=-]{1,1024}", value) is None
    ):
        raise SystemExit(f"missing or invalid exact S3 VersionId for {label}")
    return value


def load_object_versions(
    path: Path | None,
    supported_regions: set[str],
    *,
    require_product: bool,
) -> dict[str, object]:
    """Load exact staged VersionIds, or deterministic IDs for local validation."""
    if path is None:
        local = "local-validation-version"
        return {
            "schema": OBJECT_VERSIONS_SCHEMA,
            "lambda": {
                region: {name: local for name in LAMBDA_ARTIFACTS}
                for region in supported_regions
            },
            "nested": {name: local for name in NESTED_TEMPLATES},
            "qualification": {"disposable-connect.yaml": local},
            "product_template": local,
            "exact": False,
        }
    try:
        supplied = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid --versions-file: {path}") from error
    if (
        not isinstance(supplied, dict)
        or supplied.get("schema") != OBJECT_VERSIONS_SCHEMA
    ):
        raise SystemExit(f"--versions-file must use schema {OBJECT_VERSIONS_SCHEMA}")
    lambda_versions = supplied.get("lambda")
    if (
        not isinstance(lambda_versions, dict)
        or set(lambda_versions) != supported_regions
    ):
        raise SystemExit(
            "--versions-file lambda regions do not match supported regions"
        )
    for region in sorted(supported_regions):
        versions = lambda_versions.get(region)
        if not isinstance(versions, dict) or set(versions) != set(LAMBDA_ARTIFACTS):
            raise SystemExit(
                f"--versions-file has incomplete Lambda versions for {region}"
            )
        for name in LAMBDA_ARTIFACTS:
            _object_version(versions[name], f"lambda/{region}/{name}")
    nested = supplied.get("nested")
    if not isinstance(nested, dict) or set(nested) != set(NESTED_TEMPLATES):
        raise SystemExit("--versions-file has incomplete nested-template versions")
    for name in NESTED_TEMPLATES:
        _object_version(nested[name], f"nested/{name}")
    qualification = supplied.get("qualification")
    if not isinstance(qualification, dict) or set(qualification) != {
        "disposable-connect.yaml"
    }:
        raise SystemExit("--versions-file has incomplete qualification versions")
    _object_version(
        qualification["disposable-connect.yaml"],
        "qualification/disposable-connect.yaml",
    )
    product = supplied.get("product_template")
    if require_product:
        _object_version(product, "product_template")
    elif product is not None:
        _object_version(product, "product_template")
    supplied["exact"] = True
    return supplied


def render(source: Path, destination: Path, replacements: dict[str, str]) -> None:
    text = source.read_text()
    for key, value in replacements.items():
        text = text.replace(f"__{key}__", value)
    unresolved = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
    if unresolved:
        raise SystemExit(f"unresolved release tokens in {source}: {unresolved}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text)


def verify_existing_release(
    output: Path,
    *,
    expected_version: str | None = None,
    expected_repository_commit: str | None = None,
) -> dict[str, object]:
    """Verify every immutable artifact named by an existing release manifest."""
    manifest_path = output / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid release manifest: {manifest_path}") from error
    if manifest.get("schema") != "bridgefu-vapi-awsconnect-release/v1":
        raise SystemExit("unsupported release manifest schema")
    if expected_version is not None and manifest.get("version") != expected_version:
        raise SystemExit("release manifest version does not match the expected version")
    source = manifest.get("distribution_source")
    if expected_repository_commit is not None and (
        not isinstance(source, dict)
        or source.get("repository_commit") != expected_repository_commit
    ):
        raise SystemExit("release manifest repository commit does not match")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise SystemExit("release manifest does not contain an artifact inventory")
    seen: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise SystemExit("release manifest contains an invalid artifact entry")
        relative = item.get("path")
        expected_digest = item.get("sha256")
        expected_size = item.get("size_bytes")
        if (
            not isinstance(relative, str)
            or relative in seen
            or relative.startswith("/")
            or ".." in Path(relative).parts
        ):
            raise SystemExit("release manifest contains an unsafe artifact path")
        seen.add(relative)
        path = output / relative
        if not path.is_file():
            raise SystemExit(f"release artifact is missing: {relative}")
        if digest(path) != expected_digest or path.stat().st_size != expected_size:
            raise SystemExit(f"release artifact digest mismatch: {relative}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version")
    parser.add_argument("--output", type=Path, default=Path("target/release"))
    parser.add_argument("--regions-file", type=Path)
    parser.add_argument(
        "--public-base-url",
        default="https://bridgefu-vapi-awsconnect.s3.amazonaws.com",
    )
    parser.add_argument(
        "--release-prefix",
        default="releases",
        help="S3 prefix embedded in immutable template URLs",
    )
    parser.add_argument("--repository-commit")
    parser.add_argument("--versions-file", type=Path)
    parser.add_argument(
        "--render-phase",
        choices=("assets", "product", "complete"),
        default="complete",
        help="Render staged assets, the product root, or the complete release",
    )
    parser.add_argument(
        "--repository",
        default="https://github.com/eisenzopf/bridgefu-vapi-awsconnect.git",
    )
    parser.add_argument("--verify-existing", type=Path)
    parser.add_argument("--expected-version")
    parser.add_argument("--expected-repository-commit")
    args = parser.parse_args()
    if args.verify_existing is not None:
        if args.version is not None or args.regions_file is not None:
            raise SystemExit("--verify-existing cannot be combined with build inputs")
        if args.expected_repository_commit is not None and not GIT_COMMIT.fullmatch(
            args.expected_repository_commit
        ):
            raise SystemExit("invalid --expected-repository-commit")
        output = args.verify_existing.resolve()
        verify_existing_release(
            output,
            expected_version=args.expected_version,
            expected_repository_commit=args.expected_repository_commit,
        )
        print(os.fspath(output / "manifest.json"))
        return 0
    if args.version is None:
        raise SystemExit("--version is required when building a release")
    if not VERSION.fullmatch(args.version):
        raise SystemExit("invalid --version")
    release_prefix = args.release_prefix.strip("/")
    if (
        not S3_PREFIX.fullmatch(release_prefix)
        or "//" in release_prefix
        or ".." in Path(release_prefix).parts
    ):
        raise SystemExit("invalid --release-prefix")
    if args.repository_commit is not None and not GIT_COMMIT.fullmatch(
        args.repository_commit
    ):
        raise SystemExit("invalid --repository-commit")

    root = Path(__file__).resolve().parents[1]
    region_release = load_region_release(root, args.regions_file)
    supported_regions = set(region_release)
    object_versions = load_object_versions(
        args.versions_file,
        supported_regions,
        require_product=args.render_phase == "complete",
    )
    output = args.output if args.output.is_absolute() else root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        lambda_output = staging / "artifacts" / "lambda"
        build_lambdas(root, lambda_output)
        replacements = {
            "RELEASE_VERSION": args.version,
            "NESTED_TEMPLATE_BASE_URL": (
                f"{args.public_base_url.rstrip('/')}/{release_prefix}/"
                f"{args.version}/cloudformation"
            ),
            "QUALIFICATION_TEMPLATE_BASE_URL": (
                f"{args.public_base_url.rstrip('/')}/{release_prefix}/{args.version}/"
                "qualification/cloudformation"
            ),
            "PRODUCT_TEMPLATE_URL": (
                f"{args.public_base_url.rstrip('/')}/{release_prefix}/{args.version}/"
                "cloudformation/template.yaml"
            ),
        }
        for region, release in region_release.items():
            token = token_for(region)
            replacements[f"AMI_{token}"] = release["ami_id"]
            replacements[f"ARTIFACT_BUCKET_{token}"] = release["bucket"]
            lambda_versions = object_versions["lambda"][region]
            replacements[f"CONFIGURATION_ARTIFACT_VERSION_{token}"] = json.dumps(
                lambda_versions["configuration.zip"]
            )
            replacements[f"VAPI_PROVISIONER_ARTIFACT_VERSION_{token}"] = json.dumps(
                lambda_versions["vapi_provisioner.zip"]
            )
            replacements[f"HANDOFF_PREPARE_ARTIFACT_VERSION_{token}"] = json.dumps(
                lambda_versions["prepare_handoff.zip"]
            )
            replacements[f"HANDOFF_TRANSFER_ARTIFACT_VERSION_{token}"] = json.dumps(
                lambda_versions["transfer_destination.zip"]
            )
            replacements[f"HANDOFF_LOOKUP_ARTIFACT_VERSION_{token}"] = json.dumps(
                lambda_versions["connect_lookup.zip"]
            )
        for name, version_id in object_versions["nested"].items():
            token = name.removesuffix(".yaml").upper().replace("-", "_")
            replacements[f"NESTED_{token}_VERSION_ID_URLENCODED"] = urllib.parse.quote(
                version_id, safe=""
            )
        replacements["QUALIFICATION_DISPOSABLE_CONNECT_VERSION_ID_URLENCODED"] = (
            urllib.parse.quote(
                object_versions["qualification"]["disposable-connect.yaml"],
                safe="",
            )
        )
        if object_versions.get("product_template") is not None:
            replacements["PRODUCT_TEMPLATE_VERSION_ID_URLENCODED"] = urllib.parse.quote(
                object_versions["product_template"], safe=""
            )
        if args.render_phase in {"product", "complete"}:
            render(
                root / "cloudformation" / "template.yaml",
                staging / "cloudformation" / "template.yaml",
                replacements,
            )
        for source in sorted((root / "cloudformation" / "nested").glob("*.yaml")):
            render(
                source,
                staging / "cloudformation" / "nested" / source.name,
                replacements,
            )
        qualification_sources = [
            root / "qualification" / "cloudformation" / "disposable-connect.yaml"
        ]
        if args.render_phase == "complete":
            qualification_sources.append(
                root / "qualification" / "cloudformation" / "template.yaml"
            )
        for source in qualification_sources:
            render(
                source,
                staging / "qualification" / "cloudformation" / source.name,
                replacements,
            )
        shutil.copyfile(root / "bridgefu.lock.json", staging / "bridgefu.lock.json")
        if args.render_phase != "complete":
            (staging / OUTPUT_MARKER).write_text("generated release output\n")
            if output.exists():
                if not output.is_dir():
                    raise SystemExit(f"release output is not a directory: {output}")
                entries = list(output.iterdir())
                if entries and not (output / OUTPUT_MARKER).is_file():
                    raise SystemExit(
                        f"refusing to replace unowned non-empty release output: {output}"
                    )
                if entries:
                    shutil.rmtree(output)
                else:
                    output.rmdir()
            staging.replace(output)
            print(os.fspath(output))
            return 0
        template_url = (
            f"{args.public_base_url.rstrip('/')}/{release_prefix}/{args.version}/"
            "cloudformation/template.yaml"
        )
        query = urllib.parse.urlencode(
            {
                "templateURL": template_url,
                "stackName": "bridgefu-vapi-connect",
                "param_DeploymentId": "support",
                "param_InstanceType": "t4g.large",
            }
        )
        quick_create = {
            "launch": (
                "https://console.aws.amazon.com/cloudformation/home"
                f"#/stacks/create/review?{query}"
            )
        }
        (staging / "quick-create-links.json").write_text(
            json.dumps(quick_create, indent=2, sort_keys=True) + "\n"
        )
        inventory = []
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                inventory.append(
                    {
                        "path": path.relative_to(staging).as_posix(),
                        "sha256": digest(path),
                        "size_bytes": path.stat().st_size,
                    }
                )
        lock = json.loads((root / "bridgefu.lock.json").read_text())
        manifest = {
            "schema": "bridgefu-vapi-awsconnect-release/v1",
            "version": args.version,
            "supported_regions": region_release,
            "bridgefu": lock,
            "object_versions": object_versions,
            "artifacts": inventory,
            "contains_secrets": False,
        }
        if args.repository_commit is not None:
            manifest["distribution_source"] = {
                "repository": args.repository,
                "repository_commit": args.repository_commit,
            }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        (staging / OUTPUT_MARKER).write_text("generated release output\n")
        if output.exists():
            if not output.is_dir():
                raise SystemExit(f"release output is not a directory: {output}")
            entries = list(output.iterdir())
            if entries and not (output / OUTPUT_MARKER).is_file():
                raise SystemExit(
                    f"refusing to replace unowned non-empty release output: {output}"
                )
            if entries:
                shutil.rmtree(output)
            else:
                output.rmdir()
        staging.replace(output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    print(os.fspath(output / "manifest.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
