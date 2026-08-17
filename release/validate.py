#!/usr/bin/env python3
"""Fail-closed local release invariants; remote AWS validation is a later gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from ami_build_inputs import load as load_ami_build_inputs

EXPECTED_TEMPLATE_COUNT = 10
VALIDATION_VERSION = "0.1.0-validation"
ZERO_COMMIT = "0" * 40


def require_command(name: str) -> str:
    command = shutil.which(name)
    if command is None:
        raise SystemExit(f"required local validation tool is missing: {name}")
    return command


def run(command: list[str], *, root: Path, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=root, env=env, check=True)


def tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def validate_release(root: Path) -> None:
    cfn_lint = require_command("cfn-lint")
    load_ami_build_inputs(root / "image" / "build-inputs.json")

    lock = json.loads(
        (root / "bridgefu.lock.json").read_text(encoding="utf-8")
    )
    if lock["required_rvoip_version"] != "0.3.8":
        raise SystemExit("bridgefu.lock.json must pin rvoip 0.3.8")
    if "crates.io-index" not in lock["required_rvoip_source"]:
        raise SystemExit("rvoip source must be crates.io")
    source_templates = [root / "cloudformation" / "template.yaml"] + sorted(
        (root / "cloudformation" / "nested").glob("*.yaml")
    ) + sorted((root / "qualification" / "cloudformation").glob("*.yaml"))
    if len(source_templates) != EXPECTED_TEMPLATE_COUNT:
        raise SystemExit(
            f"expected exactly {EXPECTED_TEMPLATE_COUNT} deployable templates; "
            f"found {len(source_templates)}"
        )
    for path in source_templates:
        text = path.read_text(encoding="utf-8")
        if "VapiApiKey:" in text or "NoEcho: true" in text:
            raise SystemExit(f"raw Vapi keys are forbidden in CloudFormation: {path}")
        if re.search(r"(?i)(secret|token).*(output|value):", text):
            raise SystemExit(f"possible secret output in {path}")

    with (
        tempfile.TemporaryDirectory(prefix="bridgefu-release-a-") as first,
        tempfile.TemporaryDirectory(prefix="bridgefu-release-b-") as second,
    ):
        outputs = (Path(first), Path(second))
        for destination in outputs:
            run(
                [
                    sys.executable,
                    os.fspath(root / "release" / "build_release.py"),
                    "--version",
                    VALIDATION_VERSION,
                    "--repository-commit",
                    ZERO_COMMIT,
                    "--output",
                    os.fspath(destination),
                ],
                root=root,
            )
        if tree_bytes(outputs[0]) != tree_bytes(outputs[1]):
            raise SystemExit("complete release packaging is not deterministic")
        rendered = [outputs[0] / "cloudformation" / "template.yaml"] + sorted(
            (outputs[0] / "cloudformation" / "nested").glob("*.yaml")
        ) + sorted(
            (outputs[0] / "qualification" / "cloudformation").glob("*.yaml")
        )
        if len(rendered) != EXPECTED_TEMPLATE_COUNT:
            raise SystemExit("rendered release template inventory is incomplete")
        run(
            [
                cfn_lint,
                *map(os.fspath, rendered),
                *map(os.fspath, sorted((root / "publisher").glob("*.yaml"))),
            ],
            root=root,
        )


def _packer_platform() -> str:
    system = platform.system()
    machine = platform.machine()
    if system == "Darwin" and machine in {"arm64", "aarch64"}:
        return "darwin_arm64"
    if system == "Linux" and machine in {"x86_64", "amd64"}:
        return "linux_amd64"
    if system == "Linux" and machine in {"aarch64", "arm64"}:
        return "linux_arm64"
    raise SystemExit(
        f"unsupported Packer validation platform: {system}/{machine}"
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_packer(root: Path) -> None:
    packer = require_command("packer")
    curl = require_command("curl")
    inputs = load_ami_build_inputs(root / "image" / "build-inputs.json")
    expected_core = inputs["packer"]["core_version"]
    version_output = subprocess.check_output(
        [packer, "version"], cwd=root, text=True
    )
    match = re.search(r"(?m)^Packer v([^\s]+)$", version_output)
    if match is None or match.group(1) != expected_core:
        raise SystemExit(f"Packer core version mismatch; expected {expected_core}")

    plugin_platform = _packer_platform()
    plugin_version = inputs["packer"]["amazon_plugin_version"]
    expected_digest = inputs["packer"]["amazon_plugin_zip_sha256"][
        plugin_platform
    ]
    binary_name = (
        f"packer-plugin-amazon_v{plugin_version}_x5.0_{plugin_platform}"
    )
    url = (
        "https://github.com/hashicorp/packer-plugin-amazon/releases/download/"
        f"v{plugin_version}/{binary_name}.zip"
    )

    with tempfile.TemporaryDirectory(prefix="bridgefu-packer-") as directory:
        workspace = Path(directory)
        archive = workspace / "packer-plugin-amazon.zip"
        run(
            [
                curl,
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--proto",
                "=https",
                "--tlsv1.2",
                url,
                "--output",
                os.fspath(archive),
            ],
            root=root,
        )
        if _sha256(archive) != expected_digest:
            raise SystemExit("Packer Amazon plugin archive digest mismatch")
        with zipfile.ZipFile(archive) as bundle:
            try:
                payload = bundle.read(binary_name)
            except KeyError as error:
                raise SystemExit(
                    "Packer Amazon plugin archive does not contain the exact binary"
                ) from error
        binary = workspace / binary_name
        binary.write_bytes(payload)
        binary.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        plugin_path = workspace / "plugins"
        config_path = workspace / "config"
        plugin_path.mkdir(mode=0o700)
        config_path.mkdir(mode=0o700)
        environment = {
            **os.environ,
            "PACKER_PLUGIN_PATH": os.fspath(plugin_path),
            "PACKER_CONFIG_DIR": os.fspath(config_path),
        }
        run(
            [
                packer,
                "plugins",
                "install",
                "--path",
                os.fspath(binary),
                "github.com/hashicorp/amazon",
            ],
            root=root,
            env=environment,
        )
        installed = subprocess.check_output(
            [packer, "plugins", "installed"],
            cwd=root,
            env=environment,
            text=True,
        )
        if installed.count(f"/{binary_name}") != 1:
            raise SystemExit("exact Packer Amazon plugin was not installed once")
        run(
            [packer, "init", os.fspath(root / "image" / "bridgefu.pkr.hcl")],
            root=root,
            env=environment,
        )
        lock = json.loads(
            (root / "bridgefu.lock.json").read_text(encoding="utf-8")
        )
        run(
            [
                packer,
                "validate",
                "-var",
                f"aws_region={inputs['source_ami']['region']}",
                "-var",
                f"source_ami_id={inputs['source_ami']['id']}",
                "-var",
                f"bridgefu_commit={lock['commit']}",
                "-var",
                f"bridgefu_cargo_lock_sha256={lock['cargo_lock_sha256']}",
                "-var",
                "candidate_id=candidate-0.1.0-dev-local-validation",
                "-var",
                f"distribution_repository_commit={ZERO_COMMIT}",
                "-var",
                "release_version=0.1.0-dev",
                os.fspath(root / "image" / "bridgefu.pkr.hcl"),
            ],
            root=root,
            env=environment,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--packer-only",
        action="store_true",
        help="verify immutable Packer inputs and validate the AMI template",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.packer_only:
        validate_packer(root)
        print("immutable Packer validation passed")
    else:
        validate_release(root)
        print("deterministic release and CloudFormation validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
