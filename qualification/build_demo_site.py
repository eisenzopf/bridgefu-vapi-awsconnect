#!/usr/bin/env python3
"""Build the deterministic, credential-free Bridgefu Web qualification site."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

MARKER = ".bridgefu-qualification-demo-site"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)
PUBLIC_FILES = (
    "index.html",
    "style.css",
    "app.js",
    "app.js.LEGAL.txt",
    "third-party-licenses.json",
)
SDK_NAME = "@bridgefu/webrtc-browser"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root: Path) -> str:
    records = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": digest(path),
            "size_bytes": path.stat().st_size,
        }
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    ]
    encoded = json.dumps(records, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def installed_packages(node_modules: Path) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    manifests = sorted(node_modules.glob("*/package.json")) + sorted(
        node_modules.glob("@*/*/package.json")
    )
    for manifest in manifests:
        value = json.loads(manifest.read_text(encoding="utf-8"))
        name = value.get("name")
        version = value.get("version")
        license_name = value.get("license", "UNKNOWN")
        if isinstance(name, str) and isinstance(version, str):
            packages.append(
                {
                    "name": name,
                    "version": version,
                    "license": (
                        license_name
                        if isinstance(license_name, str)
                        else "SEE-PACKAGE"
                    ),
                }
            )
    return sorted(packages, key=lambda item: (item["name"], item["version"]))


def zip_files(source: Path, output: Path) -> None:
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name in PUBLIC_FILES:
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (source / name).read_bytes())


def verified_sdk_checkout(qualification: Path, checkout: Path) -> dict[str, str]:
    checkout = checkout.resolve()
    source_lock = json.loads((qualification.parent / "bridgefu.lock.json").read_text())
    expected_commit = source_lock.get("commit")
    expected_cargo_lock = source_lock.get("cargo_lock_sha256")
    if (
        not checkout.is_dir()
        or checkout.is_symlink()
        or not isinstance(expected_commit, str)
        or not isinstance(expected_cargo_lock, str)
    ):
        raise SystemExit("pinned Bridgefu SDK checkout is invalid")
    actual_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual_commit != expected_commit:
        raise SystemExit("Bridgefu SDK checkout is not at the pinned commit")
    cargo_lock = checkout / "Cargo.lock"
    if not cargo_lock.is_file() or digest(cargo_lock) != expected_cargo_lock:
        raise SystemExit("Bridgefu SDK checkout Cargo.lock is not pinned")
    sdk = checkout / "sdk" / "typescript"
    package = json.loads((sdk / "package.json").read_text())
    if package.get("name") != SDK_NAME or package.get("version") != "0.1.0":
        raise SystemExit("Bridgefu browser SDK package identity is invalid")
    for path in (sdk / "package-lock.json", sdk / "tsconfig.json", sdk / "src"):
        if not path.exists() or path.is_symlink():
            raise SystemExit("Bridgefu browser SDK source is incomplete")
    return {
        "checkout": str(checkout),
        "commit": actual_commit,
        "cargo_lock_sha256": expected_cargo_lock,
        "sdk": str(sdk),
        "sdk_version": str(package["version"]),
        "sdk_package_lock_sha256": digest(sdk / "package-lock.json"),
    }


def build(output: Path, bridgefu_checkout: Path) -> Path:
    qualification = Path(__file__).resolve().parent
    source = qualification / "demo-site"
    verified = verified_sdk_checkout(qualification, bridgefu_checkout)
    sdk_source = Path(verified["sdk"])
    output = output.resolve()
    if output.exists() and (
        output.is_symlink()
        or not output.is_dir()
        or not (output / MARKER).is_file()
    ):
        raise SystemExit(f"refusing to replace unmarked output directory: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    work = Path(tempfile.mkdtemp(prefix="bridgefu-qualification-site-"))
    sdk_work = Path(tempfile.mkdtemp(prefix="bridgefu-browser-sdk-"))
    try:
        for name in ("package.json", "package-lock.json"):
            shutil.copyfile(qualification / name, work / name)
        subprocess.run(
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=work,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        for name in ("package.json", "package-lock.json", "tsconfig.json"):
            shutil.copyfile(sdk_source / name, sdk_work / name)
        shutil.copytree(sdk_source / "src", sdk_work / "src")
        subprocess.run(
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=sdk_work,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            ["npm", "run", "build", "--silent"],
            cwd=sdk_work,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        sdk_dist = sdk_work / "dist"
        if not (sdk_dist / "index.js").is_file():
            raise SystemExit("Bridgefu browser SDK build produced no entry point")
        public = work / "public"
        public.mkdir()
        for name in ("index.html", "style.css"):
            shutil.copyfile(source / name, public / name)
        app_source = work / "app.js"
        shutil.copyfile(source / "app.js", app_source)
        subprocess.run(
            [
                os.fspath(work / "node_modules" / ".bin" / "esbuild"),
                os.fspath(app_source),
                "--bundle",
                "--format=esm",
                "--platform=browser",
                "--target=es2022",
                "--minify",
                "--legal-comments=external",
                f"--alias:{SDK_NAME}={sdk_dist / 'index.js'}",
                f"--outfile={public / 'app.js'}",
            ],
            cwd=work,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        legal = public / "app.js.LEGAL.txt"
        if not legal.is_file():
            legal.write_text(
                "Third-party package names, versions, and license identifiers are in "
                "third-party-licenses.json.\n",
                encoding="utf-8",
            )
        packages = installed_packages(work / "node_modules")
        packages.extend(installed_packages(sdk_work / "node_modules"))
        packages.append(
            {"name": SDK_NAME, "version": verified["sdk_version"], "license": "MIT"}
        )
        licenses = {
            "schema_version": 1,
            "generated_from": [
                "qualification/package-lock.json",
                "bridgefu/sdk/typescript/package-lock.json",
            ],
            "packages": sorted(
                {json.dumps(item, sort_keys=True): item for item in packages}.values(),
                key=lambda item: (item["name"], item["version"]),
            ),
        }
        (public / "third-party-licenses.json").write_text(
            json.dumps(licenses, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        archive = staging / "demo-site.zip"
        zip_files(public, archive)
        manifest = {
            "schema_version": 2,
            "producer": "bridgefu-vapi-awsconnect-qualification-site@2",
            "package_lock_sha256": digest(qualification / "package-lock.json"),
            "bridgefu_commit": verified["commit"],
            "bridgefu_cargo_lock_sha256": verified["cargo_lock_sha256"],
            "bridgefu_sdk": {
                "name": SDK_NAME,
                "version": verified["sdk_version"],
                "package_lock_sha256": verified["sdk_package_lock_sha256"],
                "dist_sha256": tree_digest(sdk_dist),
            },
            "archive_sha256": digest(archive),
            "files": [
                {
                    "path": name,
                    "sha256": digest(public / name),
                    "size_bytes": (public / name).stat().st_size,
                }
                for name in PUBLIC_FILES
            ],
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (staging / MARKER).write_text(
            "bridgefu qualification demo-site build\n", encoding="utf-8"
        )
        if output.exists():
            shutil.rmtree(output)
        staging.replace(output)
        return output / "demo-site.zip"
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(sdk_work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bridgefu-checkout", type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output, args.bridgefu_checkout))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
