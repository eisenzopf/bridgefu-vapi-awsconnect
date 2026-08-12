#!/usr/bin/env python3
"""Build the deterministic, credential-free Vapi Web qualification site."""

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


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def build(output: Path) -> Path:
    qualification = Path(__file__).resolve().parent
    source = qualification / "demo-site"
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
    try:
        for name in ("package.json", "package-lock.json"):
            shutil.copyfile(qualification / name, work / name)
        subprocess.run(
            ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=work,
            check=True,
            stdout=subprocess.DEVNULL,
        )
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
        licenses = {
            "schema_version": 1,
            "generated_from": "qualification/package-lock.json",
            "packages": installed_packages(work / "node_modules"),
        }
        (public / "third-party-licenses.json").write_text(
            json.dumps(licenses, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        archive = staging / "demo-site.zip"
        zip_files(public, archive)
        manifest = {
            "schema_version": 1,
            "producer": "bridgefu-vapi-awsconnect-qualification-site@1",
            "package_lock_sha256": digest(qualification / "package-lock.json"),
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
