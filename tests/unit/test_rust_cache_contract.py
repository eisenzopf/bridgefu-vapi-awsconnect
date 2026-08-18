from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CACHE_SHA = "0400d5f644dc74513175e3cd8d07132dd4860809"


class RustCacheContractTests(unittest.TestCase):
    def test_every_rust_cache_is_immutable_and_exactly_keyed(self) -> None:
        for relative in (
            ".github/workflows/ci.yml",
            ".github/workflows/candidate.yml",
            ".github/workflows/remote-qualification.yml",
        ):
            with self.subTest(workflow=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                yaml.safe_load(text)
                self.assertIn(f"actions/cache@{CACHE_SHA}", text)
                self.assertIn("rustc -vV", text)
                self.assertIn("${{ runner.os }}-${{ runner.arch }}", text)
                self.assertIn("hashFiles('qualification/sip-client/Cargo.lock'", text)
                self.assertNotIn("restore-keys:", text)

    def test_ci_caches_each_native_target_but_never_packer_output(self) -> None:
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        for path in (
            "qualification/sdp-observer/target",
            "qualification/sip-client/target",
            "qualification/direct-secure-probe/target",
        ):
            self.assertIn(path, text)
        self.assertNotIn("target/packer-manifest.json\n          key:", text)


if __name__ == "__main__":
    unittest.main()
