from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "qualification_controller_site_contract",
    ROOT / "qualification" / "controller.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("qualification controller could not be imported")
CONTROLLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONTROLLER)


def site_archive(path: Path, *, extra: str | None = None) -> str:
    with zipfile.ZipFile(path, "w") as bundle:
        for name in sorted(CONTROLLER.DEMO_SITE_FILES):
            bundle.writestr(name, f"synthetic {name}\n")
        if extra:
            bundle.writestr(extra, "unexpected\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SitePreflightContractTests(unittest.TestCase):
    def test_archive_digest_and_exact_contents_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "site.zip"
            digest = site_archive(archive)
            site, observed = CONTROLLER.prepare_demo_site_archive(
                archive, digest, root / "site"
            )
            self.assertEqual(observed, digest)
            self.assertEqual(
                {item.name for item in site.iterdir()}, CONTROLLER.DEMO_SITE_FILES
            )

            with self.assertRaisesRegex(
                CONTROLLER.QualificationError, "digest does not match"
            ):
                CONTROLLER.prepare_demo_site_archive(
                    archive, "0" * 64, root / "bad-digest"
                )

            unexpected = root / "unexpected.zip"
            unexpected_digest = site_archive(unexpected, extra="customer-secret.txt")
            with self.assertRaisesRegex(
                CONTROLLER.QualificationError, "contents are invalid"
            ):
                CONTROLLER.prepare_demo_site_archive(
                    unexpected, unexpected_digest, root / "unexpected"
                )

    def test_run_validates_site_before_any_aws_preflight_or_deploy(self):
        controller = CONTROLLER.Controller.__new__(CONTROLLER.Controller)
        controller.phase = "initialization"
        controller.primary = []
        controller.validate_inputs = mock.Mock()
        controller.build_site = mock.Mock(
            side_effect=CONTROLLER.QualificationError("candidate site is bad")
        )
        controller.preflight = mock.Mock()
        controller.deploy = mock.Mock()
        controller.record_failure_evidence = mock.Mock()
        controller.cleanup = mock.Mock(return_value={})
        controller.stop_active_work = mock.Mock(return_value=[])
        controller.record_retained_environment = mock.Mock()
        controller.work = Path(tempfile.mkdtemp(prefix="site-ordering-test-"))
        controller.args = SimpleNamespace(retain_on_failure=False)

        with self.assertRaisesRegex(
            CONTROLLER.QualificationError, "candidate site is bad"
        ):
            controller.run()
        controller.preflight.assert_not_called()
        controller.deploy.assert_not_called()
        controller.cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
