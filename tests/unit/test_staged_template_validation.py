from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "release"))

import validate_staged_templates as subject  # noqa: E402

CANDIDATE_ID = "candidate-0.1.20-abcdef123456-12345-1"
BUCKET = "bridgefu-vapi-awsconnect-123456789012-us-east-1"
VERSION = "0.1.20"


def bodies_and_journal() -> tuple[dict[str, bytes], dict[str, Any]]:
    bodies: dict[str, bytes] = {}
    objects: list[dict[str, Any]] = []
    for index, relative in enumerate(subject.EXACT_TEMPLATES):
        key = f"releases/{VERSION}/{relative}"
        body = f"AWSTemplateFormatVersion: '2010-09-09'\nDescription: {index}\n".encode()
        bodies[key] = body
        objects.append(
            {
                "region": "us-east-1",
                "bucket": BUCKET,
                "key": key,
                "version_id": f"version+{index}=exact",
                "sha256": hashlib.sha256(body).hexdigest(),
                "size_bytes": len(body),
            }
        )
    return bodies, {"schema": subject.STAGED_SCHEMA, "objects": objects}


class FakeAws:
    def __init__(
        self,
        bodies: dict[str, bytes],
        records: tuple[dict[str, Any], ...],
        *,
        head_size_delta: int = 0,
        corrupt_download: bool = False,
        corrupt_key: str | None = None,
        foreign_candidate: bool = False,
    ) -> None:
        self.bodies = bodies
        self.records = {record["key"]: record for record in records}
        self.head_size_delta = head_size_delta
        self.corrupt_download = corrupt_download
        self.corrupt_key = corrupt_key
        self.foreign_candidate = foreign_candidate
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, arguments: list[str] | tuple[str, ...]) -> dict[str, Any]:
        call = tuple(arguments)
        self.calls.append(call)
        if call[:2] == ("cloudformation", "validate-template"):
            return {"Parameters": []}
        key = call[call.index("--key") + 1]
        record = self.records[key]
        metadata = {
            "sha256": record["sha256"],
            "candidate-id": "foreign" if self.foreign_candidate else CANDIDATE_ID,
        }
        result = {
            "VersionId": record["version_id"],
            "ContentLength": record["size_bytes"],
            "Metadata": metadata,
        }
        if call[:2] == ("s3api", "head-object"):
            result["ContentLength"] += self.head_size_delta
            return result
        if call[:2] != ("s3api", "get-object"):
            raise AssertionError(call)
        body = self.bodies[key]
        if self.corrupt_download and (self.corrupt_key is None or key == self.corrupt_key):
            body += b"tampered"
        Path(call[-1]).write_bytes(body)
        return result


class StagedTemplateValidationTests(unittest.TestCase):
    def load(self, journal: dict[str, Any]) -> tuple[dict[str, Any], ...]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "staged.json"
            path.write_text(json.dumps(journal))
            return subject.load_exact_template_records(
                path, release_version=VERSION, bucket=BUCKET
            )

    def test_all_ten_exact_downloads_precede_twenty_remote_validations(self):
        bodies, journal = bodies_and_journal()
        records = self.load(journal)
        aws = FakeAws(bodies, records)
        subject.verify_and_validate(
            records=records,
            candidate_id=CANDIDATE_ID,
            regions=("us-west-2", "us-east-1"),
            aws_json=aws,
        )
        heads = [call for call in aws.calls if call[:2] == ("s3api", "head-object")]
        gets = [call for call in aws.calls if call[:2] == ("s3api", "get-object")]
        validates = [
            call
            for call in aws.calls
            if call[:2] == ("cloudformation", "validate-template")
        ]
        self.assertEqual(len(heads), 10)
        self.assertEqual(len(gets), 10)
        self.assertEqual(len(validates), 20)
        for record in records:
            self.assertTrue(
                any(
                    call[call.index("--version-id") + 1] == record["version_id"]
                    for call in heads
                    if call[call.index("--key") + 1] == record["key"]
                )
            )
            expected_url = subject.exact_template_url(record)
            self.assertIn("?versionId=version%2B", expected_url)
            self.assertEqual(
                sum(expected_url in call for call in validates),
                2,
            )

    def test_missing_duplicate_or_foreign_template_record_fails_closed(self):
        _, journal = bodies_and_journal()
        cases = []
        missing = json.loads(json.dumps(journal))
        missing["objects"].pop()
        cases.append(missing)
        duplicate = json.loads(json.dumps(journal))
        duplicate["objects"].append(dict(duplicate["objects"][0]))
        cases.append(duplicate)
        foreign = json.loads(json.dumps(journal))
        foreign["objects"][0]["region"] = "us-west-2"
        cases.append(foreign)
        for case in cases:
            with self.subTest(case=cases.index(case)):
                with self.assertRaises(subject.StagedTemplateError):
                    self.load(case)

    def test_head_or_download_tampering_blocks_every_validate_call(self):
        bodies, journal = bodies_and_journal()
        records = self.load(journal)
        for options in (
            {"head_size_delta": 1},
            {"corrupt_download": True},
            {"corrupt_download": True, "corrupt_key": records[-1]["key"]},
            {"foreign_candidate": True},
        ):
            with self.subTest(options=options):
                aws = FakeAws(bodies, records, **options)
                with self.assertRaises(subject.StagedTemplateError):
                    subject.verify_and_validate(
                        records=records,
                        candidate_id=CANDIDATE_ID,
                        regions=("us-west-2", "us-east-1"),
                        aws_json=aws,
                    )
                self.assertFalse(
                    any(
                        call[:2] == ("cloudformation", "validate-template")
                        for call in aws.calls
                    )
                )

    def test_candidate_runs_extracted_remote_exact_validator(self):
        workflow = (ROOT / ".github" / "workflows" / "candidate.yml").read_text()
        self.assertIn("python release/validate_staged_templates.py", workflow)
        self.assertIn("--staged-objects target/candidate/staged-objects.json", workflow)
        self.assertIn('--candidate-id "$CANDIDATE_ID"', workflow)
        self.assertIn('--bucket "$east_bucket"', workflow)

    def test_region_catalog_cannot_silently_skip_either_release_region(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "regions.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": subject.REGIONS_SCHEMA,
                        "regions": [{"code": "us-west-2"}],
                    }
                )
            )
            with self.assertRaises(subject.StagedTemplateError):
                subject.load_supported_regions(path)


if __name__ == "__main__":
    unittest.main()
