from __future__ import annotations

import sys
import unittest
from pathlib import Path

COMMON = Path(__file__).resolve().parents[2] / "lambda" / "common"
sys.path.insert(0, str(COMMON))

import aws_runtime  # noqa: E402
from bridgefu_handoff import HandoffError  # noqa: E402


class ConditionalFailure(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeDynamo:
    def __init__(self):
        self.item = None
        self.last_get = None

    def get_item(self, **kwargs):
        self.last_get = kwargs
        return {"Item": self.item} if self.item is not None else {}

    def put_item(self, **kwargs):
        if self.item is not None:
            raise ConditionalFailure()
        self.item = kwargs["Item"]


class AwsRuntimeTests(unittest.TestCase):
    def test_schema_v2_map_round_trips_and_replays(self):
        client = FakeDynamo()
        store = aws_runtime.DynamoHandoffStore("handoff-table", client=client)
        record = {
            "schema_version": 2,
            "correlation_id": "bf1_" + "a" * 43,
            "screen_pop_values": {
                "customer_name": "Synthetic Caller",
                "queue": "support",
            },
            "screen_pop_schema_hash": "d" * 64,
            "vapi_call_fingerprint": "b" * 64,
            "content_hash": "c" * 64,
            "handoff_status": "PREPARED",
            "expires_at": 1_900_000_000,
        }
        self.assertEqual(store.put_prepared(record), "created")
        self.assertEqual(store.put_prepared(record), "replayed")
        self.assertEqual(store.get(record["correlation_id"]), record)
        projection = client.last_get["ProjectionExpression"]
        self.assertIn("screen_pop_values", projection)
        self.assertIn("screen_pop_schema_hash", projection)

    def test_dynamo_adapter_rejects_unbounded_or_unsupported_values(self):
        for value in (True, [], {}, {"nested": {"too": {"deep": "value"}}}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(HandoffError, "handoff_store_invalid"):
                    aws_runtime._encode_item({"field": value})

        with self.assertRaisesRegex(HandoffError, "handoff_store_invalid"):
            aws_runtime._decode_item({"field": {"BOOL": True}})


if __name__ == "__main__":
    unittest.main()
