from __future__ import annotations

import sys
import unittest
from pathlib import Path

COMMON = Path(__file__).resolve().parents[2] / "lambda" / "common"
sys.path.insert(0, str(COMMON))

import aws_runtime  # noqa: E402
from bridgefu_handoff import HandoffError, VapiIdentity  # noqa: E402


class ConditionalFailure(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeDynamo:
    def __init__(self):
        self.item = None
        self.last_get = None
        self.last_update = None

    def get_item(self, **kwargs):
        self.last_get = kwargs
        return {"Item": self.item} if self.item is not None else {}

    def put_item(self, **kwargs):
        if self.item is not None:
            raise ConditionalFailure()
        self.item = kwargs["Item"]

    def update_item(self, **kwargs):
        self.last_update = kwargs
        values = kwargs["ExpressionAttributeValues"]
        if kwargs.get("ReturnValues") == "ALL_NEW":
            self.item.update(
                {
                    "handoff_status": values[":prepared"],
                    "updated_at": values[":updated"],
                    "screen_pop_values": values[":values"],
                    "content_hash": values[":content"],
                    "vapi_call_fingerprint": values[":identity"],
                }
            )
            return {"Attributes": dict(self.item)}
        self.item["handoff_status"] = values[":reserved"]
        self.item["updated_at"] = values[":updated"]
        return {}


class FakeHttpResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _maximum):
        return self.body


class FakeOpener:
    def __init__(self, response):
        self.response = response
        self.request = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return self.response


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

    def test_direct_store_returns_only_prebound_call_leg_route_and_receipt(self):
        client = FakeDynamo()
        client.item = aws_runtime._encode_item(
            {
                "correlation_id": "bf1_" + "a" * 43,
                "direct_token_id": "token_001",
                "bridgefu_call_id": "call_001",
                "direct_leg_id": "leg_001",
                "direct_route_id": "amazon-connect",
                "direct_idempotency_key": "replace_001",
                "handoff_status": "MAPPED",
                "expires_at": 1_900_000_000,
            }
        )
        store = aws_runtime.DynamoHandoffStore("handoff-table", client=client)
        result = store.prepare_direct(
            "bf1_" + "a" * 43,
            "token_001",
            VapiIdentity("org_001", "vapi_call_001"),
            {"customer_name": "Synthetic"},
            1_800_000_000,
        )
        self.assertEqual(
            result,
            {
                "call_id": "call_001",
                "leg_id": "leg_001",
                "route_id": "amazon-connect",
                "idempotency_key": "replace_001",
            },
        )
        self.assertIn(
            "direct_token_id = :token", client.last_update["ConditionExpression"]
        )
        self.assertNotIn("org_001", str(client.last_update))
        self.assertNotIn("vapi_call_001", str(client.last_update))
        store.mark_direct_started("bf1_" + "a" * 43, 1_800_000_001)
        self.assertEqual(
            aws_runtime._decode_item(client.item)["handoff_status"], "RESERVED"
        )

    def test_bridgefu_replace_uses_exact_server_route_and_bounded_response(self):
        client = aws_runtime.BridgefuRouteClient(
            "https://control.example.test",
            "amazon-connect",
            "b" * 32,
        )
        opener = FakeOpener(
            FakeHttpResponse(
                202,
                b'{"call_id":"call_001","tenant_id":"support","legs":[]}',
            )
        )
        client._opener = opener
        client.replace("call_001", "leg_001", "amazon-connect", "replace_001")
        self.assertEqual(
            opener.request.full_url,
            "https://control.example.test/v1/calls/call_001/legs/leg_001/replace",
        )
        self.assertEqual(opener.request.get_method(), "POST")
        self.assertEqual(opener.request.data, b'{"route_id":"amazon-connect"}')
        self.assertEqual(opener.request.get_header("Idempotency-key"), "replace_001")
        with self.assertRaisesRegex(HandoffError, "bridgefu_replacement_invalid"):
            client.replace("call_001", "leg_001", "attacker-route", "replace_002")


if __name__ == "__main__":
    unittest.main()
