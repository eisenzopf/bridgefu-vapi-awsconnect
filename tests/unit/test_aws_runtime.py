from __future__ import annotations

import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

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
        if isinstance(self.response, BaseException):
            raise self.response
        return self.response


class AwsRuntimeTests(unittest.TestCase):
    def test_fresh_secret_read_bypasses_and_does_not_replace_cache(self):
        class Secrets:
            def __init__(self, values):
                self.values = iter(values)
                self.calls = 0

            def get_secret_value(self, *, SecretId):
                self.calls += 1
                self.secret_id = SecretId
                return {"SecretString": next(self.values)}

        arn = "arn:aws:secretsmanager:us-west-2:123456789012:secret:test"
        aws_runtime._SECRET_CACHE.clear()
        client = Secrets(("a" * 32, "b" * 32))
        self.assertEqual(aws_runtime.load_secret(arn, client, now=1), "a" * 32)
        self.assertEqual(
            aws_runtime.load_secret(arn, client, now=2, use_cache=False), "b" * 32
        )
        self.assertEqual(aws_runtime.load_secret(arn, client, now=3), "a" * 32)
        self.assertEqual(client.calls, 2)

    def test_structured_identity_secret_can_use_explicit_short_minimum(self):
        client = mock.Mock()
        client.get_secret_value.return_value = {"SecretString": '{"status":"unbound"}'}
        arn = "arn:aws:secretsmanager:us-west-2:123456789012:secret:identity"
        with self.assertRaisesRegex(HandoffError, "secret_configuration_invalid"):
            aws_runtime.load_secret(arn, client, use_cache=False)
        self.assertEqual(
            aws_runtime.load_secret(arn, client, use_cache=False, minimum_length=1),
            '{"status":"unbound"}',
        )

    def test_short_cached_secret_cannot_bypass_a_stricter_later_minimum(self):
        client = mock.Mock()
        client.get_secret_value.return_value = {"SecretString": '{"status":"unbound"}'}
        arn = "arn:aws:secretsmanager:us-west-2:123456789012:secret:minimum"
        aws_runtime._SECRET_CACHE.clear()
        self.assertEqual(
            aws_runtime.load_secret(arn, client, now=1, minimum_length=1),
            '{"status":"unbound"}',
        )
        with self.assertRaisesRegex(HandoffError, "secret_configuration_invalid"):
            aws_runtime.load_secret(arn, client, now=2, minimum_length=32)
        self.assertEqual(client.get_secret_value.call_count, 2)

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

        # Vapi may retry an already accepted webhook. The same token, call
        # identity, and values must replay the exact Bridgefu replacement
        # receipt rather than turning the successful handoff into a 409.
        replayed = store.prepare_direct(
            "bf1_" + "a" * 43,
            "token_001",
            VapiIdentity("org_001", "vapi_call_001"),
            {"customer_name": "Synthetic"},
            1_800_000_002,
        )
        self.assertEqual(replayed, result)
        self.assertIn(":reserved", client.last_update["ConditionExpression"])
        self.assertEqual(
            client.last_update["ExpressionAttributeValues"][":reserved"],
            {"S": "RESERVED"},
        )
        store.mark_direct_started("bf1_" + "a" * 43, 1_800_000_003)
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
                b'{"call_id":"018f9c2a-7b3d-7ef0-bfee-9d5a5c600001",'
                b'"tenant_id":"support","legs":[]}',
            )
        )
        client._opener = opener
        client.replace(
            "018f9c2a-7b3d-7ef0-bfee-9d5a5c600001",
            "018f9c2a-7b3d-7ef0-bfee-9d5a5c600002",
            "amazon-connect",
            "replace_001",
        )
        self.assertEqual(
            opener.request.full_url,
            "https://control.example.test/v1/calls/"
            "018f9c2a-7b3d-7ef0-bfee-9d5a5c600001/legs/"
            "018f9c2a-7b3d-7ef0-bfee-9d5a5c600002/replace",
        )
        self.assertEqual(opener.request.get_method(), "POST")
        self.assertEqual(opener.request.data, b'{"route_id":"amazon-connect"}')
        self.assertEqual(opener.request.get_header("Idempotency-key"), "replace_001")
        with self.assertRaisesRegex(HandoffError, "bridgefu_replacement_invalid"):
            client.replace("call_001", "leg_001", "attacker-route", "replace_002")

    def test_bridgefu_http_errors_are_not_mislabeled_as_transport_failures(self):
        client = aws_runtime.BridgefuRouteClient(
            "https://control.example.test",
            "amazon-connect",
            "b" * 32,
        )
        cases = tuple(
            (operation, status, f"bridgefu_{noun}_http_{status}", response_status)
            for operation, noun in (
                ("reserve", "reservation"),
                ("replace", "replacement"),
            )
            for status, response_status in (
                (400, 502),
                (401, 502),
                (403, 502),
                (404, 502),
                (408, 503),
                (409, 502),
                (422, 502),
                (425, 503),
                (429, 503),
            )
        ) + (
            ("reserve", 503, "bridgefu_reservation_http_5xx", 503),
            ("replace", 599, "bridgefu_replacement_http_5xx", 503),
            ("reserve", 418, "bridgefu_reservation_failed", 502),
            ("replace", 302, "bridgefu_replacement_failed", 502),
        )
        for operation, status, code, response_status in cases:
            with self.subTest(operation=operation, status=status):
                client._opener = FakeOpener(
                    urllib.error.HTTPError(
                        "https://control.example.test/closed",
                        status,
                        "closed",
                        {},
                        None,
                    )
                )
                with self.assertRaises(HandoffError) as raised:
                    if operation == "reserve":
                        client.reserve("bf1_" + "a" * 43, "reserve_001")
                    else:
                        client.replace(
                            "018f9c2a-7b3d-7ef0-bfee-9d5a5c600001",
                            "018f9c2a-7b3d-7ef0-bfee-9d5a5c600002",
                            "amazon-connect",
                            "replace_001",
                        )
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(raised.exception.status_code, response_status)
                self.assertIn(code, aws_runtime.SAFE_RESULTS)


if __name__ == "__main__":
    unittest.main()
