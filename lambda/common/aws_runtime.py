"""AWS adapters for the handoff contract.

Only resource identifiers and low-cardinality result codes may be logged by
entrypoints. This module never logs secret strings, handoff rows, or payloads.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

from bridgefu_handoff import CORRELATION, HandoffError, SipReservation

_SECRET_CACHE: dict[str, tuple[str, float]] = {}
_SECRET_LOCK = threading.Lock()
SECRET_CACHE_TTL_SECONDS = 300.0
UUID = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
SAFE_EVENTS = {
    "prepare_handoff",
    "transfer_destination",
    "connect_lookup",
    "direct_browser_handoff",
    "vapi_provisioner",
}
SAFE_RESULTS = {
    "created",
    "replayed",
    "reserved",
    "available",
    "unavailable",
    "create_success",
    "update_success",
    "delete_success",
    "delete_retained",
    "direct_started",
    "vapi_identity_binding_invalid",
    "vapi_identity_mismatch",
    "provisioning_failed",
    "authentication_unavailable",
    "bridgefu_configuration_invalid",
    "bridgefu_destination_expired",
    "bridgefu_destination_invalid",
    "bridgefu_reservation_failed",
    "bridgefu_reservation_http_400",
    "bridgefu_reservation_http_401",
    "bridgefu_reservation_http_403",
    "bridgefu_reservation_http_404",
    "bridgefu_reservation_http_408",
    "bridgefu_reservation_http_409",
    "bridgefu_reservation_http_422",
    "bridgefu_reservation_http_425",
    "bridgefu_reservation_http_429",
    "bridgefu_reservation_http_5xx",
    "bridgefu_reservation_unavailable",
    "bridgefu_response_invalid",
    "bridgefu_replacement_failed",
    "bridgefu_replacement_http_400",
    "bridgefu_replacement_http_401",
    "bridgefu_replacement_http_403",
    "bridgefu_replacement_http_404",
    "bridgefu_replacement_http_408",
    "bridgefu_replacement_http_409",
    "bridgefu_replacement_http_422",
    "bridgefu_replacement_http_425",
    "bridgefu_replacement_http_429",
    "bridgefu_replacement_http_5xx",
    "bridgefu_replacement_invalid",
    "bridgefu_replacement_unavailable",
    "conflicting_tool_arguments",
    "context_too_large",
    "correlation_derivation_failed",
    "handoff_expired",
    "handoff_identity_conflict",
    "handoff_not_prepared",
    "handoff_replay_conflict",
    "handoff_state_conflict",
    "handoff_store_invalid",
    "direct_handoff_binding_invalid",
    "direct_handoff_conflict",
    "invalid_direct_handoff_key",
    "invalid_direct_handoff_token",
    "invalid_context_ttl",
    "invalid_correlation_key",
    "invalid_http_request",
    "invalid_json",
    "invalid_tool_arguments",
    "invalid_tool_call",
    "invalid_tool_name",
    "invalid_vapi_call",
    "invalid_vapi_event",
    "request_too_large",
    "secret_configuration_invalid",
    "unauthorized",
    "unsupported_content_type",
    "internal_error",
}
BRIDGEFU_EXACT_HTTP_STATUSES = frozenset({400, 401, 403, 404, 408, 409, 422, 425, 429})
BRIDGEFU_RETRYABLE_HTTP_STATUSES = frozenset({408, 425, 429})
BRIDGEFU_CONFLICT_RETRY_DELAYS_SECONDS = (0.17, 0.53, 1.11, 2.03)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _bridgefu_http_error(operation: str, status: int) -> HandoffError:
    """Map one upstream status to a closed, body-free diagnostic category."""
    if operation not in {"reservation", "replacement"}:
        return HandoffError("internal_error", 500)
    if status in BRIDGEFU_EXACT_HTTP_STATUSES:
        result = f"bridgefu_{operation}_http_{status}"
    elif 500 <= status <= 599:
        result = f"bridgefu_{operation}_http_5xx"
    else:
        result = f"bridgefu_{operation}_failed"
    public_status = (
        503
        if status in BRIDGEFU_RETRYABLE_HTTP_STATUSES or 500 <= status <= 599
        else 502
    )
    return HandoffError(result, public_status)


def _bridgefu_error_code(error: urllib.error.HTTPError) -> str | None:
    """Read only Bridgefu's closed error code from one bounded response."""
    try:
        raw = error.read(4097)
    except (OSError, ValueError):
        return None
    if len(raw) > 4096:
        return None
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    envelope = payload.get("error") if isinstance(payload, Mapping) else None
    code = envelope.get("code") if isinstance(envelope, Mapping) else None
    return code if code in {"call_conflict", "invalid_transition"} else None


def _boto3_client(service: str):
    import boto3  # AWS Lambda runtime dependency; intentionally not vendored.

    return boto3.client(service)


def load_secret(
    secret_arn: str,
    client=None,
    now=None,
    *,
    use_cache: bool = True,
    minimum_length: int = 32,
) -> str:
    if (
        not isinstance(secret_arn, str)
        or not secret_arn.startswith("arn:")
        or not isinstance(minimum_length, int)
        or not 1 <= minimum_length <= 65_536
    ):
        raise HandoffError("secret_configuration_invalid", 500)
    current = time.monotonic() if now is None else float(now)
    if use_cache:
        with _SECRET_LOCK:
            cached = _SECRET_CACHE.get(secret_arn)
        if (
            cached is not None
            and current - cached[1] < SECRET_CACHE_TTL_SECONDS
            and len(cached[0]) >= minimum_length
        ):
            return cached[0]
    client = client or _boto3_client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_arn)
    value = response.get("SecretString")
    if not isinstance(value, str) or len(value) < minimum_length:
        raise HandoffError("secret_configuration_invalid", 500)
    if use_cache:
        with _SECRET_LOCK:
            _SECRET_CACHE[secret_arn] = (value, current)
    return value


def emit_operation(event: str, result: str, started_at: float) -> None:
    """Emit one bounded EMF record with no request body or identifiers."""
    safe_event = event if event in SAFE_EVENTS else "internal"
    safe_result = result if result in SAFE_RESULTS else "internal_error"
    duration = max(0.0, min(120_000.0, (time.monotonic() - started_at) * 1000.0))
    print(
        json.dumps(
            {
                "_aws": {
                    "Timestamp": int(time.time() * 1000),
                    "CloudWatchMetrics": [
                        {
                            "Namespace": "Bridgefu/Recipe",
                            "Dimensions": [["operation", "result"]],
                            "Metrics": [
                                {"Name": "Requests", "Unit": "Count"},
                                {"Name": "Duration", "Unit": "Milliseconds"},
                            ],
                        }
                    ],
                },
                "event": safe_event,
                "operation": safe_event,
                "result": safe_result,
                "Requests": 1,
                "Duration": round(duration, 3),
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def emit_correlation_evidence(
    operation: str,
    result: str,
    correlation_id: str,
) -> None:
    """Emit one bounded lookup audit event without the correlation identifier."""
    if (
        operation not in SAFE_EVENTS
        or result not in SAFE_RESULTS
        or not isinstance(correlation_id, str)
        or CORRELATION.fullmatch(correlation_id) is None
    ):
        return
    print(
        json.dumps(
            {
                "event": "bridgefu_correlation_evidence",
                "operation": operation,
                "result": result,
                "correlation_fingerprint": hashlib.sha256(
                    correlation_id.encode("ascii")
                ).hexdigest()[:12],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )


def _decode_value(value: Any, depth: int = 0) -> Any:
    if depth > 2 or not isinstance(value, Mapping) or len(value) != 1:
        raise HandoffError("handoff_store_invalid", 500)
    kind, raw = next(iter(value.items()))
    if kind == "S" and isinstance(raw, str):
        return raw
    if kind == "N" and isinstance(raw, str):
        try:
            return int(raw)
        except ValueError:
            raise HandoffError("handoff_store_invalid", 500) from None
    if kind == "M" and isinstance(raw, Mapping) and raw:
        if any(not isinstance(key, str) or not key for key in raw):
            raise HandoffError("handoff_store_invalid", 500)
        return {key: _decode_value(item, depth + 1) for key, item in raw.items()}
    raise HandoffError("handoff_store_invalid", 500)


def _decode_item(item: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _decode_value(value) for key, value in item.items()}


def _encode_value(value: Any, depth: int = 0) -> dict[str, Any]:
    if depth > 2 or isinstance(value, bool):
        raise HandoffError("handoff_store_invalid", 500)
    if isinstance(value, int):
        return {"N": str(value)}
    if isinstance(value, str):
        return {"S": value}
    if isinstance(value, Mapping) and value:
        if any(not isinstance(key, str) or not key for key in value):
            raise HandoffError("handoff_store_invalid", 500)
        return {
            "M": {key: _encode_value(item, depth + 1) for key, item in value.items()}
        }
    raise HandoffError("handoff_store_invalid", 500)


def _encode_item(record: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {key: _encode_value(value) for key, value in record.items()}


def _conditional_failure(error: Exception) -> bool:
    response = getattr(error, "response", None)
    return (
        isinstance(response, Mapping)
        and response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"
    )


class DynamoHandoffStore:
    def __init__(self, table_name: str, client=None) -> None:
        if not isinstance(table_name, str) or not table_name:
            raise HandoffError("handoff_store_invalid", 500)
        self._table_name = table_name
        self._client = client or _boto3_client("dynamodb")

    def get(self, correlation_id: str) -> Mapping[str, Any] | None:
        response = self._client.get_item(
            TableName=self._table_name,
            Key={"correlation_id": {"S": correlation_id}},
            ConsistentRead=True,
            ProjectionExpression=(
                "schema_version,correlation_id,customer_name,issue_summary,intent,"
                "verification_status,vapi_call_reference,vapi_call_fingerprint,"
                "content_hash,created_at,updated_at,expires_at,handoff_status,"
                "bridgefu_call_id,attachment_expires_at,screen_pop_values,"
                "screen_pop_schema_hash,direct_token_id,direct_leg_id,"
                "direct_route_id,direct_idempotency_key"
            ),
        )
        item = response.get("Item")
        return _decode_item(item) if isinstance(item, Mapping) else None

    def put_prepared(self, record: Mapping[str, Any]) -> str:
        try:
            self._client.put_item(
                TableName=self._table_name,
                Item=_encode_item(record),
                ConditionExpression="attribute_not_exists(correlation_id)",
            )
            return "created"
        except Exception as error:
            if not _conditional_failure(error):
                raise
        existing = self.get(str(record["correlation_id"]))
        exact = (
            existing is not None
            and existing.get("schema_version") == record.get("schema_version")
            and existing.get("vapi_call_fingerprint")
            == record.get("vapi_call_fingerprint")
            and existing.get("content_hash") == record.get("content_hash")
            and existing.get("handoff_status") in ("PREPARED", "RESERVED")
        )
        if not exact:
            raise HandoffError("handoff_replay_conflict", 409)
        return "replayed"

    def mark_reserved(
        self,
        correlation_id: str,
        updated_at: int,
        bridgefu_call_id: str,
        attachment_expires_at: int,
    ) -> None:
        try:
            self._client.update_item(
                TableName=self._table_name,
                Key={"correlation_id": {"S": correlation_id}},
                UpdateExpression=(
                    "SET #status = :reserved, updated_at = :updated, "
                    "bridgefu_call_id = :call, attachment_expires_at = :attachment_expiry"
                ),
                ConditionExpression="#status IN (:prepared, :reserved)",
                ExpressionAttributeNames={"#status": "handoff_status"},
                ExpressionAttributeValues={
                    ":prepared": {"S": "PREPARED"},
                    ":reserved": {"S": "RESERVED"},
                    ":updated": {"N": str(updated_at)},
                    ":call": {"S": bridgefu_call_id},
                    ":attachment_expiry": {"N": str(attachment_expires_at)},
                },
            )
        except Exception as error:
            if _conditional_failure(error):
                raise HandoffError("handoff_state_conflict", 409) from None
            raise

    def prepare_direct(
        self,
        session_id: str,
        token_id: str,
        identity,
        values: Mapping[str, str],
        updated_at: int,
    ) -> Mapping[str, str]:
        content_hash = hashlib.sha256(
            json.dumps(
                dict(values),
                separators=(",", ":"),
                sort_keys=True,
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        identity_hash = hashlib.sha256(
            f"direct-vapi|{identity.org_id}|{identity.call_id}".encode("ascii")
        ).hexdigest()
        try:
            response = self._client.update_item(
                TableName=self._table_name,
                Key={"correlation_id": {"S": session_id}},
                UpdateExpression=(
                    "SET #status = :prepared, updated_at = :updated, "
                    "screen_pop_values = :values, content_hash = :content, "
                    "vapi_call_fingerprint = :identity"
                ),
                ConditionExpression=(
                    "direct_token_id = :token AND expires_at > :updated AND "
                    "#status IN (:mapped, :prepared, :reserved) AND "
                    "(attribute_not_exists(content_hash) OR content_hash = :content) AND "
                    "(attribute_not_exists(vapi_call_fingerprint) OR "
                    "vapi_call_fingerprint = :identity)"
                ),
                ExpressionAttributeNames={"#status": "handoff_status"},
                ExpressionAttributeValues={
                    ":token": {"S": token_id},
                    ":updated": {"N": str(updated_at)},
                    ":mapped": {"S": "MAPPED"},
                    ":prepared": {"S": "PREPARED"},
                    ":reserved": {"S": "RESERVED"},
                    ":values": _encode_value(values),
                    ":content": {"S": content_hash},
                    ":identity": {"S": identity_hash},
                },
                ReturnValues="ALL_NEW",
            )
        except Exception as error:
            if _conditional_failure(error):
                raise HandoffError("direct_handoff_conflict", 409) from None
            raise
        attributes = response.get("Attributes")
        record = _decode_item(attributes) if isinstance(attributes, Mapping) else {}
        expected = {
            "call_id": record.get("bridgefu_call_id"),
            "leg_id": record.get("direct_leg_id"),
            "route_id": record.get("direct_route_id"),
            "idempotency_key": record.get("direct_idempotency_key"),
        }
        if any(
            not isinstance(value, str)
            or not value.replace("-", "").replace("_", "").isalnum()
            for value in expected.values()
        ):
            raise HandoffError("direct_handoff_binding_invalid", 500)
        return expected

    def mark_direct_started(self, session_id: str, updated_at: int) -> None:
        try:
            self._client.update_item(
                TableName=self._table_name,
                Key={"correlation_id": {"S": session_id}},
                UpdateExpression="SET #status = :reserved, updated_at = :updated",
                ConditionExpression="#status IN (:prepared, :reserved)",
                ExpressionAttributeNames={"#status": "handoff_status"},
                ExpressionAttributeValues={
                    ":prepared": {"S": "PREPARED"},
                    ":reserved": {"S": "RESERVED"},
                    ":updated": {"N": str(updated_at)},
                },
            )
        except Exception as error:
            if _conditional_failure(error):
                raise HandoffError("direct_handoff_conflict", 409) from None
            raise


class BridgefuRouteClient:
    def __init__(
        self,
        base_url: str,
        route_id: str,
        bearer_token: str,
        timeout_seconds: float = 8.0,
        private_http_hostname: str | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        secure_origin = parsed.scheme == "https" and parsed.port in {None, 443}
        private_test_origin = (
            parsed.scheme == "http"
            and private_http_hostname is not None
            and parsed.hostname == private_http_hostname
            and parsed.port == 443
            and re.fullmatch(
                r"control\.bft-[a-z0-9-]{4,20}\.bridgefu\.internal",
                private_http_hostname,
            )
            is not None
        )
        if (
            not (secure_origin or private_test_origin)
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise HandoffError("bridgefu_configuration_invalid", 500)
        if parsed.query or parsed.fragment:
            raise HandoffError("bridgefu_configuration_invalid", 500)
        if parsed.path not in ("", "/"):
            raise HandoffError("bridgefu_configuration_invalid", 500)
        if not route_id or not route_id.replace("-", "").replace("_", "").isalnum():
            raise HandoffError("bridgefu_configuration_invalid", 500)
        if len(bearer_token) < 32:
            raise HandoffError("bridgefu_configuration_invalid", 500)
        self._base_url = base_url.rstrip("/")
        self._route_id = route_id
        self._bearer_token = bearer_token
        self._timeout_seconds = timeout_seconds
        transport = (
            urllib.request.HTTPSHandler(context=ssl.create_default_context())
            if secure_origin
            else urllib.request.HTTPHandler()
        )
        self._opener = urllib.request.build_opener(_NoRedirect(), transport)

    def reserve(self, correlation_id: str, idempotency_key: str) -> SipReservation:
        url = (
            f"{self._base_url}/v1/routes/"
            f"{urllib.parse.quote(self._route_id, safe='')}/calls"
        )
        body = json.dumps(
            {
                "ingress": "sip",
                "context": {"correlation_id": correlation_id, "metadata": {}},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "authorization": f"Bearer {self._bearer_token}",
                "content-type": "application/json",
                "idempotency-key": idempotency_key,
                "user-agent": "bridgefu-recipe-handoff/1",
            },
        )
        try:
            with self._opener.open(
                request,
                timeout=self._timeout_seconds,
            ) as response:
                if response.status != 201:
                    raise HandoffError("bridgefu_reservation_failed", 502)
                raw = response.read(16_385)
        except HandoffError:
            raise
        except urllib.error.HTTPError as error:
            raise _bridgefu_http_error("reservation", error.code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise HandoffError("bridgefu_reservation_unavailable", 503) from None
        if len(raw) > 16_384:
            raise HandoffError("bridgefu_response_invalid", 502)
        try:
            payload = json.loads(raw)
            attachment = payload["attachment"]
            uri = attachment["uri"]
            expires_at_raw = attachment["expires_at"]
            call_id = payload["call_id"]
        except (KeyError, TypeError, json.JSONDecodeError):
            raise HandoffError("bridgefu_response_invalid", 502) from None
        if (
            not isinstance(uri, str)
            or not isinstance(call_id, str)
            or not isinstance(expires_at_raw, str)
        ):
            raise HandoffError("bridgefu_response_invalid", 502)
        try:
            from datetime import datetime

            expires_at = int(
                datetime.fromisoformat(
                    expires_at_raw.replace("Z", "+00:00")
                ).timestamp()
            )
        except ValueError:
            raise HandoffError("bridgefu_response_invalid", 502) from None
        return SipReservation(uri=uri, call_id=call_id, expires_at=expires_at)

    def replace(
        self,
        call_id: str,
        leg_id: str,
        route_id: str,
        idempotency_key: str,
    ) -> None:
        identifiers = (route_id, idempotency_key)
        if (
            any(
                not isinstance(value, str)
                or not value.replace("-", "").replace("_", "").isalnum()
                for value in identifiers
            )
            or not isinstance(call_id, str)
            or UUID.fullmatch(call_id) is None
            or not isinstance(leg_id, str)
            or UUID.fullmatch(leg_id) is None
            or route_id != self._route_id
        ):
            raise HandoffError("bridgefu_replacement_invalid", 500)
        url = (
            f"{self._base_url}/v1/calls/{urllib.parse.quote(call_id, safe='')}/"
            f"legs/{urllib.parse.quote(leg_id, safe='')}/replace"
        )
        request = urllib.request.Request(
            url,
            data=json.dumps({"route_id": route_id}, separators=(",", ":")).encode(
                "utf-8"
            ),
            method="POST",
            headers={
                "authorization": f"Bearer {self._bearer_token}",
                "content-type": "application/json",
                "idempotency-key": idempotency_key,
                "user-agent": "bridgefu-recipe-direct-handoff/1",
            },
        )
        for attempt in range(len(BRIDGEFU_CONFLICT_RETRY_DELAYS_SECONDS) + 1):
            try:
                with self._opener.open(
                    request, timeout=self._timeout_seconds
                ) as response:
                    if response.status != 202:
                        raise HandoffError("bridgefu_replacement_failed", 502)
                    raw = response.read(16_385)
                break
            except HandoffError:
                raise
            except urllib.error.HTTPError as error:
                upstream_code = _bridgefu_error_code(error)
                if (
                    error.code == 409
                    and upstream_code == "call_conflict"
                    and attempt < len(BRIDGEFU_CONFLICT_RETRY_DELAYS_SECONDS)
                ):
                    time.sleep(BRIDGEFU_CONFLICT_RETRY_DELAYS_SECONDS[attempt])
                    continue
                raise _bridgefu_http_error("replacement", error.code) from None
            except (urllib.error.URLError, TimeoutError, OSError):
                raise HandoffError("bridgefu_replacement_unavailable", 503) from None
        if len(raw) > 16_384:
            raise HandoffError("bridgefu_response_invalid", 502)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            raise HandoffError("bridgefu_response_invalid", 502) from None
        if not isinstance(payload, Mapping) or payload.get("call_id") != call_id:
            raise HandoffError("bridgefu_response_invalid", 502)
