"""Authenticated Vapi transfer-destination Lambda entrypoint."""

from __future__ import annotations

import json
import os
import time

from aws_runtime import (
    BridgefuRouteClient,
    DynamoHandoffStore,
    emit_operation,
    load_secret,
)
from bridgefu_handoff import (
    HandoffError,
    decode_http_json,
    direct_browser_handoff,
    error_response,
    http_response,
    transfer_destination,
    verify_bearer,
    verify_vapi_binding,
)
from screen_pop import parse_fields

_STORE = None
_BRIDGEFU = None
_DIRECT_BRIDGEFU = None


def _store():
    global _STORE
    if _STORE is None:
        _STORE = DynamoHandoffStore(os.environ["HANDOFF_TABLE_NAME"])
    return _STORE


def _bridgefu():
    global _BRIDGEFU
    if _BRIDGEFU is None:
        sip_security = os.environ.get("SIP_SECURITY", "sips_optional_srtp")
        deployment_id = os.environ["DEPLOYMENT_ID"]
        _BRIDGEFU = BridgefuRouteClient(
            os.environ["BRIDGEFU_CONTROL_BASE_URL"],
            os.environ["BRIDGEFU_ROUTE_ID"],
            load_secret(os.environ["BRIDGEFU_API_BEARER_SECRET_ARN"]),
            private_http_hostname=(
                f"control.{deployment_id}.bridgefu.internal"
                if sip_security == "sip_rtp"
                else None
            ),
        )
    return _BRIDGEFU


def _direct_bridgefu():
    global _DIRECT_BRIDGEFU
    if _DIRECT_BRIDGEFU is None:
        deployment_id = os.environ["DEPLOYMENT_ID"]
        _DIRECT_BRIDGEFU = BridgefuRouteClient(
            os.environ["BRIDGEFU_CONTROL_BASE_URL"],
            os.environ["DIRECT_HANDOFF_ROUTE_ID"],
            load_secret(os.environ["BRIDGEFU_API_BEARER_SECRET_ARN"]),
            private_http_hostname=(
                f"control.{deployment_id}.bridgefu.internal"
                if os.environ.get("SIP_SECURITY") == "sip_rtp"
                else None
            ),
        )
    return _DIRECT_BRIDGEFU


def lambda_handler(event, _context):
    started_at = time.monotonic()
    try:
        internal = event.get("bridgefuInternalReserveV1")
        route_key = event.get("routeKey")
        direct = route_key == "POST /v1/direct-handoff"
        if internal is not None and direct:
            raise HandoffError("invalid_http_request")
        if internal is not None:
            if not isinstance(internal, dict) or set(internal) != {"call"}:
                raise HandoffError("internal_reservation_invalid")
            payload = {
                "message": {
                    "type": "transfer-destination-request",
                    "call": internal["call"],
                }
            }
        else:
            payload, headers = decode_http_json(event)
            verify_bearer(
                headers,
                load_secret(os.environ["VAPI_WEBHOOK_SECRET_ARN"]),
            )
        identity_binding = json.loads(
            load_secret(os.environ["VAPI_IDENTITY_BINDING_ARN"])
        )
        verify_vapi_binding(
            payload,
            identity_binding,
        )
        if direct:
            response = direct_browser_handoff(
                payload,
                binding=identity_binding,
                signing_key=load_secret(
                    os.environ["DIRECT_HANDOFF_SIGNING_KEY_SECRET_ARN"]
                ).encode("utf-8"),
                store=_store(),
                configured_fields=parse_fields(
                    json.loads(os.environ["SCREEN_POP_FIELDS_JSON"])
                ),
                replace=_direct_bridgefu().replace,
            )
            result = "direct_started"
        else:
            response = transfer_destination(
                payload,
                _store(),
                load_secret(os.environ["CORRELATION_KEY_SECRET_ARN"]).encode("utf-8"),
                os.environ["DEPLOYMENT_ID"],
                _bridgefu().reserve,
                os.environ.get("SIP_SECURITY", "sips_optional_srtp"),
            )
            result = "reserved"
        output = response if internal is not None else http_response(200, response)
    except HandoffError as error:
        result = error.code
        output = error_response(error)
    except Exception:
        result = "internal_error"
        output = error_response(HandoffError("internal_error", 500))
    emit_operation(
        "direct_browser_handoff"
        if event.get("routeKey") == "POST /v1/direct-handoff"
        else "transfer_destination",
        result,
        started_at,
    )
    return output
