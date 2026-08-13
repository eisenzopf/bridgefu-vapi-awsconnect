"""Pure contracts for the Bridgefu WebRTC → Vapi → Connect qualification path.

This module performs no network or filesystem I/O.  It keeps one-use browser
attachments and signed handoff authority out of argv, logs, and retained
evidence while giving the controller strict shapes to validate before it
mutates Vapi or asks Bridgefu to replace a leg.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

WEB_SCENARIO = "bridgefu-web-sdk-handoff"
DIRECT_TOOL_NAME = "bridgefu_direct_handoff"
DIRECT_PROMPT_MARKER = "bridgefu-direct-browser-handoff@1"
HANDOFF_ISSUER = "bridgefu-vapi-awsconnect-qualification"
HANDOFF_AUDIENCE = "bridgefu-direct-handoff"
IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
TOKEN = re.compile(r"^[A-Za-z0-9_.-]{1,4096}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DirectHandoffContractError(ValueError):
    """A closed direct-handoff boundary was violated."""


@dataclass(frozen=True)
class DirectRouteBinding:
    tenant_id: str
    call_id: str
    source_leg_id: str
    destination_leg_id: str
    route_attachment: Mapping[str, Any]

    def browser_input(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "route_attachment": dict(self.route_attachment),
            "route_binding": {
                "tenantId": self.tenant_id,
                "callId": self.call_id,
                "legId": self.source_leg_id,
            },
        }


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_b64url(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise DirectHandoffContractError("direct handoff token encoding is invalid")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise DirectHandoffContractError(
            "direct handoff token encoding is invalid"
        ) from error


def issue_handoff_token(
    signing_key: str,
    session_id: str,
    token_id: str,
    *,
    issued_at: int | None = None,
    lifetime_seconds: int = 3600,
) -> str:
    """Issue a bounded HS256 token containing no call, leg, route, or endpoint."""
    if not isinstance(signing_key, str) or not 32 <= len(signing_key) <= 4096:
        raise DirectHandoffContractError("direct handoff signing key is invalid")
    if not IDENTIFIER.fullmatch(session_id) or not IDENTIFIER.fullmatch(token_id):
        raise DirectHandoffContractError("direct handoff identity is invalid")
    if not 60 <= lifetime_seconds <= 7200:
        raise DirectHandoffContractError("direct handoff lifetime is invalid")
    now = int(time.time()) if issued_at is None else issued_at
    if now <= 0:
        raise DirectHandoffContractError("direct handoff issued-at is invalid")
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "aud": HANDOFF_AUDIENCE,
        "exp": now + lifetime_seconds,
        "iat": now,
        "iss": HANDOFF_ISSUER,
        "jti": token_id,
        "sub": session_id,
    }
    encoded_header = _b64url(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("ascii")
    )
    encoded_claims = _b64url(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("ascii")
    )
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    signature = _b64url(
        hmac.new(signing_key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    )
    result = f"{encoded_header}.{encoded_claims}.{signature}"
    if not TOKEN.fullmatch(result):
        raise DirectHandoffContractError("direct handoff token is invalid")
    return result


def verify_handoff_token(
    token: str,
    signing_key: str,
    *,
    now: int | None = None,
) -> tuple[str, str]:
    """Verify the exact qualification token and return only session/token IDs."""
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        raise DirectHandoffContractError("direct handoff token is invalid")
    if not isinstance(signing_key, str) or not 32 <= len(signing_key) <= 4096:
        raise DirectHandoffContractError("direct handoff signing key is invalid")
    parts = token.split(".")
    if len(parts) != 3:
        raise DirectHandoffContractError("direct handoff token is invalid")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    expected = hmac.new(
        signing_key.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected, _decode_b64url(parts[2])):
        raise DirectHandoffContractError("direct handoff token signature is invalid")
    try:
        header = json.loads(_decode_b64url(parts[0]))
        claims = json.loads(_decode_b64url(parts[1]))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DirectHandoffContractError("direct handoff token is invalid") from error
    if header != {"alg": "HS256", "typ": "JWT"} or set(claims) != {
        "aud",
        "exp",
        "iat",
        "iss",
        "jti",
        "sub",
    }:
        raise DirectHandoffContractError("direct handoff claims are invalid")
    current = int(time.time()) if now is None else now
    if (
        claims.get("iss") != HANDOFF_ISSUER
        or claims.get("aud") != HANDOFF_AUDIENCE
        or not isinstance(claims.get("iat"), int)
        or not isinstance(claims.get("exp"), int)
        or claims["iat"] > current + 5
        or claims["exp"] < current - 5
        or claims["exp"] <= claims["iat"]
        or claims["exp"] - claims["iat"] > 7200
        or not isinstance(claims.get("sub"), str)
        or not IDENTIFIER.fullmatch(claims["sub"])
        or not isinstance(claims.get("jti"), str)
        or not IDENTIFIER.fullmatch(claims["jti"])
    ):
        raise DirectHandoffContractError("direct handoff claims are invalid")
    return claims["sub"], claims["jti"]


def route_request(correlation_id: str, handoff_token: str) -> dict[str, Any]:
    if not re.fullmatch(r"bf1_[A-Za-z0-9_-]{43}", correlation_id):
        raise DirectHandoffContractError("direct route correlation is invalid")
    if not TOKEN.fullmatch(handoff_token):
        raise DirectHandoffContractError("direct route handoff token is invalid")
    return {
        "ingress": "webrtc",
        "context": {
            "correlation_id": correlation_id,
            "metadata": {"handoff_token": handoff_token},
        },
    }


def parse_route_response(value: Any, expected_route_id: str) -> DirectRouteBinding:
    """Bind one exact inbound WebRTC leg and one replaceable outbound SIP leg."""
    if not isinstance(value, Mapping) or not IDENTIFIER.fullmatch(expected_route_id):
        raise DirectHandoffContractError("direct route response is invalid")
    if value.get("route_id") != expected_route_id:
        raise DirectHandoffContractError("direct route identity changed")
    tenant = value.get("tenant_id")
    call = value.get("call_id")
    legs = value.get("legs")
    attachment = value.get("attachment")
    if (
        not isinstance(tenant, str)
        or not IDENTIFIER.fullmatch(tenant)
        or not isinstance(call, str)
        or not IDENTIFIER.fullmatch(call)
        or not isinstance(legs, list)
        or len(legs) != 2
        or not isinstance(attachment, Mapping)
    ):
        raise DirectHandoffContractError("direct route response is invalid")
    inbound = [
        leg
        for leg in legs
        if isinstance(leg, Mapping)
        and leg.get("direction") == "inbound"
        and leg.get("kind") == "web_rtc"
    ]
    outbound = [
        leg
        for leg in legs
        if isinstance(leg, Mapping)
        and leg.get("direction") == "outbound"
        and leg.get("kind") == "sip"
    ]
    if len(inbound) != 1 or len(outbound) != 1:
        raise DirectHandoffContractError("direct route legs are ambiguous")
    source_leg = inbound[0].get("leg_id")
    destination_leg = outbound[0].get("leg_id")
    if not all(
        isinstance(item, str) and IDENTIFIER.fullmatch(item)
        for item in (source_leg, destination_leg)
    ):
        raise DirectHandoffContractError("direct route leg identity is invalid")
    _validate_attachment(attachment)
    return DirectRouteBinding(
        tenant_id=tenant,
        call_id=call,
        source_leg_id=source_leg,
        destination_leg_id=destination_leg,
        route_attachment=dict(attachment),
    )


def _validate_attachment(value: Mapping[str, Any]) -> None:
    expected = {
        "type",
        "signaling_uri",
        "token",
        "signaling_credential",
        "subprotocols",
        "ice_servers",
        "expires_at",
    }
    token = value.get("token")
    credential = value.get("signaling_credential")
    protocols = value.get("subprotocols")
    if (
        set(value) != expected
        or value.get("type") != "webrtc"
        or not isinstance(token, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
        or not isinstance(credential, Mapping)
        or set(credential) != {"usage", "token", "expires_at"}
        or credential.get("usage") != "bridgefu-webrtc-signaling"
        or credential.get("token") != token
        or credential.get("expires_at") != value.get("expires_at")
        or protocols
        != ["rvoip.webrtc.v1", f"token.{token}", f"bridgefu.attach.{token}"]
        or not isinstance(value.get("ice_servers"), list)
    ):
        raise DirectHandoffContractError("direct route attachment is invalid")
    parsed = urlsplit(str(value.get("signaling_uri", "")))
    if (
        parsed.scheme != "wss"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise DirectHandoffContractError("direct route signaling URI is invalid")
    try:
        expires = datetime.fromisoformat(
            str(value.get("expires_at")).replace("Z", "+00:00")
        ).timestamp()
    except ValueError as error:
        raise DirectHandoffContractError("direct route expiry is invalid") from error
    if expires <= 0:
        raise DirectHandoffContractError("direct route expiry is invalid")


def direct_tool_payload(
    *,
    endpoint_url: str,
    credential_id: str,
    field_schema: Mapping[str, Any],
    execution_id: str,
) -> dict[str, Any]:
    parsed = urlsplit(endpoint_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not IDENTIFIER.fullmatch(credential_id)
        or not isinstance(field_schema, Mapping)
        or field_schema.get("type") != "object"
        or field_schema.get("additionalProperties") is not False
        or not IDENTIFIER.fullmatch(execution_id)
    ):
        raise DirectHandoffContractError("direct Vapi tool configuration is invalid")
    parameters = json.loads(json.dumps(field_schema))
    properties = parameters.get("properties")
    if not isinstance(properties, dict) or "handoff_token" in properties:
        raise DirectHandoffContractError("direct Vapi field schema is invalid")
    return {
        "type": "function",
        "function": {
            "name": DIRECT_TOOL_NAME,
            "description": (
                "Store the configured screen-pop context and securely replace "
                "this Bridgefu assistant leg with Amazon Connect."
            ),
            "parameters": parameters,
        },
        "server": {
            "url": endpoint_url,
            "credentialId": credential_id,
            "timeoutSeconds": 10,
        },
        "parameters": [
            {
                "key": "handoff_token",
                "value": "{{ bridgefu_handoff_token }}",
            }
        ],
    }


def direct_tool_owned(
    value: Mapping[str, Any],
    *,
    execution_id: str,
    endpoint_url: str,
    credential_id: str,
) -> bool:
    """Bind ownership to the unique stack URL and exact webhook credential."""
    function = value.get("function")
    server = value.get("server")
    return (
        IDENTIFIER.fullmatch(execution_id) is not None
        and IDENTIFIER.fullmatch(credential_id) is not None
        and value.get("type") == "function"
        and isinstance(function, Mapping)
        and function.get("name") == DIRECT_TOOL_NAME
        and isinstance(server, Mapping)
        and server.get("url") == endpoint_url
        and server.get("credentialId") == credential_id
    )


def apply_assistant_overlay(
    assistant: Mapping[str, Any], tool_id: str
) -> tuple[dict[str, Any], str]:
    """Add one owned tool and prompt while preserving the complete assistant."""
    if not IDENTIFIER.fullmatch(tool_id):
        raise DirectHandoffContractError("direct Vapi tool identity is invalid")
    desired = json.loads(json.dumps(assistant))
    model = desired.get("model")
    if not isinstance(model, dict):
        raise DirectHandoffContractError("Vapi assistant model is invalid")
    tool_ids = model.setdefault("toolIds", [])
    messages = model.setdefault("messages", [])
    if not isinstance(tool_ids, list) or not isinstance(messages, list):
        raise DirectHandoffContractError("Vapi assistant overlay target is invalid")
    marker = f"[{DIRECT_PROMPT_MARKER}]"
    if tool_id in tool_ids or any(
        isinstance(message, Mapping)
        and isinstance(message.get("content"), str)
        and marker in message["content"]
        for message in messages
    ):
        raise DirectHandoffContractError("direct Vapi assistant overlay already exists")
    tool_ids.append(tool_id)
    prompt = (
        f"{marker} When this SIP call includes the trusted static "
        "bridgefu_handoff_token tool parameter, collect only the fields declared "
        "by bridgefu_direct_handoff and call that tool exactly once when the caller "
        "asks for a human. Do not call prepare_handoff or transferCall in this "
        "direct-browser mode. The model must never request, repeat, invent, or "
        "modify the token, a route, a URI, a call ID, or a leg ID."
    )
    messages.append({"role": "system", "content": prompt})
    return desired, hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def remove_assistant_overlay(
    assistant: Mapping[str, Any], tool_id: str, prompt_sha256: str
) -> dict[str, Any]:
    """Remove only the exact owned tool and exact marked prompt."""
    if not IDENTIFIER.fullmatch(tool_id) or not SHA256.fullmatch(prompt_sha256):
        raise DirectHandoffContractError("direct Vapi overlay ownership is invalid")
    desired = json.loads(json.dumps(assistant))
    model = desired.get("model")
    if not isinstance(model, dict):
        raise DirectHandoffContractError("Vapi assistant model is invalid")
    tool_ids = model.get("toolIds")
    messages = model.get("messages")
    if not isinstance(tool_ids, list) or tool_ids.count(tool_id) != 1:
        raise DirectHandoffContractError("direct Vapi tool ownership is ambiguous")
    owned = [
        message
        for message in messages or []
        if isinstance(message, Mapping)
        and isinstance(message.get("content"), str)
        and f"[{DIRECT_PROMPT_MARKER}]" in message["content"]
    ]
    if (
        not isinstance(messages, list)
        or len(owned) != 1
        or hashlib.sha256(owned[0]["content"].encode("utf-8")).hexdigest()
        != prompt_sha256
    ):
        raise DirectHandoffContractError("direct Vapi prompt ownership is ambiguous")
    model["toolIds"] = [value for value in tool_ids if value != tool_id]
    model["messages"] = [message for message in messages if message is not owned[0]]
    return desired
