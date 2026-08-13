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
DIRECT_ASSISTANT_OWNER = "bridgefu-direct-web-qualification@1"
HANDOFF_ISSUER = "bridgefu-vapi-awsconnect-qualification"
HANDOFF_AUDIENCE = "bridgefu-direct-handoff"
IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
UUID = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
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
        or not UUID.fullmatch(call)
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
        and leg.get("kind") == "webrtc"
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
        isinstance(item, str) and UUID.fullmatch(item)
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
    credential_token = (
        credential.get("token") if isinstance(credential, Mapping) else None
    )
    protocols = value.get("subprotocols")
    if (
        set(value) != expected
        or value.get("type") != "webrtc"
        or not isinstance(token, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token)
        or not isinstance(credential, Mapping)
        or set(credential) != {"usage", "token", "expires_at"}
        or credential.get("usage") != "bridgefu-webrtc-signaling"
        or not isinstance(credential_token, str)
        or not re.fullmatch(r"bfs1\.[A-Za-z0-9_.-]{1,4091}", credential_token)
        or credential.get("expires_at") != value.get("expires_at")
        or protocols
        != [
            "rvoip.webrtc.v1",
            f"token.{credential_token}",
            f"bridgefu.attach.{token}",
        ]
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


def direct_assistant_payload(
    *, execution_id: str, tool_id: str, model_name: str, voice_id: str
) -> tuple[dict[str, Any], str]:
    """Build a disposable assistant with exactly one prompt and one tool surface."""
    if (
        not isinstance(execution_id, str)
        or not IDENTIFIER.fullmatch(execution_id)
        or not isinstance(tool_id, str)
        or not IDENTIFIER.fullmatch(tool_id)
        or not all(
            isinstance(value, str)
            and 1 <= len(value) <= 128
            and not re.search(r"[\x00-\x1f\x7f]", value)
            for value in (model_name, voice_id)
        )
    ):
        raise DirectHandoffContractError(
            "direct Vapi assistant configuration is invalid"
        )
    marker = f"[{DIRECT_PROMPT_MARKER}]"
    prompt = (
        f"{marker} This is a disposable Bridgefu release-qualification assistant. "
        "Collect only the fields declared by bridgefu_direct_handoff and call that "
        "tool exactly once when the caller asks for a human. The trusted static "
        "bridgefu_handoff_token is supplied by the tool configuration. Never ask "
        "for, repeat, invent, or modify the token, a route, a URI, a call ID, or a "
        "leg ID."
    )
    desired = {
        "name": f"BFQ direct {execution_id}",
        "firstMessageMode": "assistant-waits-for-user",
        "model": {
            "provider": "openai",
            "model": model_name,
            "temperature": 0,
            "messages": [{"role": "system", "content": prompt}],
            "toolIds": [tool_id],
        },
        "voice": {"provider": "vapi", "voiceId": voice_id},
        "transcriber": {
            "provider": "deepgram",
            "model": "nova-3",
            "language": "en",
        },
        "artifactPlan": {"recordingEnabled": False},
        "maxDurationSeconds": 300,
        "metadata": {
            "bridgefu_qualification": execution_id,
            "bridgefu_owner": DIRECT_ASSISTANT_OWNER,
        },
    }
    return desired, hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def direct_assistant_owned(
    value: Mapping[str, Any],
    *,
    execution_id: str,
    tool_id: str,
    prompt_sha256: str,
    model_name: str,
    voice_id: str,
) -> bool:
    """Prove the exact direct-only assistant surface before adoption or deletion."""
    if (
        not all(
            isinstance(item, str) and IDENTIFIER.fullmatch(item)
            for item in (execution_id, tool_id)
        )
        or not isinstance(prompt_sha256, str)
        or not SHA256.fullmatch(prompt_sha256)
    ):
        return False
    metadata = value.get("metadata")
    model = value.get("model")
    messages = model.get("messages") if isinstance(model, Mapping) else None
    prompt = (
        messages[0].get("content")
        if isinstance(messages, list)
        and len(messages) == 1
        and isinstance(messages[0], Mapping)
        else None
    )
    voice = value.get("voice")
    transcriber = value.get("transcriber")
    artifact_plan = value.get("artifactPlan")
    allowed_top_level = {
        "id",
        "orgId",
        "createdAt",
        "updatedAt",
        "name",
        "firstMessageMode",
        "model",
        "voice",
        "transcriber",
        "artifactPlan",
        "maxDurationSeconds",
        "metadata",
        "server",
        "serverUrl",
        "serverMessages",
        "hooks",
        "credentialIds",
    }
    allowed_model = {
        "provider",
        "model",
        "temperature",
        "messages",
        "toolIds",
        "tools",
        "knowledgeBase",
        "knowledgeBaseId",
    }
    allowed_voice = {"provider", "voiceId", "fallbackPlan"}
    allowed_transcriber = {"provider", "model", "language", "smartFormat"}
    allowed_artifact_plan = {"recordingEnabled", "loggingEnabled"}
    return (
        set(value) <= allowed_top_level
        and value.get("name") == f"BFQ direct {execution_id}"
        and value.get("firstMessageMode") == "assistant-waits-for-user"
        and isinstance(metadata, Mapping)
        and set(metadata) == {"bridgefu_qualification", "bridgefu_owner"}
        and metadata.get("bridgefu_qualification") == execution_id
        and metadata.get("bridgefu_owner") == DIRECT_ASSISTANT_OWNER
        and isinstance(model, Mapping)
        and set(model) <= allowed_model
        and model.get("provider") == "openai"
        and model.get("model") == model_name
        and model.get("temperature") == 0
        and model.get("toolIds") == [tool_id]
        and model.get("tools") in (None, [])
        and model.get("knowledgeBase") is None
        and model.get("knowledgeBaseId") is None
        and isinstance(prompt, str)
        and f"[{DIRECT_PROMPT_MARKER}]" in prompt
        and hashlib.sha256(prompt.encode("utf-8")).hexdigest() == prompt_sha256
        and value.get("server") is None
        and value.get("serverUrl") is None
        and value.get("serverMessages") in (None, [])
        and value.get("hooks") in (None, [])
        and value.get("credentialIds") in (None, [])
        and isinstance(voice, Mapping)
        and set(voice) <= allowed_voice
        and voice.get("provider") == "vapi"
        and voice.get("voiceId") == voice_id
        and voice.get("fallbackPlan") in (None, {}, [])
        and isinstance(transcriber, Mapping)
        and set(transcriber) <= allowed_transcriber
        and transcriber.get("provider") == "deepgram"
        and transcriber.get("model") == "nova-3"
        and transcriber.get("language") == "en"
        and transcriber.get("smartFormat") in (None, True)
        and isinstance(artifact_plan, Mapping)
        and set(artifact_plan) <= allowed_artifact_plan
        and artifact_plan.get("recordingEnabled") is False
        and artifact_plan.get("loggingEnabled") in (None, False)
        and value.get("maxDurationSeconds") == 300
    )
