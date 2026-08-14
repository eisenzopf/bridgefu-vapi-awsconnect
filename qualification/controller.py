#!/usr/bin/env python3
"""Fail-closed live qualification for the published Bridgefu AWS release.

The controller creates one disposable Amazon Connect environment, exercises the
two release smoke paths, writes only redacted evidence, and then proves that all
test-owned AWS and Vapi resources are absent. Secrets and raw remote responses
remain in memory and are never included in retained output.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import jsonschema

try:
    import direct_secure_preflight
except ModuleNotFoundError:  # Imported as a repository module by unit tests.
    from qualification import direct_secure_preflight

try:
    import bridgefu_web_handoff
    import bridgefu_web_runtime
except ModuleNotFoundError:  # Imported as a repository module by unit tests.
    from qualification import bridgefu_web_handoff, bridgefu_web_runtime

ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "qualification"
LAMBDA_COMMON = ROOT / "lambda" / "common"
if os.fspath(LAMBDA_COMMON) not in sys.path:
    sys.path.insert(0, os.fspath(LAMBDA_COMMON))

from vapi_provisioning import (  # noqa: E402
    ProvisioningConfig,
    VapiHttpClient,
    VapiProvisioningError,
    provision_create,
    provision_delete,
)
from vapi_provisioning import (
    VapiAmbiguousWriteError as ProvisioningAmbiguousWriteError,
)


class LostAssistantCreateResponseClient:
    """Commit one assistant POST, then simulate its lost HTTP response once."""

    def __init__(self, delegate: VapiHttpClient) -> None:
        self.delegate = delegate
        self.injected = False

    def list(self, resource: str) -> list[Mapping[str, Any]]:
        return self.delegate.list(resource)

    def get(self, resource: str, resource_id: str) -> Mapping[str, Any] | None:
        return self.delegate.get(resource, resource_id)

    def create(self, resource: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        result = self.delegate.create(resource, payload)
        if resource == "assistant" and not self.injected:
            self.injected = True
            raise ProvisioningAmbiguousWriteError("POST", "assistant", None)
        return result

    def update(
        self, resource: str, resource_id: str, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        return self.delegate.update(resource, resource_id, payload)

    def delete(self, resource: str, resource_id: str) -> None:
        self.delegate.delete(resource, resource_id)


PRODUCER = "bridgefu-vapi-awsconnect-qualification@1"
RECIPE = "vapi-amazon-connect-screen-pop@1"
VAPI_BASE_URL = "https://api.vapi.ai"
REGIONS = {"us-west-2", "us-east-1"}
EXECUTION_ID = re.compile(r"^bfq-[a-z0-9-]{4,20}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")
RESOURCE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
S3_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
WEB_SCENARIO = "bridgefu-web-sdk-handoff"
SCENARIOS = (WEB_SCENARIO, "vapi-sip-transfer")
CONTEXT = {
    "customer_name": "Bridgefu Synthetic Caller",
    "intent": "qualification",
    "verification_status": "synthetic",
}
SCREEN_POP_KEYS = (
    "customer_name",
    "issue_summary",
    "intent",
    "verification_status",
)
DIAGNOSTIC_LIMIT = 2048
PHONE_OWNERSHIP_PRODUCER = "bridgefu-vapi-phone-ownership@1"
PHONE_INTENT_PRODUCER = "bridgefu-vapi-phone-intent@1"
PHONE_REQUEST_PRODUCER = "bridgefu-vapi-phone-request@1"
DIRECT_TOOL_INTENT_PRODUCER = "bridgefu-vapi-direct-tool-intent@1"
DIRECT_TOOL_REQUEST_PRODUCER = "bridgefu-vapi-direct-tool-request@1"
DIRECT_TOOL_OWNERSHIP_PRODUCER = "bridgefu-vapi-direct-tool-ownership@1"
DIRECT_ASSISTANT_INTENT_PRODUCER = "bridgefu-vapi-direct-assistant-intent@1"
DIRECT_ASSISTANT_REQUEST_PRODUCER = "bridgefu-vapi-direct-assistant-request@1"
DIRECT_ASSISTANT_OWNERSHIP_PRODUCER = "bridgefu-vapi-direct-assistant-ownership@1"
AGENT_OBSERVER_PRODUCER = "bridgefu-agent-workspace-playwright@1"
MAX_OBJECT_VERSION_PAGES = 100
MAX_OBJECT_VERSIONS = 10_000
MAX_DELETE_OBJECTS = 1_000
BROWSER_READINESS_TIMEOUT_SECONDS = 210
VAPI_DESTINATION_SECURITY_EVENT = "bridgefu_vapi_destination_security_evidence"
VAPI_SOURCE_SECURITY_EVENT = "bridgefu_vapi_source_security_evidence"
VAPI_DESTINATION_SECURITY_FIELDS = {
    "event",
    "correlation_fingerprint",
    "leg",
    "uri_scheme",
    "signaling_transport",
    "media_profile",
    "media_keying",
    "media_suite",
    "inbound_srtp_context_installed",
    "outbound_srtp_context_installed",
    "answered",
    "redacted",
}
VAPI_DESTINATION_SECURITY_EXPECTED = {
    "event": VAPI_DESTINATION_SECURITY_EVENT,
    "leg": "vapi-to-bridgefu",
    "signaling_transport": "tls",
    "answered": True,
    "redacted": True,
}
VAPI_DESTINATION_MEDIA_SUITES = {
    "AES_CM_128_HMAC_SHA1_80",
    "AES_CM_128_HMAC_SHA1_32",
}
VAPI_DESTINATION_MEDIA_PROFILES = {"RTP/AVP", "RTP/SAVP"}
DEMO_SITE_FILES = {
    "index.html",
    "style.css",
    "app.js",
    "app.js.LEGAL.txt",
    "third-party-licenses.json",
}
MAX_DEMO_SITE_FILE_BYTES = 16 * 1024 * 1024
MAX_DEMO_SITE_BYTES = 32 * 1024 * 1024
ACM_OWNERSHIP_PRODUCER = "bridgefu-acm-validation-ownership@1"
MAX_NESTED_STACKS = 16
MAX_ACM_VALIDATION_RECORDS = 8


class QualificationError(RuntimeError):
    """Expected qualification failure with a non-sensitive message."""


class VapiAmbiguousWriteError(QualificationError):
    """A Vapi write may have completed even though its response was lost."""


class VapiPhoneReconciliationError(QualificationError):
    """A transient Vapi endpoint may exist but cannot yet be identified safely."""


def utc_now() -> str:
    return (
        dt.datetime.now(dt.UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Mapping[str, Any]) -> str:
    return sha256_bytes(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )


def desired_payload_present(actual: Any, desired: Any) -> bool:
    if isinstance(desired, Mapping):
        return isinstance(actual, Mapping) and all(
            key in actual and desired_payload_present(actual[key], value)
            for key, value in desired.items()
        )
    if isinstance(desired, list):
        return isinstance(actual, list) and actual == desired
    return actual == desired


def direct_tool_surface_matches(
    actual: Mapping[str, Any], desired: Mapping[str, Any]
) -> bool:
    """Compare every customer-controlled tool field while ignoring API metadata."""
    allowed = {
        "id",
        "orgId",
        "createdAt",
        "updatedAt",
        "latestVersion",
        "type",
        "function",
        "server",
        "parameters",
    }
    org_id = actual.get("orgId")
    latest_version = actual.get("latestVersion")
    timestamps = (actual.get("createdAt"), actual.get("updatedAt"))
    return (
        set(desired) == {"type", "function", "server", "parameters"}
        and set(actual) <= allowed
        and (
            org_id in (None, "")
            or (isinstance(org_id, str) and RESOURCE_ID.fullmatch(org_id) is not None)
        )
        and (
            latest_version in (None, "")
            or (
                isinstance(latest_version, str)
                and RESOURCE_ID.fullmatch(latest_version) is not None
            )
        )
        and all(value is None or isinstance(value, str) for value in timestamps)
        and all(actual.get(key) == value for key, value in desired.items())
    )


def vapi_phone_owned_name(execution_id: str) -> str:
    if not EXECUTION_ID.fullmatch(execution_id):
        raise QualificationError("execution ID is invalid")
    name = f"BFQ {execution_id} SIP smoke"
    if len(name) > 40:
        raise QualificationError("temporary Vapi endpoint name is invalid")
    return name


def vapi_phone_intent(
    execution_id: str,
    assistant_id: str,
    authentication: Mapping[str, str],
) -> dict[str, str]:
    """Build the non-secret identity used to reconcile one transient endpoint."""
    if set(authentication) != {"realm", "username", "password"}:
        raise QualificationError("Vapi SIP authentication has an invalid shape")
    username = authentication["username"]
    password = authentication["password"]
    if (
        not RESOURCE_ID.fullmatch(assistant_id)
        or authentication["realm"] != "sip.vapi.ai"
        or re.fullmatch(r"bfq_[a-f0-9]{16}", username) is None
        or not 16 <= len(password) <= 40
        or re.search(r"[\x00-\x20\x7f]", password)
    ):
        raise QualificationError("Vapi SIP authentication is invalid")
    return {
        "name": vapi_phone_owned_name(execution_id),
        "assistant_id": assistant_id,
        "sip_uri": f"sip:{username}@sip.vapi.ai",
        "authentication_realm": authentication["realm"],
        "authentication_username": username,
    }


def vapi_phone_matches_intent(
    phone: Mapping[str, Any], intent: Mapping[str, str]
) -> bool:
    """Match every stable identity field Vapi returns without retaining secrets."""
    phone_id = phone.get("id")
    if (
        not isinstance(phone_id, str)
        or not RESOURCE_ID.fullmatch(phone_id)
        or phone.get("provider") != "vapi"
        or phone.get("name") != intent.get("name")
        or phone.get("assistantId") != intent.get("assistant_id")
        or phone.get("sipUri") != intent.get("sip_uri")
    ):
        return False
    remote_authentication = phone.get("authentication")
    if remote_authentication is None:
        return True
    if not isinstance(remote_authentication, Mapping):
        return False
    expected_authentication = {
        "realm": intent.get("authentication_realm"),
        "username": intent.get("authentication_username"),
    }
    return all(
        key not in remote_authentication
        or remote_authentication.get(key) == expected_value
        for key, expected_value in expected_authentication.items()
    )


def vapi_phone_intent_journal(
    execution_id: str,
    region: str,
    intent: Mapping[str, str],
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    owned = {
        "execution_id": execution_id,
        "region": region,
        "resource_type": "phone-number",
        "owned_name": intent.get("name"),
        "assistant_id": intent.get("assistant_id"),
        "sip_uri": intent.get("sip_uri"),
        "authentication_realm": intent.get("authentication_realm"),
        "authentication_username": intent.get("authentication_username"),
    }
    value: dict[str, Any] = {
        "schema_version": 1,
        "producer": PHONE_INTENT_PRODUCER,
        **owned,
        "intent_sha256": canonical_sha256(owned),
        "created_at": created_at or utc_now(),
        "redacted": True,
    }
    return dict(validate_vapi_phone_intent_journal(value))


def validate_vapi_phone_intent_journal(value: Any) -> Mapping[str, Any]:
    keys = {
        "schema_version",
        "producer",
        "execution_id",
        "region",
        "resource_type",
        "owned_name",
        "assistant_id",
        "sip_uri",
        "authentication_realm",
        "authentication_username",
        "intent_sha256",
        "created_at",
        "redacted",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise QualificationError("temporary Vapi endpoint intent shape is invalid")
    execution_id = value.get("execution_id")
    region = value.get("region")
    assistant_id = value.get("assistant_id")
    username = value.get("authentication_username")
    if (
        value.get("schema_version") != 1
        or value.get("producer") != PHONE_INTENT_PRODUCER
        or value.get("resource_type") != "phone-number"
        or value.get("redacted") is not True
        or not isinstance(execution_id, str)
        or not EXECUTION_ID.fullmatch(execution_id)
        or region not in REGIONS
        or value.get("owned_name") != vapi_phone_owned_name(execution_id)
        or not isinstance(assistant_id, str)
        or not RESOURCE_ID.fullmatch(assistant_id)
        or value.get("authentication_realm") != "sip.vapi.ai"
        or not isinstance(username, str)
        or re.fullmatch(r"bfq_[a-f0-9]{16}", username) is None
        or value.get("sip_uri") != f"sip:{username}@sip.vapi.ai"
        or not isinstance(value.get("created_at"), str)
        or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", value["created_at"]
        )
    ):
        raise QualificationError("temporary Vapi endpoint intent is invalid")
    owned = {
        "execution_id": execution_id,
        "region": region,
        "resource_type": "phone-number",
        "owned_name": value["owned_name"],
        "assistant_id": assistant_id,
        "sip_uri": value["sip_uri"],
        "authentication_realm": value["authentication_realm"],
        "authentication_username": username,
    }
    if value.get("intent_sha256") != canonical_sha256(owned):
        raise QualificationError("temporary Vapi endpoint intent hash is invalid")
    return value


def vapi_phone_ownership_journal(
    execution_id: str,
    region: str,
    phone_id: str,
    assistant_id: str,
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    if (
        not EXECUTION_ID.fullmatch(execution_id)
        or region not in REGIONS
        or not RESOURCE_ID.fullmatch(phone_id)
        or not RESOURCE_ID.fullmatch(assistant_id)
    ):
        raise QualificationError("temporary Vapi endpoint ownership is invalid")
    owned = {
        "execution_id": execution_id,
        "region": region,
        "resource_type": "phone-number",
        "phone_id": phone_id,
        "assistant_id": assistant_id,
        "owned_name": vapi_phone_owned_name(execution_id),
    }
    value: dict[str, Any] = {
        "schema_version": 1,
        "producer": PHONE_OWNERSHIP_PRODUCER,
        **owned,
        "ownership_sha256": canonical_sha256(owned),
        "created_at": created_at or utc_now(),
        "redacted": True,
    }
    return dict(validate_vapi_phone_ownership_journal(value))


def vapi_phone_request_journal(
    intent: Mapping[str, Any],
    request_nonce: str,
    *,
    authorized_at: str | None = None,
) -> dict[str, Any]:
    """Seal authorization for one exact temporary-phone create request."""
    validate_vapi_phone_intent_journal(intent)
    if re.fullmatch(r"[0-9a-f]{32}", request_nonce) is None:
        raise QualificationError("temporary Vapi endpoint request is invalid")
    owned = {
        "execution_id": intent["execution_id"],
        "region": intent["region"],
        "resource_type": "phone-number",
        "intent_sha256": intent["intent_sha256"],
        "request_nonce": request_nonce,
        "attempt_state": "authorized",
    }
    return {
        "schema_version": 1,
        "producer": PHONE_REQUEST_PRODUCER,
        **owned,
        "request_sha256": canonical_sha256(owned),
        "authorized_at": authorized_at or utc_now(),
        "redacted": True,
    }


def validate_vapi_phone_ownership_journal(value: Any) -> Mapping[str, Any]:
    keys = {
        "schema_version",
        "producer",
        "execution_id",
        "region",
        "resource_type",
        "phone_id",
        "assistant_id",
        "owned_name",
        "ownership_sha256",
        "created_at",
        "redacted",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise QualificationError("temporary Vapi endpoint journal shape is invalid")
    execution_id = value.get("execution_id")
    region = value.get("region")
    phone_id = value.get("phone_id")
    assistant_id = value.get("assistant_id")
    if (
        value.get("schema_version") != 1
        or value.get("producer") != PHONE_OWNERSHIP_PRODUCER
        or value.get("resource_type") != "phone-number"
        or value.get("redacted") is not True
        or not isinstance(execution_id, str)
        or not EXECUTION_ID.fullmatch(execution_id)
        or region not in REGIONS
        or not isinstance(phone_id, str)
        or not RESOURCE_ID.fullmatch(phone_id)
        or not isinstance(assistant_id, str)
        or not RESOURCE_ID.fullmatch(assistant_id)
        or value.get("owned_name") != vapi_phone_owned_name(execution_id)
        or not isinstance(value.get("created_at"), str)
        or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", value["created_at"]
        )
    ):
        raise QualificationError("temporary Vapi endpoint journal is invalid")
    owned = {
        "execution_id": execution_id,
        "region": region,
        "resource_type": "phone-number",
        "phone_id": phone_id,
        "assistant_id": assistant_id,
        "owned_name": value["owned_name"],
    }
    if value.get("ownership_sha256") != canonical_sha256(owned):
        raise QualificationError("temporary Vapi endpoint journal hash is invalid")
    return value


def direct_tool_intent_journal(
    execution_id: str,
    region: str,
    endpoint_url: str,
    credential_id: str,
    desired: Mapping[str, Any],
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    if (
        not EXECUTION_ID.fullmatch(execution_id)
        or region not in REGIONS
        or not RESOURCE_ID.fullmatch(credential_id)
        or not bridgefu_web_handoff.direct_tool_owned(
            desired,
            execution_id=execution_id,
            endpoint_url=endpoint_url,
            credential_id=credential_id,
        )
    ):
        raise QualificationError("direct Vapi tool intent is invalid")
    desired_copy = json.loads(json.dumps(desired))
    desired_sha256 = canonical_sha256(desired_copy)
    owned = {
        "execution_id": execution_id,
        "region": region,
        "resource_type": "tool",
        "endpoint_url": endpoint_url,
        "credential_id": credential_id,
        "desired_sha256": desired_sha256,
    }
    return {
        "schema_version": 1,
        "producer": DIRECT_TOOL_INTENT_PRODUCER,
        **owned,
        "desired": desired_copy,
        "intent_sha256": canonical_sha256(owned),
        "created_at": created_at or utc_now(),
        "redacted": True,
    }


def direct_tool_ownership_journal(
    intent: Mapping[str, Any],
    tool_id: str,
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    if (
        intent.get("producer") != DIRECT_TOOL_INTENT_PRODUCER
        or not isinstance(tool_id, str)
        or not RESOURCE_ID.fullmatch(tool_id)
    ):
        raise QualificationError("direct Vapi tool ownership is invalid")
    owned = {
        "execution_id": intent["execution_id"],
        "region": intent["region"],
        "resource_type": "tool",
        "tool_id": tool_id,
        "endpoint_url": intent["endpoint_url"],
        "credential_id": intent["credential_id"],
        "desired_sha256": intent["desired_sha256"],
        "intent_sha256": intent["intent_sha256"],
    }
    return {
        "schema_version": 1,
        "producer": DIRECT_TOOL_OWNERSHIP_PRODUCER,
        **owned,
        "ownership_sha256": canonical_sha256(owned),
        "created_at": created_at or utc_now(),
        "redacted": True,
    }


def direct_vapi_request_journal(
    intent: Mapping[str, Any],
    request_nonce: str,
    *,
    authorized_at: str | None = None,
) -> dict[str, Any]:
    """Seal that one exact Vapi POST was authorized after its durable intent."""
    resource_type = intent.get("resource_type")
    producer = {
        "tool": DIRECT_TOOL_REQUEST_PRODUCER,
        "assistant": DIRECT_ASSISTANT_REQUEST_PRODUCER,
    }.get(resource_type)
    expected_intent_producer = {
        "tool": DIRECT_TOOL_INTENT_PRODUCER,
        "assistant": DIRECT_ASSISTANT_INTENT_PRODUCER,
    }.get(resource_type)
    if (
        producer is None
        or intent.get("producer") != expected_intent_producer
        or not isinstance(intent.get("execution_id"), str)
        or not EXECUTION_ID.fullmatch(intent["execution_id"])
        or intent.get("region") not in REGIONS
        or not isinstance(intent.get("intent_sha256"), str)
        or not SHA256.fullmatch(intent["intent_sha256"])
        or not isinstance(request_nonce, str)
        or re.fullmatch(r"[0-9a-f]{32}", request_nonce) is None
    ):
        raise QualificationError("direct Vapi request authorization is invalid")
    owned = {
        "execution_id": intent["execution_id"],
        "region": intent["region"],
        "resource_type": resource_type,
        "intent_sha256": intent["intent_sha256"],
        "request_nonce": request_nonce,
        "attempt_state": "authorized",
    }
    return {
        "schema_version": 1,
        "producer": producer,
        **owned,
        "request_sha256": canonical_sha256(owned),
        "authorized_at": authorized_at or utc_now(),
        "redacted": True,
    }


def direct_assistant_intent_journal(
    execution_id: str,
    region: str,
    organization_id: str,
    tool_id: str,
    model_name: str,
    voice_id: str,
    prompt_sha256: str,
    desired: Mapping[str, Any],
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    if (
        not EXECUTION_ID.fullmatch(execution_id)
        or region not in REGIONS
        or not RESOURCE_ID.fullmatch(organization_id)
        or not RESOURCE_ID.fullmatch(tool_id)
        or not SHA256.fullmatch(prompt_sha256)
        or not bridgefu_web_handoff.direct_assistant_owned(
            desired,
            execution_id=execution_id,
            tool_id=tool_id,
            prompt_sha256=prompt_sha256,
            model_name=model_name,
            voice_id=voice_id,
        )
    ):
        raise QualificationError("direct Vapi assistant intent is invalid")
    desired_copy = json.loads(json.dumps(desired))
    desired_sha256 = canonical_sha256(desired_copy)
    owned = {
        "execution_id": execution_id,
        "region": region,
        "resource_type": "assistant",
        "owned_name": f"BFQ direct {execution_id}",
        "owner_marker": bridgefu_web_handoff.DIRECT_ASSISTANT_OWNER,
        "tool_id": tool_id,
        "organization_id": organization_id,
        "model_name": model_name,
        "voice_id": voice_id,
        "prompt_sha256": prompt_sha256,
        "desired_sha256": desired_sha256,
    }
    return {
        "schema_version": 1,
        "producer": DIRECT_ASSISTANT_INTENT_PRODUCER,
        **owned,
        "desired": desired_copy,
        "intent_sha256": canonical_sha256(owned),
        "created_at": created_at or utc_now(),
        "redacted": True,
    }


def direct_assistant_ownership_journal(
    intent: Mapping[str, Any],
    assistant_id: str,
    *,
    created_at: str | None = None,
) -> dict[str, Any]:
    if (
        intent.get("producer") != DIRECT_ASSISTANT_INTENT_PRODUCER
        or not isinstance(assistant_id, str)
        or not RESOURCE_ID.fullmatch(assistant_id)
    ):
        raise QualificationError("direct Vapi assistant ownership is invalid")
    owned = {
        "execution_id": intent["execution_id"],
        "region": intent["region"],
        "resource_type": "assistant",
        "assistant_id": assistant_id,
        "owned_name": intent["owned_name"],
        "owner_marker": intent["owner_marker"],
        "tool_id": intent["tool_id"],
        "organization_id": intent["organization_id"],
        "model_name": intent["model_name"],
        "voice_id": intent["voice_id"],
        "prompt_sha256": intent["prompt_sha256"],
        "desired_sha256": intent["desired_sha256"],
        "intent_sha256": intent["intent_sha256"],
    }
    return {
        "schema_version": 1,
        "producer": DIRECT_ASSISTANT_OWNERSHIP_PRODUCER,
        **owned,
        "ownership_sha256": canonical_sha256(owned),
        "created_at": created_at or utc_now(),
        "redacted": True,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def executable_sha256(path: Path) -> str:
    try:
        details = path.lstat()
    except OSError as error:
        raise QualificationError("direct secure probe binary is unavailable") from error
    if not stat.S_ISREG(details.st_mode) or not os.access(path, os.X_OK):
        raise QualificationError(
            "direct secure probe must be an executable regular non-symlink file"
        )
    return sha256_file(path)


def prepare_demo_site_archive(
    archive: Path, expected_sha256: str, destination: Path
) -> tuple[Path, str]:
    """Validate and privately extract the immutable qualification Web bundle."""
    if not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256):
        raise QualificationError("demo site archive digest is invalid")
    try:
        details = archive.lstat()
    except OSError as error:
        raise QualificationError("demo site archive is unavailable") from error
    if not stat.S_ISREG(details.st_mode) or archive.is_symlink():
        raise QualificationError("demo site archive must be a regular file")
    if details.st_size < 1 or details.st_size > MAX_DEMO_SITE_BYTES:
        raise QualificationError("demo site archive size is invalid")
    actual_sha256 = sha256_file(archive)
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise QualificationError("demo site archive digest does not match candidate")
    try:
        destination.mkdir(mode=0o700)
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            names = [entry.filename for entry in entries]
            if set(names) != DEMO_SITE_FILES or len(names) != len(DEMO_SITE_FILES):
                raise QualificationError("demo site archive contents are invalid")
            total_size = 0
            for entry in entries:
                mode = (entry.external_attr >> 16) & 0o170000
                if (
                    entry.is_dir()
                    or entry.flag_bits & 0x1
                    or entry.file_size < 1
                    or entry.file_size > MAX_DEMO_SITE_FILE_BYTES
                    or mode not in (0, stat.S_IFREG)
                    or Path(entry.filename).name != entry.filename
                ):
                    raise QualificationError("demo site archive entry is unsafe")
                total_size += entry.file_size
                if total_size > MAX_DEMO_SITE_BYTES:
                    raise QualificationError("demo site archive expands past its bound")
                payload = bundle.read(entry)
                if len(payload) != entry.file_size:
                    raise QualificationError("demo site archive entry is truncated")
                target = destination / entry.filename
                descriptor = os.open(
                    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(payload)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise QualificationError("demo site archive is invalid") from error
    return destination, actual_sha256


def combine_failures(
    primary: BaseException | None, cleanup: BaseException, *, label: str = "cleanup"
) -> QualificationError:
    """Preserve both bounded failure categories without leaking raw diagnostics."""
    if primary is None:
        if isinstance(cleanup, QualificationError):
            return cleanup
        return QualificationError(f"{label} failed unexpectedly")
    primary_summary = (
        sanitize_diagnostic(str(primary))
        if isinstance(primary, QualificationError)
        else "qualification failed unexpectedly"
    )
    cleanup_summary = sanitize_diagnostic(str(cleanup))
    return QualificationError(f"{primary_summary}; {label} failed: {cleanup_summary}")


def private_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    temporary.replace(path)
    path.chmod(0o600)


def read_json(path: Path) -> Any:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise QualificationError("qualification JSON input is missing or unsafe")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise QualificationError("qualification JSON input is invalid") from error


def validate_schema(value: Any, name: str) -> None:
    schema = read_json(QUALIFICATION / "schemas" / name)
    try:
        jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.FormatChecker()
        ).validate(value)
    except jsonschema.ValidationError as error:
        raise QualificationError(f"{name} validation failed") from error


def read_private_json(path: Path) -> Any:
    value = read_json(path)
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise QualificationError("private qualification JSON is unavailable") from error
    if stat.S_IMODE(mode) != 0o600:
        raise QualificationError("private qualification JSON must be mode 0600")
    return value


def validate_direct_agent_readiness(value: Any) -> Mapping[str, Any]:
    expected = {
        "schema_version": 1,
        "producer": "bridgefu-agent-direct-secure-observer@1",
        "mode": "direct-secure-preflight",
        "agent_available": True,
        "redacted": True,
    }
    if not isinstance(value, Mapping) or dict(value) != expected:
        raise QualificationError("direct secure agent readiness is invalid")
    return value


def validate_agent_readiness(
    value: Any, execution_id: str, scenario: str
) -> Mapping[str, Any]:
    expected = {
        "schema_version": 1,
        "producer": AGENT_OBSERVER_PRODUCER,
        "mode": "scenario-observer",
        "execution_id": execution_id,
        "scenario_id": scenario,
        "agent_available": True,
        "redacted": True,
    }
    if (
        not EXECUTION_ID.fullmatch(execution_id)
        or scenario not in SCENARIOS
        or not isinstance(value, Mapping)
        or dict(value) != expected
    ):
        raise QualificationError("Amazon Connect observer readiness is invalid")
    return value


def validate_web_source_readiness(value: Any) -> Mapping[str, Any]:
    keys = {
        "schema_version",
        "call_id",
        "source_call_fingerprint",
        "started_at",
        "started_epoch_ms",
    }
    if not isinstance(value, Mapping) or set(value) != keys:
        raise QualificationError("Vapi browser readiness shape is invalid")
    call_id = value.get("call_id")
    fingerprint = value.get("source_call_fingerprint")
    started_at = value.get("started_at")
    started_epoch_ms = value.get("started_epoch_ms")
    if (
        value.get("schema_version") != 1
        or not isinstance(call_id, str)
        or not RESOURCE_ID.fullmatch(call_id)
        or fingerprint != sha256_bytes(call_id.encode("utf-8"))[:12]
        or not isinstance(started_at, str)
        or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z",
            started_at,
        )
        or type(started_epoch_ms) is not int
        or started_epoch_ms <= 0
    ):
        raise QualificationError("Vapi browser readiness is invalid")
    try:
        parsed = dt.datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise QualificationError(
            "Vapi browser readiness timestamp is invalid"
        ) from error
    if (
        parsed.tzinfo is None
        or int(parsed.timestamp() * 1000) != started_epoch_ms
        or parsed > dt.datetime.now(dt.UTC) + dt.timedelta(minutes=1)
    ):
        raise QualificationError("Vapi browser readiness timestamp is invalid")
    return value


def direct_cleanup_receipt(
    execution_id: str,
    *,
    probe_command_terminal: bool,
    cleanup_command_terminal: bool,
    remote: Mapping[str, Any],
) -> dict[str, Any]:
    remote_fields = set(direct_secure_preflight.CLEANUP_FIELDS)
    if (
        not EXECUTION_ID.fullmatch(execution_id)
        or type(probe_command_terminal) is not bool
        or type(cleanup_command_terminal) is not bool
        or not isinstance(remote, Mapping)
        or set(remote) != remote_fields
        or any(type(remote[name]) is not bool for name in remote_fields)
    ):
        raise QualificationError("direct secure cleanup proof is invalid")
    checks = [probe_command_terminal, cleanup_command_terminal]
    checks.extend(remote[name] for name in direct_secure_preflight.CLEANUP_FIELDS)
    return {
        "schema_version": 1,
        "producer": direct_secure_preflight.PRODUCER,
        "execution_id": execution_id,
        "observed_at": utc_now(),
        "probe_command_terminal": probe_command_terminal,
        "cleanup_command_terminal": cleanup_command_terminal,
        **dict(remote),
        "passed": all(checks),
        "redacted": True,
    }


def derive_direct_secure_checks(
    probe: Mapping[str, Any],
    agent: Mapping[str, Any],
    cleanup: Mapping[str, Any],
) -> dict[str, bool]:
    signaling = probe.get("signaling") if isinstance(probe, Mapping) else None
    media = probe.get("media") if isinstance(probe, Mapping) else None
    return {
        "sips_signaling": (
            isinstance(signaling, Mapping) and signaling.get("scheme") == "sips"
        ),
        "tls_transport": (
            isinstance(signaling, Mapping) and signaling.get("transport") == "tls"
        ),
        "rtp_savp": (isinstance(media, Mapping) and media.get("profile") == "RTP/SAVP"),
        "sdes_srtp": (
            isinstance(media, Mapping) and media.get("keying") == "SDES-SRTP"
        ),
        "srtp_contexts_installed": (
            isinstance(media, Mapping) and media.get("contexts_installed") is True
        ),
        "answered": (
            isinstance(signaling, Mapping) and signaling.get("answered") is True
        ),
        "inbound_200": (
            isinstance(signaling, Mapping) and signaling.get("inbound_200") is True
        ),
        "outbound_ack": (
            isinstance(signaling, Mapping) and signaling.get("outbound_ack") is True
        ),
        "contact_dns": (
            isinstance(signaling, Mapping) and signaling.get("contact_host") == "dns"
        ),
        "contact_sips": (
            isinstance(signaling, Mapping) and signaling.get("contact_sips") is True
        ),
        "contact_tls": (
            isinstance(signaling, Mapping) and signaling.get("contact_tls") is True
        ),
        "exactly_one_correlation_header": (
            isinstance(signaling, Mapping)
            and signaling.get("invite_count") == 1
            and signaling.get("correlation_header_count") == 1
        ),
        "agent_available": agent.get("agent_available") is True,
        "agent_sole_contact_auto_accepted": (
            agent.get("sole_contact_auto_accepted") is True
        ),
        "agent_remote_audio": agent.get("remote_audio_observed") is True,
        "agent_outbound_rtp": agent.get("outbound_rtp_observed") is True,
        "agent_remote_hangup": agent.get("remote_hangup_observed") is True,
        "agent_contact_cleanup": agent.get("contact_cleanup_observed") is True,
        "owned_ssm_commands_terminal": (
            cleanup.get("probe_command_terminal") is True
            and cleanup.get("cleanup_command_terminal") is True
        ),
        "runtime_probe_process_absent": (cleanup.get("probe_process_absent") is True),
        "runtime_configuration_restored": (
            cleanup.get("configuration_restored") is True
        ),
        "runtime_private_dns_verified": (cleanup.get("private_dns_verified") is True),
        "runtime_run_artifacts_absent": (cleanup.get("run_artifacts_absent") is True),
        "runtime_bridgefu_ready": cleanup.get("bridgefu_active") is True,
    }


def sanitize_diagnostic(value: Any, maximum: int = DIAGNOSTIC_LIMIT) -> str:
    """Return one bounded line that cannot retain common credential forms."""
    if not isinstance(value, str) or maximum < 1:
        return "unavailable"
    cleaned = re.sub(r"[\x00-\x1f\x7f]+", " ", value)
    cleaned = re.sub(r"(?i)\bBearer\s+[^\s,;]+", "Bearer [REDACTED]", cleaned)
    secret_assignment = re.compile(
        r"(?i)[\"']?\b(authorization|x-api-key|api[-_ ]?key|password|passwd|secret|"
        r"token|credential|signature)\b[\"']?\s*[:=]\s*"
        r"(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    )
    cleaned = secret_assignment.sub(
        lambda match: f"{match.group(1)}=[REDACTED]", cleaned
    )
    cleaned = re.sub(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "[REDACTED_AWS_KEY]", cleaned)
    cleaned = re.sub(
        r"\beyJ[A-Za-z0-9_-]{20,}(?:\.[A-Za-z0-9_-]{8,}){1,2}\b",
        "[REDACTED_TOKEN]",
        cleaned,
    )
    cleaned = re.sub(
        r"(?i)([?&](?:x-amz-[^=&\s]+|token|key|secret|password|signature)=)[^&\s]+",
        r"\1[REDACTED]",
        cleaned,
    )
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return "unavailable"
    if len(cleaned) > maximum:
        cleaned = cleaned[: maximum - 3].rstrip() + "..."
    return cleaned


class CommandRunner:
    """Subprocess boundary kept injectable for fail-closed unit tests."""

    def run(
        self,
        arguments: list[str],
        *,
        input_text: str | None = None,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: int = 900,
    ) -> str:
        try:
            result = subprocess.run(
                arguments,
                cwd=cwd,
                env=dict(env) if env is not None else None,
                input=input_text,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise QualificationError(
                f"command failed to run: {arguments[0]}"
            ) from error
        if result.returncode != 0:
            command = Path(arguments[0]).name if arguments else "command"
            service = arguments[1] if len(arguments) > 1 else ""
            label = f"{command} {service}".strip()
            detail = sanitize_diagnostic(result.stderr)
            raise QualificationError(f"command failed: {label}: {detail}")
        return result.stdout

    def popen(
        self,
        arguments: list[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
    ) -> subprocess.Popen[str]:
        try:
            return subprocess.Popen(
                arguments,
                cwd=cwd,
                env=dict(env) if env is not None else None,
                text=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as error:
            raise QualificationError(
                f"command failed to start: {arguments[0]}"
            ) from error

    def probe(self, arguments: list[str], *, timeout: int = 60) -> tuple[int, str, str]:
        try:
            result = subprocess.run(
                arguments,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise QualificationError(f"command probe failed: {arguments[0]}") from error
        return result.returncode, result.stdout, result.stderr


def terminate_owned_process(
    process: subprocess.Popen[str], *, timeout: int = 10
) -> tuple[str, str]:
    """Boundedly terminate one process and every descendant in its owned session."""
    pid = getattr(process, "pid", None)
    if isinstance(pid, int) and pid > 0:
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            if process.poll() is None:
                process.terminate()
    elif process.poll() is None:
        process.terminate()
    try:
        return process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        if isinstance(pid, int) and pid > 0:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                if process.poll() is None:
                    process.kill()
        elif process.poll() is None:
            process.kill()
        try:
            return process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise QualificationError("owned subprocess cleanup timed out") from error


class Aws:
    def __init__(self, region: str, runner: CommandRunner) -> None:
        self.region = region
        self.runner = runner

    def json(self, arguments: list[str], timeout: int = 900) -> Any:
        output = self.runner.run(
            ["aws", *arguments, "--region", self.region, "--output", "json"],
            timeout=timeout,
        )
        try:
            return json.loads(output)
        except json.JSONDecodeError as error:
            raise QualificationError("AWS CLI returned invalid JSON") from error

    def text(self, arguments: list[str], timeout: int = 900) -> str:
        return self.runner.run(
            ["aws", *arguments, "--region", self.region, "--output", "text"],
            timeout=timeout,
        ).strip()

    def exists(self, arguments: list[str]) -> bool:
        status, _, error = self.runner.probe(
            ["aws", *arguments, "--region", self.region, "--output", "json"],
            timeout=60,
        )
        if status == 0:
            return True
        operation = tuple(arguments[:2])
        code_match = re.search(r"\(([A-Za-z0-9.]+)\)", error)
        code = code_match.group(1) if code_match else None
        missing_codes = {
            ("route53", "get-hosted-zone"): {"NoSuchHostedZone"},
            ("connect", "describe-instance"): {"ResourceNotFoundException"},
            ("secretsmanager", "describe-secret"): {"ResourceNotFoundException"},
        }
        if code in missing_codes.get(operation, set()):
            return False
        if (
            operation == ("cloudformation", "describe-stacks")
            and code == "ValidationError"
            and re.search(r"Stack with id .+ does not exist", error, re.I)
        ):
            return False
        raise QualificationError("AWS existence check failed")

    def secret(self, arn: str) -> str:
        value = self.json(["secretsmanager", "get-secret-value", "--secret-id", arn])
        secret = value.get("SecretString") if isinstance(value, Mapping) else None
        if not isinstance(secret, str) or not 8 <= len(secret) <= 16384:
            raise QualificationError("Secrets Manager value is missing or invalid")
        return secret


def _validate_version_target(bucket: str, prefix: str, *, exact_key: bool) -> None:
    parts = prefix.split("/")
    if (
        not S3_BUCKET.fullmatch(bucket)
        or not prefix.startswith("qualification/")
        or len(parts) < 3
        or not EXECUTION_ID.fullmatch(parts[1])
        or (exact_key and prefix.endswith("/"))
        or (not exact_key and not prefix.endswith("/"))
        or len(prefix.encode("utf-8")) > 512
        or re.search(r"[\x00-\x1f\x7f]", prefix)
        or ".." in prefix.split("/")
    ):
        raise QualificationError("qualification object target is invalid")


def list_object_versions_exact(
    aws: Aws, bucket: str, prefix: str, *, exact_key: bool = False
) -> list[dict[str, str]]:
    """List every version and delete marker under one bounded exact prefix."""
    _validate_version_target(bucket, prefix, exact_key=exact_key)
    results: list[dict[str, str]] = []
    seen_versions: set[tuple[str, str]] = set()
    key_marker: str | None = None
    version_marker: str | None = None
    seen_markers: set[tuple[str | None, str | None]] = set()
    for _ in range(MAX_OBJECT_VERSION_PAGES):
        marker = (key_marker, version_marker)
        if marker in seen_markers:
            raise QualificationError("qualification object pagination did not advance")
        seen_markers.add(marker)
        arguments = [
            "s3api",
            "list-object-versions",
            "--bucket",
            bucket,
            "--prefix",
            prefix,
            "--max-keys",
            "1000",
            "--no-paginate",
        ]
        if key_marker is not None:
            arguments.extend(["--key-marker", key_marker])
        if version_marker is not None:
            arguments.extend(["--version-id-marker", version_marker])
        page = aws.json(arguments, timeout=120)
        if not isinstance(page, Mapping) or not isinstance(
            page.get("IsTruncated"), bool
        ):
            raise QualificationError("qualification object version list is invalid")
        for field in ("Versions", "DeleteMarkers"):
            values = page.get(field, [])
            if not isinstance(values, list):
                raise QualificationError("qualification object version list is invalid")
            for value in values:
                key = value.get("Key") if isinstance(value, Mapping) else None
                version_id = (
                    value.get("VersionId") if isinstance(value, Mapping) else None
                )
                if (
                    not isinstance(key, str)
                    or not key.startswith(prefix)
                    or len(key.encode("utf-8")) > 1024
                    or re.search(r"[\x00-\x1f\x7f]", key)
                    or not isinstance(version_id, str)
                    or not 1 <= len(version_id) <= 1024
                    or re.search(r"[\x00-\x1f\x7f]", version_id)
                ):
                    raise QualificationError(
                        "qualification object version identity is invalid"
                    )
                if exact_key and key != prefix:
                    continue
                if not exact_key and key == prefix:
                    raise QualificationError(
                        "qualification object version identity is invalid"
                    )
                version_identity = (key, version_id)
                if version_identity in seen_versions:
                    raise QualificationError(
                        "qualification object version identity is duplicated"
                    )
                seen_versions.add(version_identity)
                results.append({"Key": key, "VersionId": version_id})
                if len(results) > MAX_OBJECT_VERSIONS:
                    raise QualificationError(
                        "qualification object version bound was exceeded"
                    )
        if not page.get("IsTruncated", False):
            return results
        next_key = page.get("NextKeyMarker")
        next_version = page.get("NextVersionIdMarker")
        if (
            not isinstance(next_key, str)
            or not next_key.startswith(prefix)
            or not isinstance(next_version, str)
            or not next_version
            or len(next_key.encode("utf-8")) > 1024
            or len(next_version) > 1024
            or re.search(r"[\x00-\x1f\x7f]", next_key + next_version)
        ):
            raise QualificationError(
                "qualification object pagination marker is invalid"
            )
        key_marker, version_marker = next_key, next_version
    raise QualificationError("qualification object pagination bound was exceeded")


def purge_object_versions_exact(
    aws: Aws, bucket: str, prefix: str, *, exact_key: bool = False
) -> None:
    versions = list_object_versions_exact(aws, bucket, prefix, exact_key=exact_key)
    for offset in range(0, len(versions), MAX_DELETE_OBJECTS):
        chunk = versions[offset : offset + MAX_DELETE_OBJECTS]
        response = aws.json(
            [
                "s3api",
                "delete-objects",
                "--bucket",
                bucket,
                "--delete",
                json.dumps(
                    {"Objects": chunk, "Quiet": False},
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ],
            timeout=120,
        )
        deleted = response.get("Deleted") if isinstance(response, Mapping) else None
        errors = response.get("Errors") if isinstance(response, Mapping) else None
        expected_identities = {(item["Key"], item["VersionId"]) for item in chunk}
        deleted_identities: set[tuple[str, str]] = set()
        if isinstance(deleted, list):
            for item in deleted:
                key = item.get("Key") if isinstance(item, Mapping) else None
                version_id = (
                    item.get("VersionId") if isinstance(item, Mapping) else None
                )
                if not isinstance(key, str) or not isinstance(version_id, str):
                    deleted_identities.clear()
                    break
                deleted_identities.add((key, version_id))
        if (
            not isinstance(response, Mapping)
            or errors not in (None, [])
            or not isinstance(deleted, list)
            or len(deleted) != len(deleted_identities)
            or deleted_identities != expected_identities
        ):
            raise QualificationError("qualification object version deletion failed")
    if list_object_versions_exact(aws, bucket, prefix, exact_key=exact_key):
        raise QualificationError("qualification object versions remain after cleanup")


def _normalized_dns_name(value: Any) -> str:
    if not isinstance(value, str):
        raise QualificationError("ACM validation record name is invalid")
    normalized = value.rstrip(".").lower() + "."
    if (
        len(normalized) > 254
        or re.fullmatch(
            r"(?:_[a-z0-9]{1,64}\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+",
            normalized,
        )
        is None
    ):
        raise QualificationError("ACM validation record name is invalid")
    return normalized


def _validate_acm_record_scope(name: str, sip_hostname: str) -> None:
    base = _normalized_dns_name(sip_hostname)
    allowed_suffixes = (f".{base}", f".control.{base}")
    if not name.startswith("_") or not any(
        name.endswith(suffix) for suffix in allowed_suffixes
    ):
        raise QualificationError("ACM validation record is outside qualification scope")


def route53_record_set(
    aws: Aws, hosted_zone_id: str, name: str
) -> dict[str, Any] | None:
    if not re.fullmatch(r"[A-Z0-9]{1,64}", hosted_zone_id):
        raise QualificationError("ACM validation hosted zone is invalid")
    normalized_name = _normalized_dns_name(name)
    value = aws.json(
        [
            "route53",
            "list-resource-record-sets",
            "--hosted-zone-id",
            hosted_zone_id,
            "--start-record-name",
            normalized_name,
            "--start-record-type",
            "CNAME",
            "--max-items",
            "1",
        ],
        timeout=120,
    )
    record_sets = (
        value.get("ResourceRecordSets") if isinstance(value, Mapping) else None
    )
    if not isinstance(record_sets, list):
        raise QualificationError("Route53 record-set response is invalid")
    if not record_sets:
        return None
    candidate = record_sets[0]
    if not isinstance(candidate, Mapping):
        raise QualificationError("Route53 record-set response is invalid")
    candidate_name = _normalized_dns_name(candidate.get("Name"))
    candidate_type = candidate.get("Type")
    if candidate_name != normalized_name or candidate_type != "CNAME":
        return None
    ttl = candidate.get("TTL")
    resources = candidate.get("ResourceRecords")
    if (
        not isinstance(ttl, int)
        or not 1 <= ttl <= 2_147_483_647
        or not isinstance(resources, list)
        or not 1 <= len(resources) <= 20
    ):
        raise QualificationError("Route53 ACM validation record is invalid")
    values: list[str] = []
    for resource in resources:
        record_value = resource.get("Value") if isinstance(resource, Mapping) else None
        if (
            not isinstance(record_value, str)
            or not 1 <= len(record_value) <= 1024
            or re.search(r"[\x00-\x1f\x7f]", record_value)
        ):
            raise QualificationError("Route53 ACM validation value is invalid")
        values.append(record_value)
    if len(values) != len(set(values)):
        raise QualificationError("Route53 ACM validation values are duplicated")
    return {
        "name": candidate_name,
        "type": "CNAME",
        "ttl": ttl,
        "resource_records": sorted(values),
    }


def _nested_stack_resources(aws: Aws, root_stack: str) -> list[Mapping[str, Any]]:
    queue = [root_stack]
    seen: set[str] = set()
    resources: list[Mapping[str, Any]] = []
    while queue:
        stack = queue.pop(0)
        if stack in seen or len(seen) >= MAX_NESTED_STACKS:
            raise QualificationError("qualification nested-stack topology is invalid")
        seen.add(stack)
        value = aws.json(
            ["cloudformation", "list-stack-resources", "--stack-name", stack],
            timeout=120,
        )
        summaries = (
            value.get("StackResourceSummaries") if isinstance(value, Mapping) else None
        )
        if not isinstance(summaries, list) or len(summaries) > 500:
            raise QualificationError("qualification stack resources are invalid")
        for resource in summaries:
            if not isinstance(resource, Mapping):
                raise QualificationError("qualification stack resource is invalid")
            resources.append(resource)
            if resource.get("ResourceType") == "AWS::CloudFormation::Stack":
                nested = resource.get("PhysicalResourceId")
                if nested is None:
                    continue
                if not isinstance(nested, str) or not nested.startswith("arn:aws"):
                    raise QualificationError("qualification nested stack ID is invalid")
                queue.append(nested)
    return resources


def discover_stack_output(aws: Aws, root_stack: str, output_key: str) -> str | None:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,127}", output_key):
        raise QualificationError("qualification output key is invalid")
    queue = [root_stack]
    seen: set[str] = set()
    values: set[str] = set()
    while queue:
        stack = queue.pop(0)
        if stack in seen or len(seen) >= MAX_NESTED_STACKS:
            raise QualificationError("qualification nested-stack topology is invalid")
        seen.add(stack)
        response = aws.json(
            ["cloudformation", "describe-stacks", "--stack-name", stack], timeout=120
        )
        stacks = response.get("Stacks") if isinstance(response, Mapping) else None
        if not isinstance(stacks, list) or len(stacks) != 1:
            raise QualificationError("qualification stack description is invalid")
        outputs = stacks[0].get("Outputs", [])
        if not isinstance(outputs, list):
            raise QualificationError("qualification stack outputs are invalid")
        for output in outputs:
            if (
                isinstance(output, Mapping)
                and output.get("OutputKey") == output_key
                and isinstance(output.get("OutputValue"), str)
            ):
                values.add(output["OutputValue"])
        resources = aws.json(
            ["cloudformation", "list-stack-resources", "--stack-name", stack],
            timeout=120,
        )
        summaries = (
            resources.get("StackResourceSummaries")
            if isinstance(resources, Mapping)
            else None
        )
        if not isinstance(summaries, list) or len(summaries) > 500:
            raise QualificationError("qualification stack resources are invalid")
        for resource in summaries:
            if (
                isinstance(resource, Mapping)
                and resource.get("ResourceType") == "AWS::CloudFormation::Stack"
                and isinstance(resource.get("PhysicalResourceId"), str)
            ):
                queue.append(resource["PhysicalResourceId"])
    if len(values) > 1:
        raise QualificationError("qualification stack output is ambiguous")
    return next(iter(values), None)


def discover_acm_validation_ownership(
    aws: Aws,
    stack_name: str,
    execution_id: str,
    hosted_zone_id: str,
    sip_hostname: str,
) -> dict[str, Any] | None:
    """Discover only the certificate tagged for this exact disposable stack."""
    certificate_arns = {
        str(resource["PhysicalResourceId"])
        for resource in _nested_stack_resources(aws, stack_name)
        if resource.get("ResourceType") == "AWS::CertificateManager::Certificate"
        and isinstance(resource.get("PhysicalResourceId"), str)
    }
    if not certificate_arns:
        return None
    if len(certificate_arns) != 1:
        raise QualificationError("qualification ACM certificate identity is ambiguous")
    certificate_arn = next(iter(certificate_arns))
    if (
        re.fullmatch(
            rf"arn:aws[-a-z0-9]*:acm:{re.escape(aws.region)}:[0-9]{{12}}:certificate/[A-Za-z0-9-]+",
            certificate_arn,
        )
        is None
    ):
        raise QualificationError("qualification ACM certificate ARN is invalid")
    tag_response = aws.json(
        ["acm", "list-tags-for-certificate", "--certificate-arn", certificate_arn],
        timeout=120,
    )
    tag_items = tag_response.get("Tags") if isinstance(tag_response, Mapping) else None
    if not isinstance(tag_items, list):
        raise QualificationError("qualification ACM certificate tags are invalid")
    tags = {
        item.get("Key"): item.get("Value")
        for item in tag_items
        if isinstance(item, Mapping)
        and isinstance(item.get("Key"), str)
        and isinstance(item.get("Value"), str)
    }
    if (
        tags.get("Project") != "bridgefu-vapi-awsconnect"
        or tags.get("ManagedBy") != "bridgefu-cloudformation"
        or tags.get("BridgefuExecutionId") != execution_id
        or tags.get("BridgefuRecipe") != RECIPE
    ):
        raise QualificationError("qualification ACM certificate ownership is invalid")
    response = aws.json(
        ["acm", "describe-certificate", "--certificate-arn", certificate_arn],
        timeout=120,
    )
    certificate = response.get("Certificate") if isinstance(response, Mapping) else None
    validation_options = (
        certificate.get("DomainValidationOptions")
        if isinstance(certificate, Mapping)
        else None
    )
    if not isinstance(validation_options, list):
        raise QualificationError("qualification ACM validation options are invalid")
    expected: dict[str, str] = {}
    for option in validation_options:
        resource = option.get("ResourceRecord") if isinstance(option, Mapping) else None
        if resource is None:
            continue
        name = _normalized_dns_name(
            resource.get("Name") if isinstance(resource, Mapping) else None
        )
        record_type = resource.get("Type") if isinstance(resource, Mapping) else None
        record_value = resource.get("Value") if isinstance(resource, Mapping) else None
        _validate_acm_record_scope(name, sip_hostname)
        if (
            record_type != "CNAME"
            or not isinstance(record_value, str)
            or not 1 <= len(record_value) <= 1024
            or re.search(r"[\x00-\x1f\x7f]", record_value)
        ):
            raise QualificationError("qualification ACM validation value is invalid")
        if name in expected and expected[name] != record_value:
            raise QualificationError("qualification ACM validation record is ambiguous")
        expected[name] = record_value
    if not 1 <= len(expected) <= MAX_ACM_VALIDATION_RECORDS:
        raise QualificationError("qualification ACM validation records are unavailable")
    record_sets: list[dict[str, Any]] = []
    for name, expected_value in sorted(expected.items()):
        current = route53_record_set(aws, hosted_zone_id, name)
        if current is None or current["resource_records"] != [expected_value]:
            raise QualificationError(
                "qualification ACM validation record ownership conflicts"
            )
        record_sets.append(current)
    owned = {
        "execution_id": execution_id,
        "region": aws.region,
        "public_hosted_zone_id": hosted_zone_id,
        "certificate_arn": certificate_arn,
        "record_sets": record_sets,
    }
    journal = {
        "schema_version": 1,
        "producer": ACM_OWNERSHIP_PRODUCER,
        **owned,
        "ownership_sha256": canonical_sha256(owned),
        "created_at": utc_now(),
        "redacted": True,
    }
    validate_acm_validation_ownership(journal)
    return journal


def validate_acm_validation_ownership(value: Any) -> Mapping[str, Any]:
    validate_schema(value, "acm-validation-ownership-v1.schema.json")
    if not isinstance(value, Mapping):
        raise QualificationError("ACM validation ownership journal is invalid")
    owned = {
        key: value[key]
        for key in (
            "execution_id",
            "region",
            "public_hosted_zone_id",
            "certificate_arn",
            "record_sets",
        )
    }
    if value.get("ownership_sha256") != canonical_sha256(owned):
        raise QualificationError("ACM validation ownership journal hash is invalid")
    records = value["record_sets"]
    names = [record["name"] for record in records]
    if names != sorted(names) or len(names) != len(set(names)):
        raise QualificationError("ACM validation ownership records are not canonical")
    for record in records:
        values = record["resource_records"]
        if (
            record.get("type") != "CNAME"
            or values != sorted(values)
            or len(values) != len(set(values))
        ):
            raise QualificationError("ACM validation ownership record is invalid")
    return value


def delete_acm_validation_records_exact(aws: Aws, journal: Mapping[str, Any]) -> None:
    journal = validate_acm_validation_ownership(journal)
    hosted_zone_id = str(journal["public_hosted_zone_id"])
    for record in journal["record_sets"]:
        current = route53_record_set(aws, hosted_zone_id, record["name"])
        if current is None:
            continue
        if current != record:
            raise QualificationError(
                "ACM validation record changed after ownership seal"
            )
        response = aws.json(
            [
                "route53",
                "change-resource-record-sets",
                "--hosted-zone-id",
                hosted_zone_id,
                "--change-batch",
                json.dumps(
                    {
                        "Changes": [
                            {
                                "Action": "DELETE",
                                "ResourceRecordSet": {
                                    "Name": record["name"],
                                    "Type": "CNAME",
                                    "TTL": record["ttl"],
                                    "ResourceRecords": [
                                        {"Value": item}
                                        for item in record["resource_records"]
                                    ],
                                },
                            }
                        ]
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ],
            timeout=120,
        )
        change = response.get("ChangeInfo") if isinstance(response, Mapping) else None
        change_id = change.get("Id") if isinstance(change, Mapping) else None
        if not isinstance(change_id, str) or not change_id.startswith("/change/"):
            raise QualificationError("Route53 deletion change ID is invalid")
        deadline = time.monotonic() + 300
        while True:
            status = aws.json(["route53", "get-change", "--id", change_id], timeout=120)
            info = status.get("ChangeInfo") if isinstance(status, Mapping) else None
            state = info.get("Status") if isinstance(info, Mapping) else None
            if state == "INSYNC":
                break
            if state != "PENDING" or time.monotonic() >= deadline:
                raise QualificationError(
                    "Route53 validation-record deletion did not converge"
                )
            time.sleep(2)
    for record in journal["record_sets"]:
        if route53_record_set(aws, hosted_zone_id, record["name"]) is not None:
            raise QualificationError("ACM validation record remains after cleanup")


class Vapi:
    def __init__(self, private_key: str, base_url: str = VAPI_BASE_URL) -> None:
        if not isinstance(private_key, str) or not 8 <= len(private_key) <= 1024:
            raise QualificationError("Vapi private key is invalid")
        self.private_key = private_key
        self.base_url = base_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        allow_missing: bool = False,
    ) -> Any:
        if not path.startswith("/") or ".." in path:
            raise QualificationError("Vapi API path is invalid")
        body = None
        headers = {
            "Authorization": f"Bearer {self.private_key}",
            "Accept": "application/json",
            "User-Agent": "bridgefu-release-qualification/1",
        }
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base_url + path, data=body, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                raw = response.read(4 * 1024 * 1024 + 1)
        except urllib.error.HTTPError as error:
            if allow_missing and error.code == 404:
                return None
            if method in {"POST", "PUT", "PATCH"} and error.code >= 500:
                raise VapiAmbiguousWriteError(
                    f"Vapi API {method} write outcome is ambiguous"
                ) from error
            raise QualificationError(
                f"Vapi API {method} failed with HTTP {error.code}"
            ) from error
        except (OSError, TimeoutError) as error:
            if method in {"POST", "PUT", "PATCH"}:
                raise VapiAmbiguousWriteError(
                    f"Vapi API {method} write outcome is ambiguous"
                ) from error
            raise QualificationError(f"Vapi API {method} request failed") from error
        if len(raw) > 4 * 1024 * 1024:
            if method in {"POST", "PUT", "PATCH"}:
                raise VapiAmbiguousWriteError(
                    f"Vapi API {method} write outcome is ambiguous"
                )
            raise QualificationError("Vapi API response exceeded its bound")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            if method in {"POST", "PUT", "PATCH"}:
                raise VapiAmbiguousWriteError(
                    f"Vapi API {method} write outcome is ambiguous"
                ) from error
            raise QualificationError("Vapi API returned invalid JSON") from error

    def get(self, resource: str, resource_id: str) -> Mapping[str, Any] | None:
        if not RESOURCE_ID.fullmatch(resource_id):
            raise QualificationError("Vapi resource ID is invalid")
        value = self.request("GET", f"/{resource}/{resource_id}", allow_missing=True)
        if value is not None and not isinstance(value, Mapping):
            raise QualificationError("Vapi API resource has an invalid shape")
        return value

    def list(self, resource: str, *, limit: int = 100) -> list[Mapping[str, Any]]:
        if not 1 <= limit <= 100:
            raise QualificationError("Vapi API list limit is invalid")
        value = self.request("GET", f"/{resource}?limit={limit}")
        if not isinstance(value, list) or any(
            not isinstance(item, Mapping) for item in value
        ):
            raise QualificationError("Vapi API list has an invalid shape")
        return list(value)

    def list_calls(
        self,
        *,
        assistant_id: str,
        created_at_ge: dt.datetime,
        phone_number_id: str | None,
        call_id: str | None,
        limit: int = 20,
    ) -> list[Mapping[str, Any]]:
        for value in (assistant_id, phone_number_id, call_id):
            if value is not None and not RESOURCE_ID.fullmatch(value):
                raise QualificationError("Vapi call filter is invalid")
        if created_at_ge.tzinfo is None or not 1 <= limit <= 100:
            raise QualificationError("Vapi call filter is invalid")
        query: list[tuple[str, str]] = [
            ("limit", str(limit)),
            ("assistantId", assistant_id),
            (
                "createdAtGe",
                created_at_ge.astimezone(dt.UTC).isoformat().replace("+00:00", "Z"),
            ),
        ]
        if phone_number_id is not None:
            query.append(("phoneNumberId", phone_number_id))
        if call_id is not None:
            query.append(("id", call_id))
        value = self.request("GET", "/call?" + urllib.parse.urlencode(query))
        if not isinstance(value, list) or any(
            not isinstance(item, Mapping) for item in value
        ):
            raise QualificationError("Vapi API call list has an invalid shape")
        return list(value)

    def find_direct_tool(
        self,
        *,
        execution_id: str,
        endpoint_url: str,
        credential_id: str,
        desired: Mapping[str, Any],
    ) -> Mapping[str, Any] | None:
        tools = self.list("tool")
        if len(tools) == 100:
            raise QualificationError(
                "direct Vapi tool reconciliation exceeded its safe bound"
            )
        related: list[Mapping[str, Any]] = []
        for tool in tools:
            server = tool.get("server")
            function = tool.get("function")
            if (isinstance(server, Mapping) and server.get("url") == endpoint_url) or (
                isinstance(server, Mapping)
                and server.get("credentialId") == credential_id
                and isinstance(function, Mapping)
                and function.get("name") == bridgefu_web_handoff.DIRECT_TOOL_NAME
            ):
                related.append(tool)
        if len(related) > 1:
            raise QualificationError("direct Vapi tool ownership is ambiguous")
        if not related:
            return None
        match = related[0]
        if not bridgefu_web_handoff.direct_tool_owned(
            match,
            execution_id=execution_id,
            endpoint_url=endpoint_url,
            credential_id=credential_id,
        ) or not direct_tool_surface_matches(match, desired):
            raise QualificationError("direct Vapi tool ownership conflicts")
        return match

    def create_direct_tool(
        self,
        *,
        execution_id: str,
        endpoint_url: str,
        credential_id: str,
        desired: Mapping[str, Any],
        reconcile_timeout: int = 10,
    ) -> Mapping[str, Any]:
        existing = self.find_direct_tool(
            execution_id=execution_id,
            endpoint_url=endpoint_url,
            credential_id=credential_id,
            desired=desired,
        )
        if existing is not None:
            return existing
        try:
            created = self.request("POST", "/tool", desired)
        except VapiAmbiguousWriteError as error:
            deadline = time.monotonic() + reconcile_timeout
            while True:
                found = self.find_direct_tool(
                    execution_id=execution_id,
                    endpoint_url=endpoint_url,
                    credential_id=credential_id,
                    desired=desired,
                )
                if found is not None:
                    return found
                if time.monotonic() >= deadline:
                    raise QualificationError(
                        "direct Vapi tool creation could not be reconciled"
                    ) from error
                time.sleep(0.5)
        resource_id = created.get("id") if isinstance(created, Mapping) else None
        if not isinstance(resource_id, str) or not RESOURCE_ID.fullmatch(resource_id):
            raise QualificationError("direct Vapi tool creation returned no identity")
        exact = self.get("tool", resource_id)
        owned = self.find_direct_tool(
            execution_id=execution_id,
            endpoint_url=endpoint_url,
            credential_id=credential_id,
            desired=desired,
        )
        if (
            exact is None
            or not direct_tool_surface_matches(exact, desired)
            or owned is None
            or owned.get("id") != resource_id
        ):
            raise QualificationError("direct Vapi tool creation was not verified")
        return owned

    def delete_direct_tool(
        self,
        resource_id: str,
        *,
        execution_id: str,
        endpoint_url: str,
        credential_id: str,
        desired: Mapping[str, Any],
    ) -> None:
        exact = self.get("tool", resource_id)
        if exact is None:
            return
        if (
            exact.get("id") != resource_id
            or not bridgefu_web_handoff.direct_tool_owned(
                exact,
                execution_id=execution_id,
                endpoint_url=endpoint_url,
                credential_id=credential_id,
            )
            or not direct_tool_surface_matches(exact, desired)
        ):
            raise QualificationError("direct Vapi tool deletion target is not owned")
        self.request("DELETE", f"/tool/{resource_id}", allow_missing=True)
        deadline = time.monotonic() + 30
        while self.get("tool", resource_id) is not None:
            if time.monotonic() >= deadline:
                raise QualificationError("direct Vapi tool deletion timed out")
            time.sleep(0.5)

    def find_direct_assistant(
        self,
        *,
        execution_id: str,
        tool_id: str,
        prompt_sha256: str,
        model_name: str,
        voice_id: str,
        desired: Mapping[str, Any],
    ) -> Mapping[str, Any] | None:
        assistants = self.list("assistant")
        if len(assistants) == 100:
            raise QualificationError(
                "direct Vapi assistant reconciliation exceeded its safe bound"
            )
        name = f"BFQ direct {execution_id}"
        related: list[Mapping[str, Any]] = []
        for item in assistants:
            metadata = item.get("metadata")
            model = item.get("model")
            tool_ids = model.get("toolIds") if isinstance(model, Mapping) else None
            if (
                item.get("name") == name
                or (
                    isinstance(metadata, Mapping)
                    and metadata.get("bridgefu_qualification") == execution_id
                )
                or (
                    isinstance(metadata, Mapping)
                    and metadata.get("bridgefu_owner")
                    == bridgefu_web_handoff.DIRECT_ASSISTANT_OWNER
                    and isinstance(tool_ids, list)
                    and tool_id in tool_ids
                )
            ):
                related.append(item)
        if len(related) > 1:
            raise QualificationError("direct Vapi assistant ownership is ambiguous")
        if not related:
            return None
        match = related[0]
        if not bridgefu_web_handoff.direct_assistant_owned(
            match,
            execution_id=execution_id,
            tool_id=tool_id,
            prompt_sha256=prompt_sha256,
            model_name=model_name,
            voice_id=voice_id,
        ) or not desired_payload_present(match, desired):
            raise QualificationError("direct Vapi assistant ownership conflicts")
        return match

    def create_direct_assistant(
        self,
        *,
        execution_id: str,
        tool_id: str,
        prompt_sha256: str,
        model_name: str,
        voice_id: str,
        desired: Mapping[str, Any],
        reconcile_timeout: int = 10,
    ) -> Mapping[str, Any]:
        existing = self.find_direct_assistant(
            execution_id=execution_id,
            tool_id=tool_id,
            prompt_sha256=prompt_sha256,
            model_name=model_name,
            voice_id=voice_id,
            desired=desired,
        )
        if existing is not None:
            return existing
        try:
            created = self.request("POST", "/assistant", desired)
        except VapiAmbiguousWriteError as error:
            deadline = time.monotonic() + reconcile_timeout
            while True:
                found = self.find_direct_assistant(
                    execution_id=execution_id,
                    tool_id=tool_id,
                    prompt_sha256=prompt_sha256,
                    model_name=model_name,
                    voice_id=voice_id,
                    desired=desired,
                )
                if found is not None:
                    return found
                if time.monotonic() >= deadline:
                    raise QualificationError(
                        "direct Vapi assistant creation could not be reconciled"
                    ) from error
                time.sleep(0.5)
        resource_id = created.get("id") if isinstance(created, Mapping) else None
        if not isinstance(resource_id, str) or not RESOURCE_ID.fullmatch(resource_id):
            raise QualificationError(
                "direct Vapi assistant creation returned no identity"
            )
        exact = self.get("assistant", resource_id)
        owned = self.find_direct_assistant(
            execution_id=execution_id,
            tool_id=tool_id,
            prompt_sha256=prompt_sha256,
            model_name=model_name,
            voice_id=voice_id,
            desired=desired,
        )
        if (
            exact is None
            or not bridgefu_web_handoff.direct_assistant_owned(
                exact,
                execution_id=execution_id,
                tool_id=tool_id,
                prompt_sha256=prompt_sha256,
                model_name=model_name,
                voice_id=voice_id,
            )
            or not desired_payload_present(exact, desired)
            or owned is None
            or owned.get("id") != resource_id
        ):
            raise QualificationError("direct Vapi assistant creation was not verified")
        return exact

    def delete_direct_assistant(
        self,
        resource_id: str,
        *,
        execution_id: str,
        tool_id: str,
        prompt_sha256: str,
        model_name: str,
        voice_id: str,
    ) -> None:
        exact = self.get("assistant", resource_id)
        if exact is None:
            return
        if exact.get(
            "id"
        ) != resource_id or not bridgefu_web_handoff.direct_assistant_owned(
            exact,
            execution_id=execution_id,
            tool_id=tool_id,
            prompt_sha256=prompt_sha256,
            model_name=model_name,
            voice_id=voice_id,
        ):
            raise QualificationError(
                "direct Vapi assistant deletion target is not owned"
            )
        self.request("DELETE", f"/assistant/{resource_id}", allow_missing=True)
        deadline = time.monotonic() + 30
        while self.get("assistant", resource_id) is not None:
            if time.monotonic() >= deadline:
                raise QualificationError("direct Vapi assistant deletion timed out")
            time.sleep(0.5)

    def create_phone(
        self,
        execution_id: str,
        assistant_id: str,
        authentication: Mapping[str, str],
        *,
        reconcile_timeout: int = 10,
        poll_seconds: float = 0.5,
    ) -> Mapping[str, Any]:
        if reconcile_timeout < 0 or poll_seconds < 0:
            raise QualificationError("Vapi SIP reconciliation bound is invalid")
        intent = vapi_phone_intent(execution_id, assistant_id, authentication)
        existing = self.find_phone_for_intent(intent)
        if existing is not None:
            return existing
        payload = {
            "provider": "vapi",
            "name": intent["name"],
            "sipUri": intent["sip_uri"],
            "assistantId": assistant_id,
            "authentication": dict(authentication),
        }
        try:
            value = self.request("POST", "/phone-number", payload)
        except VapiAmbiguousWriteError as error:
            try:
                reconciled = self._wait_for_phone_intent(
                    intent, timeout=reconcile_timeout, poll_seconds=poll_seconds
                )
            except QualificationError as reconciliation_error:
                raise VapiPhoneReconciliationError(
                    "Vapi SIP endpoint creation could not be safely reconciled"
                ) from reconciliation_error
            if reconciled is None:
                raise VapiPhoneReconciliationError(
                    "Vapi SIP endpoint creation could not be safely reconciled"
                ) from error
            return reconciled
        if isinstance(value, Mapping) and vapi_phone_matches_intent(value, intent):
            return value
        response_id = value.get("id") if isinstance(value, Mapping) else None
        if isinstance(response_id, str) and RESOURCE_ID.fullmatch(response_id):
            try:
                exact = self.get("phone-number", response_id)
            except QualificationError as error:
                raise VapiPhoneReconciliationError(
                    "Vapi SIP endpoint creation could not be safely reconciled"
                ) from error
            if exact is not None:
                if not vapi_phone_matches_intent(exact, intent):
                    raise VapiPhoneReconciliationError(
                        "Vapi SIP endpoint creation returned a foreign identity"
                    )
                return exact
        try:
            reconciled = self._wait_for_phone_intent(
                intent, timeout=reconcile_timeout, poll_seconds=poll_seconds
            )
        except QualificationError as error:
            raise VapiPhoneReconciliationError(
                "Vapi SIP endpoint creation could not be safely reconciled"
            ) from error
        if reconciled is None:
            raise VapiPhoneReconciliationError(
                "Vapi SIP endpoint creation returned an invalid shape"
            )
        return reconciled

    def find_phone_for_intent(
        self, intent: Mapping[str, str]
    ) -> Mapping[str, Any] | None:
        phones = self.list("phone-number", limit=100)
        # A full bounded page cannot prove another same-name endpoint is absent.
        if len(phones) == 100:
            raise QualificationError(
                "Vapi SIP endpoint reconciliation exceeded its safe bound"
            )
        named = [phone for phone in phones if phone.get("name") == intent.get("name")]
        if not named:
            return None
        if len(named) != 1:
            raise QualificationError("Vapi SIP endpoint ownership is ambiguous")
        if not vapi_phone_matches_intent(named[0], intent):
            raise QualificationError("Vapi SIP endpoint name is already in use")
        return named[0]

    def _wait_for_phone_intent(
        self,
        intent: Mapping[str, str],
        *,
        timeout: int,
        poll_seconds: float,
    ) -> Mapping[str, Any] | None:
        deadline = time.monotonic() + timeout
        while True:
            phone = self.find_phone_for_intent(intent)
            if phone is not None:
                return phone
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(poll_seconds, remaining))

    def delete_phone(
        self,
        resource_id: str,
        intent: Mapping[str, str],
        *,
        timeout: int = 30,
        poll_seconds: float = 0.5,
    ) -> None:
        if not RESOURCE_ID.fullmatch(resource_id):
            raise QualificationError("Vapi resource ID is invalid")
        existing = self.get("phone-number", resource_id)
        if existing is None:
            return
        if not vapi_phone_matches_intent(existing, intent):
            raise QualificationError("Vapi phone deletion target is not owned")
        self.request("DELETE", f"/phone-number/{resource_id}", allow_missing=True)
        deadline = time.monotonic() + timeout
        while True:
            current = self.get("phone-number", resource_id)
            if current is None:
                return
            if not vapi_phone_matches_intent(current, intent):
                raise QualificationError("Vapi phone deletion target identity changed")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QualificationError("Vapi exact-resource deletion timed out")
            time.sleep(min(poll_seconds, remaining))

    def delete(
        self,
        resource: str,
        resource_id: str,
        *,
        timeout: int = 30,
        poll_seconds: float = 0.5,
    ) -> None:
        if resource == "phone-number":
            raise QualificationError(
                "Vapi phone deletion requires an exact ownership intent"
            )
        existing = self.get(resource, resource_id)
        if existing is None:
            return
        if existing.get("id") != resource_id:
            raise QualificationError("Vapi deletion target identity changed")
        self.request("DELETE", f"/{resource}/{resource_id}", allow_missing=True)
        deadline = time.monotonic() + timeout
        while True:
            current = self.get(resource, resource_id)
            if current is None:
                return
            if current.get("id") != resource_id:
                raise QualificationError("Vapi deletion target identity changed")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QualificationError("Vapi exact-resource deletion timed out")
            time.sleep(min(poll_seconds, remaining))


def extract_vapi_key(secret: str) -> str:
    try:
        value = json.loads(secret)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, Mapping):
        candidates = [value.get(name) for name in ("private_key", "privateKey", "key")]
        keys = [item for item in candidates if isinstance(item, str)]
        if len(keys) != 1:
            raise QualificationError(
                "Vapi secret JSON must contain one private key field"
            )
        secret = keys[0]
    if (
        not isinstance(secret, str)
        or not 8 <= len(secret) <= 1024
        or any(c.isspace() for c in secret)
    ):
        raise QualificationError("Vapi private key secret is invalid")
    return secret


def derive_correlation_id(
    key: str, execution_id: str, org_id: str, call_id: str
) -> str:
    for value in (execution_id, org_id, call_id):
        if not RESOURCE_ID.fullmatch(value):
            raise QualificationError("Vapi call identity is invalid")
    material = f"bridgefu|{execution_id}|{org_id}|{call_id}".encode("ascii")
    digest = hmac.new(key.encode("utf-8"), material, hashlib.sha256).digest()
    return "bf1_" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def session_hmac(value: Mapping[str, Any], key: str) -> str:
    unsigned = {name: field for name, field in value.items() if name != "session_hmac"}
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    return hmac.new(key.encode("utf-8"), encoded, hashlib.sha256).hexdigest()


def synthetic_context(scenario: str) -> dict[str, str]:
    issue = (
        "Qualification SIP transfer source hangup."
        if scenario == "vapi-sip-transfer"
        else "Qualification Bridgefu Web SDK source hangup."
    )
    return {
        "customer_name": CONTEXT["customer_name"],
        "issue_summary": issue,
        "intent": CONTEXT["intent"],
        "verification_status": CONTEXT["verification_status"],
    }


def qualification_field_schema() -> dict[str, Any]:
    descriptions = {
        "customer_name": "Synthetic customer name for the agent screen pop.",
        "issue_summary": "Short synthetic reason for the handoff.",
        "intent": "Synthetic qualification intent.",
        "verification_status": "Synthetic verification result.",
    }
    limits = {
        "customer_name": 256,
        "issue_summary": 1024,
        "intent": 256,
        "verification_status": 128,
    }
    expected = synthetic_context(WEB_SCENARIO)
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            key: {
                "type": "string",
                "description": descriptions[key],
                "minLength": 1,
                "maxLength": limits[key],
                "enum": [expected[key]],
            }
            for key in SCREEN_POP_KEYS
        },
        "required": list(SCREEN_POP_KEYS),
    }


def direct_context_item(
    *,
    correlation_id: str,
    token_id: str,
    binding: bridgefu_web_handoff.DirectRouteBinding,
    schema_hash: str,
    now: int,
) -> dict[str, dict[str, str]]:
    if (
        not re.fullmatch(r"bf1_[A-Za-z0-9_-]{43}", correlation_id)
        or not RESOURCE_ID.fullmatch(token_id)
        or not SHA256.fullmatch(schema_hash)
        or now <= 0
    ):
        raise QualificationError("direct handoff context identity is invalid")
    idempotency = (
        "bfq_"
        + hashlib.sha256(
            f"{correlation_id}|{binding.call_id}|{binding.destination_leg_id}".encode(
                "ascii"
            )
        ).hexdigest()[:32]
    )
    fields: dict[str, int | str] = {
        "schema_version": 2,
        "correlation_id": correlation_id,
        "created_at": now,
        "updated_at": now,
        "expires_at": now + 3600,
        "handoff_status": "MAPPED",
        "screen_pop_schema_hash": schema_hash,
        "direct_token_id": token_id,
        "bridgefu_call_id": binding.call_id,
        "direct_leg_id": binding.destination_leg_id,
        "direct_route_id": bridgefu_web_runtime.CONNECT_ROUTE_ID,
        "direct_idempotency_key": idempotency,
    }
    return {
        key: {"N": str(value)} if isinstance(value, int) else {"S": value}
        for key, value in fields.items()
    }


def make_session(
    *,
    execution_id: str,
    scenario: str,
    call: Mapping[str, Any],
    correlation_key: str,
    bridgefu_commit: str,
    release: str,
    sip_uri: str | None,
    source_call_id: str | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    vapi_call_id = call.get("id")
    org_id = call.get("orgId")
    if not isinstance(vapi_call_id, str) or not isinstance(org_id, str):
        raise QualificationError("Vapi call is missing its exact identity")
    effective_source_call_id = source_call_id or vapi_call_id
    if not RESOURCE_ID.fullmatch(effective_source_call_id):
        raise QualificationError("smoke source call identity is invalid")
    correlation = correlation_id or derive_correlation_id(
        correlation_key, execution_id, org_id, vapi_call_id
    )
    if not re.fullmatch(r"bf1_[A-Za-z0-9_-]{43}", correlation):
        raise QualificationError("smoke correlation identity is invalid")
    started = (
        call.get("createdAt") if isinstance(call.get("createdAt"), str) else utc_now()
    )
    value: dict[str, Any] = {
        "schema_version": 1,
        "execution_id": execution_id,
        "recipe": RECIPE,
        "release_id": hashlib.sha256(release.encode("ascii")).hexdigest()[:20],
        "source_tree_sha256": hashlib.sha256(
            bridgefu_commit.encode("ascii")
        ).hexdigest(),
        "image": f"bridgefu@sha256:{hashlib.sha256((release + bridgefu_commit).encode()).hexdigest()}",
        "session_id": hashlib.sha256(
            f"{scenario}:{effective_source_call_id}".encode()
        ).hexdigest()[:24],
        "scenario_id": scenario,
        "hangup_origin": "source",
        "security": "sips_optional_srtp",
        "codec": "negotiated" if scenario == WEB_SCENARIO else "pcmu",
        "network_profile": "baseline",
        "network_contract": {
            "delay_ms": 0,
            "jitter_ms": 0,
            "loss_percent": 0,
            "reorder_percent": 0,
        },
        "started_at": started,
        "started_epoch_ms": int(time.time() * 1000),
        "correlation_id": correlation,
        "correlation_fingerprint": sha256_bytes(correlation.encode("ascii"))[:12],
        "source_call_id": effective_source_call_id,
        "vapi_call_id": vapi_call_id,
        "source_org_id": org_id,
        "source_call_fingerprint": sha256_bytes(
            effective_source_call_id.encode("ascii")
        )[:12],
        "sip_uri": sip_uri,
        "sip_header": {"name": "X-Correlation-Id", "value": correlation},
        "expected_context": synthetic_context(scenario),
    }
    value["session_hmac"] = session_hmac(value, correlation_key)
    return value


def stack_outputs(value: Any) -> dict[str, str]:
    try:
        items = value["Stacks"][0]["Outputs"]
    except (KeyError, IndexError, TypeError) as error:
        raise QualificationError(
            "qualification stack outputs are unavailable"
        ) from error
    result = {
        item["OutputKey"]: item["OutputValue"]
        for item in items
        if isinstance(item, Mapping)
        and isinstance(item.get("OutputKey"), str)
        and isinstance(item.get("OutputValue"), str)
    }
    required = {
        "ConnectInstanceArn",
        "ConnectInstanceId",
        "ConnectLoginUrl",
        "AgentUsername",
        "AgentCredentialSecretArn",
        "BridgefuInstanceId",
        "ArtifactBucket",
        "VapiAssistantId",
        "VapiProvisioningStackId",
        "VapiPrepareUrl",
        "VapiTransferUrl",
        "VapiModel",
        "VapiVoiceId",
        "ScreenPopFieldsJson",
        "VapiPrepareToolId",
        "VapiWebhookCredentialId",
        "VapiWebhookSecretArn",
        "ProductVapiIdentityBindingArn",
        "HandoffTableName",
        "CorrelationKeySecretArn",
        "RuntimeLogGroupName",
        "LookupLogGroupName",
        "QualificationSipPrivateHostedZoneId",
        "DirectHandoffUrl",
        "DirectHandoffSigningKeyArn",
        "DirectVapiIdentityBindingArn",
        "DirectVapiSipAuthSecretArn",
        "BridgefuApiBearerSecretArn",
        "BridgefuPublicIp",
        "BridgefuGatewaySecurityGroupId",
        "ConnectWrapperFlowArn",
        "ScreenPopSchemaHash",
    }
    if not required.issubset(result):
        raise QualificationError("qualification stack is missing required outputs")
    return result


def decode_dynamo(value: Any) -> Any:
    if not isinstance(value, Mapping) or len(value) != 1:
        raise QualificationError("DynamoDB evidence has an invalid shape")
    kind, item = next(iter(value.items()))
    if kind == "S" and isinstance(item, str):
        return item
    if kind == "N" and isinstance(item, str):
        return int(item)
    if kind == "BOOL" and isinstance(item, bool):
        return item
    if kind == "M" and isinstance(item, Mapping):
        return {key: decode_dynamo(field) for key, field in item.items()}
    if kind == "L" and isinstance(item, list):
        return [decode_dynamo(field) for field in item]
    raise QualificationError("DynamoDB evidence contains an unsupported value")


def verify_handoff_item(item: Any, session: Mapping[str, Any]) -> Mapping[str, Any]:
    if not isinstance(item, Mapping):
        raise QualificationError("handoff context record was not found")
    decoded = {key: decode_dynamo(value) for key, value in item.items()}
    values = decoded.get("screen_pop_values")
    if not isinstance(values, Mapping):
        values = {
            key: decoded.get(key) for key in synthetic_context(session["scenario_id"])
        }
    if (
        decoded.get("correlation_id") != session.get("correlation_id")
        or values != session.get("expected_context")
        or decoded.get("handoff_status") not in {"RESERVED", "CONSUMED"}
    ):
        raise QualificationError("handoff context record does not match the smoke call")
    return decoded


def json_objects_from_logs(
    events: Iterable[Mapping[str, Any]],
) -> Iterable[Mapping[str, Any]]:
    for event in events:
        if not isinstance(event, Mapping):
            continue
        message = event.get("message")
        if not isinstance(message, str):
            continue
        seen: set[str] = set()
        for candidate in (message, *message.splitlines()):
            start = candidate.find("{")
            if start < 0:
                continue
            try:
                value = json.loads(candidate[start:])
            except json.JSONDecodeError:
                continue
            if isinstance(value, Mapping):
                value_key = json.dumps(value, separators=(",", ":"), sort_keys=True)
                if value_key not in seen:
                    seen.add(value_key)
                    yield value
                fields = value.get("fields")
                if isinstance(fields, Mapping):
                    fields_key = json.dumps(
                        fields, separators=(",", ":"), sort_keys=True
                    )
                    if fields_key not in seen:
                        seen.add(fields_key)
                        yield fields


def verify_log_evidence(
    runtime: Any,
    lookup: Any,
    fingerprint: str,
    sip_security: str,
    scenario: str = "vapi-sip-transfer",
) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{12}", fingerprint):
        raise QualificationError("correlation fingerprint is invalid")
    if scenario == WEB_SCENARIO:
        # Vapi's documented TLS listener is addressed as
        # sip:...:5061;transport=tls. URI scheme and transport are separate
        # evidence: the URI remains SIP while the trace must prove actual TLS.
        expected_uri_scheme = "sip"
        expected_event = VAPI_SOURCE_SECURITY_EVENT
        expected_leg = "bridgefu-to-vapi"
        expected_message = "established Bridgefu Vapi source leg"
    else:
        expected_uri_scheme = {
            "sips_optional_srtp": "sip",
            "sips_srtp": "sips",
        }.get(sip_security)
        expected_event = VAPI_DESTINATION_SECURITY_EVENT
        expected_leg = "vapi-to-bridgefu"
        expected_message = "accepted Vapi destination leg"
    if expected_uri_scheme is None:
        raise QualificationError("Vapi destination security policy is invalid")
    runtime_events = runtime.get("events", []) if isinstance(runtime, Mapping) else []
    lookup_events = lookup.get("events", []) if isinstance(lookup, Mapping) else []
    runtime_values = list(json_objects_from_logs(runtime_events))
    header = any(
        value.get("event") == "bridgefu_sip_invite_evidence"
        and value.get("correlation_fingerprint") == fingerprint
        and value.get("header_name") == "x-correlation-id"
        and value.get("header_count") == 1
        for value in runtime_values
    )
    available = any(
        value.get("event") == "bridgefu_correlation_evidence"
        and value.get("operation") == "connect_lookup"
        and value.get("correlation_fingerprint") == fingerprint
        and value.get("result") == "available"
        for value in json_objects_from_logs(lookup_events)
    )
    security_events = [
        value
        for value in runtime_values
        if value.get("event") == expected_event
        and value.get("correlation_fingerprint") == fingerprint
    ]
    if len(security_events) != 1:
        raise QualificationError(
            "exactly one correlated Vapi destination security event is required"
        )
    security_event = security_events[0]
    security_keys = set(security_event)
    if security_keys != VAPI_DESTINATION_SECURITY_FIELDS | {"message"}:
        raise QualificationError("Vapi destination security event shape is invalid")
    if security_event.get("message") != expected_message:
        raise QualificationError("Vapi destination security event shape is invalid")
    expected_security = {
        "event": expected_event,
        "leg": expected_leg,
        "signaling_transport": "tls",
        "answered": True,
        "redacted": True,
        "correlation_fingerprint": fingerprint,
        "uri_scheme": expected_uri_scheme,
    }
    media_profile = security_event.get("media_profile")
    media_keying = security_event.get("media_keying")
    media_suite = security_event.get("media_suite")
    inbound_srtp = security_event.get("inbound_srtp_context_installed")
    outbound_srtp = security_event.get("outbound_srtp_context_installed")
    secure_media = (
        media_profile == "RTP/SAVP"
        and media_keying == "SDES-SRTP"
        and media_suite in VAPI_DESTINATION_MEDIA_SUITES
        and inbound_srtp is True
        and outbound_srtp is True
    )
    plain_media = (
        media_profile == "RTP/AVP"
        and media_keying == "none"
        and media_suite == "none"
        and inbound_srtp is False
        and outbound_srtp is False
    )
    security = all(
        security_event.get(name) == expected
        for name, expected in expected_security.items()
    ) and (secure_media or plain_media)
    if scenario == WEB_SCENARIO:
        # The outbound event itself requires one exact redacted correlation
        # header on the TLS INVITE; the inbound admission-only event does not
        # exist for Bridgefu-originated Vapi legs.
        header = security
    if not header or not available or not security:
        raise QualificationError(
            "correlated Bridgefu, destination security, and Connect log evidence did not converge"
        )
    security_projection = {
        name: security_event[name] for name in sorted(VAPI_DESTINATION_SECURITY_FIELDS)
    }
    return {
        "bridgefu_received_correlation_header": header,
        "connect_lookup_available": available,
        "vapi_destination_uri_scheme_allowed": (
            security_event.get("uri_scheme") == expected_uri_scheme
        ),
        "vapi_destination_tls_transport": (
            security_event.get("signaling_transport") == "tls"
        ),
        "vapi_destination_media_profile_allowed": (
            media_profile in VAPI_DESTINATION_MEDIA_PROFILES
        ),
        "vapi_destination_media_posture_consistent": secure_media or plain_media,
        "vapi_destination_answered": security_event.get("answered") is True,
        "vapi_destination_security_evidence_sha256": canonical_sha256(
            security_projection
        ),
        "vapi_destination_media_profile": media_profile,
        "vapi_destination_media_keying": media_keying,
        "vapi_destination_media_suite": media_suite,
        "vapi_destination_srtp_negotiated": secure_media,
    }


def derive_scenario_checks(
    scenario: str,
    source: Mapping[str, Any],
    agent: Mapping[str, Any],
    call: Mapping[str, Any],
    handoff: Mapping[str, Any],
    log_proof: Mapping[str, Any],
) -> dict[str, bool]:
    """Derive release assertions only from the retained remote observations."""
    if scenario not in SCENARIOS:
        raise QualificationError("qualification scenario is unsupported")
    source_media = source.get("media")
    agent_media = agent.get("media")
    screen = agent.get("screen_pop")
    if not all(
        isinstance(value, Mapping) for value in (source_media, agent_media, screen)
    ):
        raise QualificationError("scenario evidence is incomplete")
    expected_fields = set(synthetic_context(scenario))
    screen_fields = screen.get("visible_fields")
    screen_visible = (
        screen.get("visible") is True
        and isinstance(screen_fields, list)
        and set(screen_fields) == expected_fields
    )
    source_to_agent = (
        int(source_media.get("source_to_agent_marker_frames_sent", 0)) >= 5
        and int(agent_media.get("source_to_agent_marker_frames", 0)) >= 5
        and len(agent_media.get("source_marker_observed_at_ms", [])) >= 3
    )
    agent_to_source = (
        int(agent_media.get("agent_to_source_marker_frames_sent", 0)) >= 5
        and int(source_media.get("agent_to_source_marker_frames", 0)) >= 3
        and len(source_media.get("agent_marker_observed_at_ms", [])) >= 3
    )
    dtmf_source_to_agent = (
        len(source_media.get("dtmf_source_to_agent_sent_at_ms", [])) >= 1
        and agent_media.get("dtmf_source_to_agent_observed") is True
    )
    if scenario == WEB_SCENARIO:
        source_connected = source.get("bridgefu", {}).get("webrtc_call_started") is True
        ended = source.get("hangup", {}).get("local_end_completed") is True
    else:
        signaling = source.get("signaling")
        source_connected = (
            isinstance(signaling, Mapping)
            and signaling.get("invite_sent") is True
            and signaling.get("answered") is True
        )
        ended = source.get("hangup", {}).get("local_bye_completed") is True
    checks = {
        "vapi_call_connected": source_connected and call.get("status") == "ended",
        "vapi_transfer_invoked": call_contains_transfer(call, scenario),
        "handoff_context_stored": (
            handoff.get("correlation_id") is not None
            and handoff.get("handoff_status") in {"RESERVED", "CONSUMED"}
        ),
        "bridgefu_received_correlation_header": (
            log_proof.get("bridgefu_received_correlation_header") is True
        ),
        "vapi_destination_uri_scheme_allowed": (
            log_proof.get("vapi_destination_uri_scheme_allowed") is True
        ),
        "vapi_destination_tls_transport": (
            log_proof.get("vapi_destination_tls_transport") is True
        ),
        "vapi_destination_media_profile_allowed": (
            log_proof.get("vapi_destination_media_profile_allowed") is True
        ),
        "vapi_destination_media_posture_consistent": (
            log_proof.get("vapi_destination_media_posture_consistent") is True
        ),
        "vapi_destination_answered": (
            log_proof.get("vapi_destination_answered") is True
        ),
        "amazon_connect_contact_connected": (
            screen_visible and source_to_agent and agent_to_source
        ),
        "configured_screen_pop_visible": screen_visible
        and log_proof.get("connect_lookup_available") is True,
        "audio_source_to_agent": source_to_agent,
        "audio_agent_to_source": agent_to_source,
        "dtmf_source_to_agent": dtmf_source_to_agent,
        "source_call_ended": ended
        and source.get("hangup", {}).get("cleanup_observed") is True,
    }
    if scenario == WEB_SCENARIO:
        checks["dtmf_agent_to_source"] = (
            len(agent_media.get("dtmf_agent_to_source_sent_at_ms", [])) >= 1
            and source_media.get("dtmf_agent_to_source_observed") is True
        )
    return checks


def call_contains_transfer(value: Any, scenario: str = "vapi-sip-transfer") -> bool:
    """Require the scenario's exact owned tool and terminal handoff behavior."""
    names: set[str] = set()
    transfer = False

    def walk(item: Any, depth: int = 0) -> None:
        nonlocal transfer
        if depth > 16:
            return
        if isinstance(item, Mapping):
            for key, child in item.items():
                if key in {"name", "functionName", "toolName"} and isinstance(
                    child, str
                ):
                    names.add(child)
                if key in {"type", "status", "endedReason"} and isinstance(child, str):
                    if "transfer" in child.lower():
                        transfer = True
                if key == "transfers" and isinstance(child, list) and child:
                    transfer = True
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item[:1000]:
                walk(child, depth + 1)

    walk(value)
    destination = value.get("destination") if isinstance(value, Mapping) else None
    transfers = value.get("transfers") if isinstance(value, Mapping) else None
    ended_reason = value.get("endedReason") if isinstance(value, Mapping) else None
    transfer = (
        transfer
        or isinstance(destination, Mapping)
        or isinstance(transfers, list)
        and len(transfers) > 0
        or ended_reason == "assistant-forwarded-call"
    )
    if not isinstance(value, Mapping) or value.get("status") != "ended":
        return False
    if scenario == WEB_SCENARIO:
        artifact = value.get("artifact")
        messages = artifact.get("messages") if isinstance(artifact, Mapping) else None
        if not isinstance(messages, list):
            return False
        calls: list[str] = []
        results: list[str] = []
        accepted_results = 0
        for message in messages:
            if not isinstance(message, Mapping):
                continue
            role = message.get("role")
            if role == "tool_calls":
                tool_calls = message.get("toolCalls", message.get("toolCallList", []))
                if not isinstance(tool_calls, list):
                    return False
                for tool_call in tool_calls:
                    if not isinstance(tool_call, Mapping):
                        return False
                    function = tool_call.get("function")
                    name = (
                        function.get("name")
                        if isinstance(function, Mapping)
                        else tool_call.get("name")
                    )
                    if not isinstance(name, str):
                        return False
                    calls.append(name)
            elif role == "tool_call_result":
                name = message.get("name", message.get("toolName"))
                if not isinstance(name, str):
                    return False
                results.append(name)
                if name != bridgefu_web_handoff.DIRECT_TOOL_NAME:
                    continue
                raw_result = message.get("result", message.get("content"))
                try:
                    result = (
                        json.loads(raw_result)
                        if isinstance(raw_result, str)
                        else raw_result
                    )
                except json.JSONDecodeError:
                    return False
                if isinstance(result, Mapping) and result.get("accepted") is True:
                    accepted_results += 1
        return (
            calls == [bridgefu_web_handoff.DIRECT_TOOL_NAME]
            and results == [bridgefu_web_handoff.DIRECT_TOOL_NAME]
            and accepted_results == 1
        )
    return "prepare_handoff" in names and "transferCall" in names and transfer


def create_failure_arguments(retain_on_failure: bool) -> list[str]:
    # The controller owns cleanup. Keeping rollback disabled until it has read
    # the stack events is what makes a normal failed run diagnosable; the
    # retain flag controls whether cleanup follows evidence capture.
    del retain_on_failure
    return ["--disable-rollback"]


def collect_cloudformation_failure_events(
    aws: Aws, stack_name: str, *, maximum_stacks: int = 8, maximum_events: int = 50
) -> tuple[list[dict[str, Any]], str | None]:
    """Collect sanitized root and nested-stack failures without physical IDs."""
    stack_arn = re.compile(
        rf"^arn:aws[-a-z0-9]*:cloudformation:{re.escape(aws.region)}:[0-9]{{12}}:"
        r"stack/[A-Za-z][-A-Za-z0-9]{0,127}/[A-Za-z0-9-]+$"
    )
    queue: list[tuple[str, int]] = [(stack_name, 0)]
    visited: set[str] = set()
    seen_events: set[str] = set()
    failures: list[dict[str, Any]] = []
    errors: list[str] = []
    while queue and len(visited) < maximum_stacks and len(failures) < maximum_events:
        identifier, depth = queue.pop(0)
        if identifier in visited:
            continue
        visited.add(identifier)
        try:
            response = aws.json(
                [
                    "cloudformation",
                    "describe-stack-events",
                    "--stack-name",
                    identifier,
                    "--max-items",
                    "100",
                ],
                timeout=120,
            )
        except QualificationError as error:
            errors.append(sanitize_diagnostic(str(error), 256))
            continue
        values = response.get("StackEvents") if isinstance(response, Mapping) else None
        if not isinstance(values, list):
            errors.append("CloudFormation stack events had an invalid shape")
            continue
        for item in values:
            if not isinstance(item, Mapping):
                continue
            event_id = item.get("EventId")
            status = item.get("ResourceStatus")
            logical_id = item.get("LogicalResourceId")
            resource_type = item.get("ResourceType")
            physical_id = item.get("PhysicalResourceId")
            if (
                resource_type == "AWS::CloudFormation::Stack"
                and isinstance(physical_id, str)
                and physical_id != identifier
                and logical_id != stack_name
                and stack_arn.fullmatch(physical_id)
                and physical_id not in visited
                and len(queue) + len(visited) < maximum_stacks
            ):
                queue.append((physical_id, depth + 1))
            if not isinstance(status, str) or not any(
                marker in status for marker in ("FAILED", "ROLLBACK", "CANCEL")
            ):
                continue
            dedupe = (
                event_id
                if isinstance(event_id, str)
                else "|".join(
                    str(item.get(key, ""))
                    for key in (
                        "LogicalResourceId",
                        "ResourceType",
                        "ResourceStatus",
                        "ResourceStatusReason",
                        "Timestamp",
                    )
                )
            )
            if dedupe in seen_events:
                continue
            seen_events.add(dedupe)
            failures.append(
                {
                    "stack_depth": depth,
                    "logical_resource_id": sanitize_diagnostic(logical_id, 256),
                    "resource_type": sanitize_diagnostic(resource_type, 256),
                    "status": sanitize_diagnostic(status, 128),
                    "reason": sanitize_diagnostic(
                        item.get("ResourceStatusReason"), 1024
                    ),
                    "timestamp": sanitize_diagnostic(item.get("Timestamp"), 64),
                }
            )
            if len(failures) == maximum_events:
                break
    return failures, sanitize_diagnostic("; ".join(errors), 512) if errors else None


def ensure_connect_agent_available(aws: Aws, outputs: Mapping[str, str]) -> None:
    """Select exactly the disposable agent's routable Available status."""
    instance_id = outputs.get("ConnectInstanceId")
    instance_arn = outputs.get("ConnectInstanceArn")
    username = outputs.get("AgentUsername")
    arn_match = re.fullmatch(
        rf"arn:aws[-a-z0-9]*:connect:{re.escape(aws.region)}:[0-9]{{12}}:"
        rf"instance/({re.escape(instance_id or '')})",
        instance_arn or "",
    )
    if (
        arn_match is None
        or not isinstance(instance_id, str)
        or not RESOURCE_ID.fullmatch(instance_id)
        or username != "bridgefu-demo-agent"
    ):
        raise QualificationError(
            "Connect availability target is not the exact disposable agent"
        )
    users = aws.json(
        [
            "connect",
            "list-users",
            "--instance-id",
            instance_id,
            "--max-results",
            "100",
        ]
    )
    statuses = aws.json(
        [
            "connect",
            "list-agent-statuses",
            "--instance-id",
            instance_id,
            "--max-results",
            "100",
        ]
    )
    user_summaries = (
        users.get("UserSummaryList") if isinstance(users, Mapping) else None
    )
    status_summaries = (
        statuses.get("AgentStatusSummaryList")
        if isinstance(statuses, Mapping)
        else None
    )
    if not isinstance(user_summaries, list) or not isinstance(status_summaries, list):
        raise QualificationError("Connect availability lookup did not return lists")
    user_matches = [
        item
        for item in user_summaries
        if isinstance(item, Mapping)
        and item.get("Username") == username
        and isinstance(item.get("Arn"), str)
        and isinstance(item.get("Id"), str)
        and RESOURCE_ID.fullmatch(item["Id"])
        and item["Arn"] == f"{instance_arn}/agent/{item['Id']}"
    ]
    status_matches = [
        item
        for item in status_summaries
        if isinstance(item, Mapping)
        and item.get("Name") == "Available"
        and item.get("Type") == "ROUTABLE"
        and isinstance(item.get("Arn"), str)
        and isinstance(item.get("Id"), str)
        and RESOURCE_ID.fullmatch(item["Id"])
        and item["Arn"] == f"{instance_arn}/agent-state/{item['Id']}"
    ]
    if len(user_matches) != 1 or len(status_matches) != 1:
        raise QualificationError("Connect availability lookup was not exact")
    status, _, stderr = aws.runner.probe(
        [
            "aws",
            "connect",
            "put-user-status",
            "--instance-id",
            instance_id,
            "--user-id",
            user_matches[0]["Id"],
            "--agent-status-id",
            status_matches[0]["Id"],
            "--region",
            aws.region,
            "--output",
            "json",
            "--no-cli-pager",
        ],
        timeout=60,
    )
    already_available = (
        status != 0
        and "InvalidRequestException" in stderr
        and "User already in requested status" in stderr
    )
    if status != 0 and not already_available:
        raise QualificationError(
            "Connect could not set the generated agent Available: "
            + sanitize_diagnostic(stderr)
        )


def wait_for_ssm_command(
    aws: Aws,
    command_id: str,
    instance_id: str,
    *,
    timeout: int,
    poll_seconds: float = 2.0,
) -> None:
    """Wait for the exact invocation without the AWS CLI waiter's short cap."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            invocation = aws.json(
                [
                    "ssm",
                    "get-command-invocation",
                    "--command-id",
                    command_id,
                    "--instance-id",
                    instance_id,
                ]
            )
        except QualificationError as error:
            # SSM acknowledges SendCommand before the per-instance invocation
            # is guaranteed readable. Only that exact eventual-consistency
            # response is retryable; authorization and transport errors fail.
            if "InvocationDoesNotExist" not in str(error):
                raise
            invocation = {"Status": "Pending"}
        status = invocation.get("Status") if isinstance(invocation, Mapping) else None
        if status == "Success":
            return
        if status in {"Cancelled", "Cancelling", "Failed", "TimedOut"}:
            detail = sanitize_diagnostic(invocation.get("StandardErrorContent"))
            raise QualificationError(
                f"qualification SSM command ended with {status}: {detail}"
            )
        if status not in {"Pending", "InProgress", "Delayed"}:
            raise QualificationError("qualification SSM command status is invalid")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise QualificationError("qualification SSM command timed out")
        time.sleep(min(poll_seconds, remaining))


def encode_ssm_shell_parameters(commands: list[str]) -> str:
    """Encode the exact AWS-RunShellScript command-array contract."""
    if (
        not isinstance(commands, list)
        or not commands
        or len(commands) > 1024
        or sum(len(command.encode("utf-8")) + 1 for command in commands) > 60 * 1024
        or any(
            not isinstance(command, str)
            or not command
            or "\n" in command
            or "\r" in command
            or len(command.encode("utf-8")) > 8192
            for command in commands
        )
    ):
        raise QualificationError("qualification SSM program is invalid")
    return json.dumps({"commands": commands}, separators=(",", ":"))


def read_ssm_output(
    aws: Aws, command_id: str, instance_id: str, *, maximum: int = 16 * 1024
) -> str:
    invocation = aws.json(
        [
            "ssm",
            "get-command-invocation",
            "--command-id",
            command_id,
            "--instance-id",
            instance_id,
        ]
    )
    raw = (
        invocation.get("StandardOutputContent")
        if isinstance(invocation, Mapping)
        else None
    )
    if (
        not isinstance(invocation, Mapping)
        or invocation.get("Status") != "Success"
        or not isinstance(raw, str)
        or not 2 <= len(raw.encode("utf-8")) <= maximum
    ):
        raise QualificationError("qualification SSM output is unavailable")
    return raw


def read_ssm_json_output(
    aws: Aws, command_id: str, instance_id: str, *, maximum: int = 16 * 1024
) -> Mapping[str, Any]:
    raw = read_ssm_output(aws, command_id, instance_id, maximum=maximum)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise QualificationError("qualification SSM JSON output is invalid") from error
    if not isinstance(value, Mapping):
        raise QualificationError("qualification SSM JSON output shape is invalid")
    return value


def cancel_and_wait_ssm_terminal(
    aws: Aws,
    command_id: str,
    instance_id: str,
    *,
    timeout: int = 90,
    poll_seconds: float = 1.0,
) -> bool:
    """Cancel an owned active command and prove its exact invocation terminal."""
    terminal = {"Success", "Cancelled", "Failed", "TimedOut"}
    active = {"Pending", "InProgress", "Delayed", "Cancelling"}
    deadline = time.monotonic() + timeout
    cancellation_ok = True
    cancellation_attempted = False
    while True:
        try:
            invocation = aws.json(
                [
                    "ssm",
                    "get-command-invocation",
                    "--command-id",
                    command_id,
                    "--instance-id",
                    instance_id,
                ]
            )
            status = (
                invocation.get("Status") if isinstance(invocation, Mapping) else None
            )
        except QualificationError as error:
            if "InvocationDoesNotExist" not in str(error):
                return False
            status = "Pending"
        if status in terminal:
            return cancellation_ok
        if status not in active:
            return False
        if status != "Cancelling" and not cancellation_attempted:
            cancellation_attempted = True
            try:
                aws.text(["ssm", "cancel-command", "--command-id", command_id])
            except QualificationError:
                cancellation_ok = False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(poll_seconds, remaining))


def wait_for_vapi_phone_active(
    vapi: Vapi,
    phone_id: str,
    sip_uri: str,
    assistant_id: str,
    *,
    timeout: int = 60,
    poll_seconds: float = 0.5,
) -> Mapping[str, Any]:
    """Poll the exact transient endpoint instead of assuming propagation time."""
    if not all(
        isinstance(value, str) and RESOURCE_ID.fullmatch(value)
        for value in (phone_id, assistant_id)
    ):
        raise QualificationError("temporary Vapi SIP endpoint identity is invalid")
    deadline = time.monotonic() + timeout
    while True:
        phone = vapi.get("phone-number", phone_id)
        if phone is not None:
            if (
                phone.get("id") != phone_id
                or phone.get("sipUri") != sip_uri
                or phone.get("assistantId") != assistant_id
            ):
                raise QualificationError(
                    "temporary Vapi SIP endpoint changed identity while provisioning"
                )
            status = phone.get("status")
            if status == "active":
                return phone
            if status not in {"pending", "provisioning", "creating"}:
                raise QualificationError(
                    "temporary Vapi SIP endpoint entered terminal status: "
                    + sanitize_diagnostic(status, 128)
                )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise QualificationError("temporary Vapi SIP endpoint activation timed out")
        time.sleep(min(poll_seconds, remaining))


class Controller:
    def __init__(
        self, args: argparse.Namespace, runner: CommandRunner | None = None
    ) -> None:
        self.args = args
        self.runner = runner or CommandRunner()
        self.aws = Aws(args.region, self.runner)
        self.stack_name = f"bridgefu-{args.execution_id}"
        self.work = Path(tempfile.mkdtemp(prefix=f".{args.execution_id}."))
        self.work.chmod(0o700)
        self.outputs: dict[str, str] = {}
        self.vapi: Vapi | None = None
        self.temp_phone_id: str | None = None
        self.temp_phone_intent: dict[str, str] | None = None
        self.temp_phone_creation_ambiguous = False
        self.temp_sip_auth_object: str | None = None
        self.temp_phone_intent_journal_object: str | None = None
        self.temp_phone_request_journal_object: str | None = None
        self.temp_phone_journal_object: str | None = None
        self.direct_tool_id: str | None = None
        self.direct_tool_prompt_sha256: str | None = None
        self.direct_tool_desired: dict[str, Any] | None = None
        self.direct_tool_creation_ambiguous = False
        self.direct_tool_intent: dict[str, Any] | None = None
        self.direct_tool_intent_journal_object: str | None = None
        self.direct_tool_request_journal_object: str | None = None
        self.direct_tool_journal_object: str | None = None
        self.direct_assistant_id: str | None = None
        self.direct_assistant_desired: dict[str, Any] | None = None
        self.direct_assistant_creation_ambiguous = False
        self.direct_assistant_intent: dict[str, Any] | None = None
        self.direct_assistant_intent_journal_object: str | None = None
        self.direct_assistant_request_journal_object: str | None = None
        self.direct_assistant_journal_object: str | None = None
        self.direct_vapi_cleanup_required = False
        self.direct_identity_binding_installed = False
        self.product_assistant_sha256: str | None = None
        self.direct_context_correlation_id: str | None = None
        self.web_runtime_object_key: str | None = None
        self.web_runtime_cleanup_required = False
        self.web_runtime_restoration_passed = False
        self.web_runtime_media_permission: dict[str, Any] | None = None
        self.web_runtime_secret_written = False
        self.acm_validation_journal: dict[str, Any] | None = None
        self.acm_validation_journal_object: str | None = None
        self.acm_validation_discovery_complete = False
        self.demo_site: Path | None = None
        self.demo_site_sha256: str | None = None
        self.created_stack = False
        self.processes: list[subprocess.Popen[str]] = []
        self.ssm_commands: list[str] = []
        self.started_at = utc_now()
        self.phase = "initialization"
        self.scenario_evidence: list[dict[str, Any]] = []
        self.secure_preflight_evidence: dict[str, Any] | None = None
        self.vapi_provisioning_resilience_evidence: dict[str, Any] | None = None
        self.vapi_provisioning_cleanup_required = False
        self.secure_preflight_binary_sha256: str | None = None
        self.secure_preflight_object_key: str | None = None
        self.secure_preflight_cleanup_required = False
        self.secure_preflight_restoration_passed = False
        self.secure_preflight_cleanup_passed = False
        self.bridgefu_lock = read_json(ROOT / "bridgefu.lock.json")

    def validate_inputs(self) -> None:
        if not EXECUTION_ID.fullmatch(self.args.execution_id):
            raise QualificationError("execution ID is invalid")
        if self.args.region not in REGIONS or not VERSION.fullmatch(self.args.release):
            raise QualificationError("release version or region is invalid")
        if not re.fullmatch(r"[A-Z0-9]{1,64}", self.args.hosted_zone_id):
            raise QualificationError("hosted zone ID is invalid")
        hosted_zone_name = self.args.hosted_zone_name.rstrip(".").lower()
        if (
            len(hosted_zone_name) > 253
            or re.fullmatch(
                r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                hosted_zone_name,
            )
            is None
        ):
            raise QualificationError("hosted zone name is invalid")
        if not re.fullmatch(
            r"arn:aws[-a-z0-9]*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}",
            self.args.cloudformation_role_arn,
        ):
            raise QualificationError("CloudFormation service role ARN is invalid")
        parsed = urllib.parse.urlsplit(self.args.template_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise QualificationError("qualification template URL must be HTTPS")
        if not self.args.sip_client.is_file() or self.args.sip_client.is_symlink():
            raise QualificationError("release SIP client binary is unavailable")
        if not isinstance(self.args.demo_site_archive, Path):
            raise QualificationError("demo site archive is unavailable")
        if not isinstance(self.args.demo_site_sha256, str) or not SHA256.fullmatch(
            self.args.demo_site_sha256
        ):
            raise QualificationError("demo site archive digest is invalid")
        self.secure_preflight_binary_sha256 = executable_sha256(
            self.args.direct_secure_probe
        )
        commit = self.bridgefu_lock.get("commit")
        lock_digest = self.bridgefu_lock.get("cargo_lock_sha256")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise QualificationError("Bridgefu source lock is invalid")
        if not isinstance(lock_digest, str) or not SHA256.fullmatch(lock_digest):
            raise QualificationError("Bridgefu Cargo lock digest is invalid")
        if not self.args.bridgefu_checkout.is_dir():
            raise QualificationError("pinned Bridgefu checkout is unavailable")
        if shutil.which("session-manager-plugin") is None:
            raise QualificationError("AWS Session Manager plugin is unavailable")

    def preflight(self) -> None:
        if self.aws.exists(
            ["cloudformation", "describe-stacks", "--stack-name", self.stack_name]
        ):
            raise QualificationError("execution stack already exists")
        instances = self.aws.json(["connect", "list-instances", "--max-results", "100"])
        aliases = {
            item.get("InstanceAlias")
            for item in instances.get("InstanceSummaryList", [])
            if isinstance(item, Mapping)
        }
        if f"{self.args.execution_id}-connect" in aliases:
            raise QualificationError("execution Connect instance already exists")

    def initialize_vapi(self) -> None:
        """Read and bind the Vapi credential only after secure runtime restoration."""
        private_key = extract_vapi_key(self.aws.secret(self.args.vapi_secret_arn))
        self.vapi = Vapi(private_key)
        owned_assistants = []
        for assistant in self.vapi.list("assistant"):
            metadata = assistant.get("metadata")
            if (
                isinstance(metadata, Mapping)
                and metadata.get("bridgefu_deployment") == self.args.execution_id
            ):
                owned_assistants.append(assistant)
        if len(owned_assistants) != 1 or owned_assistants[0].get(
            "id"
        ) != self.outputs.get("VapiAssistantId"):
            raise QualificationError("execution Vapi assistant identity is not exact")
        phone_name_prefix = f"BFQ {self.args.execution_id} "
        if any(
            isinstance(phone.get("name"), str)
            and phone["name"].startswith(phone_name_prefix)
            for phone in self.vapi.list("phone-number")
        ):
            raise QualificationError("execution Vapi SIP endpoint already exists")

    def provisioning_config(self) -> ProvisioningConfig:
        """Reconstruct the exact stack-owned Vapi desired state in memory."""
        return ProvisioningConfig(
            stack_id=self.outputs["VapiProvisioningStackId"],
            deployment_id=self.args.execution_id,
            prepare_url=self.outputs["VapiPrepareUrl"],
            transfer_url=self.outputs["VapiTransferUrl"],
            model=self.outputs["VapiModel"],
            voice_id=self.outputs["VapiVoiceId"],
            screen_pop_fields_json=self.outputs["ScreenPopFieldsJson"],
            webhook_token=self.aws.secret(self.outputs["VapiWebhookSecretArn"]),
            asset_root=ROOT / "vapi",
        )

    def vapi_provisioning_resilience(self) -> None:
        """Prove delete/recreate and lost-POST reconciliation against live Vapi."""
        if (
            self.temp_phone_id is not None
            or getattr(self, "temp_phone_intent", None) is not None
            or getattr(self, "direct_identity_binding_installed", False)
            or getattr(self, "direct_assistant_id", None) is not None
            or getattr(self, "direct_tool_id", None) is not None
            or getattr(self, "web_runtime_cleanup_required", False)
        ):
            raise QualificationError(
                "Vapi provisioning resilience requires clean smoke transients"
            )
        config = self.provisioning_config()
        api_key = extract_vapi_key(self.aws.secret(self.args.vapi_secret_arn))
        client = VapiHttpClient(api_key)
        current_physical_id = (
            "bridgefu-vapi-v2:"
            f"{self.outputs['VapiAssistantId']}:"
            f"{self.outputs['VapiPrepareToolId']}:"
            f"{self.outputs['VapiWebhookCredentialId']}"
        )
        try:
            self.vapi_provisioning_cleanup_required = True
            provision_delete(client, config, current_physical_id)
            ambiguous_client = LostAssistantCreateResponseClient(client)
            first = provision_create(ambiguous_client, config)
            self.outputs["VapiAssistantId"] = first.assistant_id
            self.outputs["VapiPrepareToolId"] = first.prepare_tool_id
            self.outputs["VapiWebhookCredentialId"] = first.webhook_credential_id
            first_verified = provision_create(client, config)
            if (
                not ambiguous_client.injected
                or first_verified.physical_id != first.physical_id
            ):
                raise VapiProvisioningError("vapi_resilience_reconciliation_failed")

            provision_delete(client, config, first.physical_id)
            if any(
                client.get(resource, resource_id) is not None
                for resource, resource_id in (
                    ("assistant", first.assistant_id),
                    ("tool", first.prepare_tool_id),
                    ("credential", first.webhook_credential_id),
                )
            ):
                raise VapiProvisioningError("vapi_resilience_delete_failed")

            second = provision_create(client, config)
            self.outputs["VapiAssistantId"] = second.assistant_id
            self.outputs["VapiPrepareToolId"] = second.prepare_tool_id
            self.outputs["VapiWebhookCredentialId"] = second.webhook_credential_id
            second_verified = provision_create(client, config)
            if second_verified.physical_id != second.physical_id:
                raise VapiProvisioningError("vapi_resilience_recreate_failed")
        except VapiProvisioningError as error:
            raise QualificationError("Vapi provisioning resilience failed") from error

        self.vapi_provisioning_resilience_evidence = {
            "schema_version": 1,
            "producer": "bridgefu-vapi-provisioning-resilience@1",
            "ambiguous_create_reconciled": True,
            "first_cycle_deleted": True,
            "second_cycle_recreated": True,
            "exact_owner_resources_present": True,
            "redacted": True,
            "passed": True,
        }

    def cleanup_vapi_provisioning_resilience(self) -> list[str]:
        """Delete the recreated exact-owner resources before stack teardown."""
        if not getattr(self, "vapi_provisioning_cleanup_required", False):
            return []
        try:
            config = self.provisioning_config()
            api_key = extract_vapi_key(self.aws.secret(self.args.vapi_secret_arn))
            client = VapiHttpClient(api_key)
            current = provision_create(client, config)
            self.outputs["VapiAssistantId"] = current.assistant_id
            self.outputs["VapiPrepareToolId"] = current.prepare_tool_id
            self.outputs["VapiWebhookCredentialId"] = current.webhook_credential_id
            provision_delete(client, config, current.physical_id)
            if any(
                client.get(resource, resource_id) is not None
                for resource, resource_id in (
                    ("assistant", current.assistant_id),
                    ("tool", current.prepare_tool_id),
                    ("credential", current.webhook_credential_id),
                )
            ):
                raise VapiProvisioningError("vapi_resilience_cleanup_failed")
            self.vapi_provisioning_cleanup_required = False
        except (QualificationError, VapiProvisioningError):
            return ["Vapi provisioning resilience cleanup failed"]
        return []

    def initialize_cleanup_vapi_verifier(self) -> None:
        """Bind a read-only exact-ID verifier even after an early run failure."""
        ids = (
            self.outputs.get("VapiAssistantId"),
            self.outputs.get("VapiPrepareToolId"),
            self.outputs.get("VapiWebhookCredentialId"),
            self.temp_phone_id,
            getattr(self, "direct_assistant_id", None),
            getattr(self, "direct_tool_id", None),
        )
        phone_intent_exists = (
            getattr(self, "temp_phone_intent", None) is not None
            or getattr(self, "temp_phone_creation_ambiguous", False)
            or getattr(self, "temp_phone_intent_journal_object", None) is not None
            or getattr(self, "temp_phone_request_journal_object", None) is not None
        )
        if self.vapi is None and (
            any(isinstance(item, str) for item in ids) or phone_intent_exists
        ):
            private_key = extract_vapi_key(self.aws.secret(self.args.vapi_secret_arn))
            self.vapi = Vapi(private_key)

    def ensure_acm_validation_journal(self) -> None:
        """Seal exact public DNS ownership before deleting any stack resource."""
        if self.acm_validation_discovery_complete:
            return
        if not self.created_stack:
            self.acm_validation_discovery_complete = True
            return
        if not self.aws.exists(
            ["cloudformation", "describe-stacks", "--stack-name", self.stack_name]
        ):
            raise QualificationError(
                "qualification stack disappeared before ACM ownership was sealed"
            )
        description = self.aws.json(
            ["cloudformation", "describe-stacks", "--stack-name", self.stack_name],
            timeout=120,
        )
        stacks = description.get("Stacks") if isinstance(description, Mapping) else None
        stack_status = (
            stacks[0].get("StackStatus")
            if isinstance(stacks, list)
            and len(stacks) == 1
            and isinstance(stacks[0], Mapping)
            else None
        )
        if not isinstance(stack_status, str):
            raise QualificationError("qualification stack status is invalid")
        sip_hostname = (
            f"{self.args.execution_id}.{self.args.hosted_zone_name.rstrip('.')}"
        )
        journal = discover_acm_validation_ownership(
            self.aws,
            self.stack_name,
            self.args.execution_id,
            self.args.hosted_zone_id,
            sip_hostname,
        )
        if journal is None:
            if stack_status.endswith("_IN_PROGRESS"):
                raise QualificationError(
                    "qualification ACM ownership is not stable while stack changes"
                )
            self.acm_validation_discovery_complete = True
            return
        bucket = self.outputs.get("ArtifactBucket") or discover_stack_output(
            self.aws, self.stack_name, "ArtifactBucket"
        )
        if not isinstance(bucket, str) or not S3_BUCKET.fullmatch(bucket):
            raise QualificationError(
                "qualification artifact bucket is unavailable for ACM ownership"
            )
        target = (
            f"s3://{bucket}/qualification/{self.args.execution_id}/"
            "ownership/acm-validation-records.json"
        )
        self.acm_validation_journal = dict(journal)
        self.acm_validation_journal_object = target
        private_json(self.args.output / "acm-validation-ownership.json", journal)
        self.runner.run(
            [
                "aws",
                "s3",
                "cp",
                "-",
                target,
                "--sse",
                "AES256",
                "--only-show-errors",
                "--region",
                self.args.region,
            ],
            input_text=json.dumps(journal, separators=(",", ":"), sort_keys=True),
            timeout=120,
        )
        self.acm_validation_discovery_complete = True

    def deploy(self) -> None:
        hostname = f"{self.args.execution_id}.{self.args.hosted_zone_name.rstrip('.')}"
        parameters = [
            ("DeploymentId", self.args.execution_id),
            ("VapiApiKeySecretArn", self.args.vapi_secret_arn),
            ("PublicHostedZoneId", self.args.hosted_zone_id),
            ("SipHostname", hostname),
            ("InstanceType", self.args.instance_type),
        ]
        arguments = [
            "cloudformation",
            "create-stack",
            "--stack-name",
            self.stack_name,
            "--template-url",
            self.args.template_url,
            "--capabilities",
            "CAPABILITY_NAMED_IAM",
            "--role-arn",
            self.args.cloudformation_role_arn,
            *create_failure_arguments(self.args.retain_on_failure),
            "--parameters",
            *[
                f"ParameterKey={key},ParameterValue={value}"
                for key, value in parameters
            ],
        ]
        self.aws.json(arguments, timeout=120)
        self.created_stack = True
        self.aws.text(
            [
                "cloudformation",
                "wait",
                "stack-create-complete",
                "--stack-name",
                self.stack_name,
            ],
            timeout=3600,
        )
        description = self.aws.json(
            ["cloudformation", "describe-stacks", "--stack-name", self.stack_name]
        )
        self.outputs = stack_outputs(description)
        self.ensure_acm_validation_journal()
        self.wait_for_runtime()

    def wait_for_runtime(self) -> None:
        command_id = self.aws.text(
            [
                "ssm",
                "send-command",
                "--instance-ids",
                self.outputs["BridgefuInstanceId"],
                "--document-name",
                "AWS-RunShellScript",
                "--parameters",
                encode_ssm_shell_parameters(
                    [
                        "systemctl is-active bridgefu.service",
                        "curl --fail --silent --show-error --max-time 5 "
                        "http://127.0.0.1:9090/readyz",
                    ]
                ),
                "--query",
                "Command.CommandId",
            ]
        )
        wait_for_ssm_command(
            self.aws,
            command_id,
            self.outputs["BridgefuInstanceId"],
            timeout=300,
        )

    def build_site(self) -> tuple[Path, str]:
        """Verify all local immutable inputs before the first AWS API call."""
        checkout = self.args.bridgefu_checkout.resolve()
        expected_commit = self.bridgefu_lock["commit"]
        actual_commit = self.runner.run(
            ["git", "rev-parse", "HEAD"], cwd=checkout, timeout=30
        ).strip()
        if actual_commit != expected_commit:
            raise QualificationError("Bridgefu checkout is not at the pinned commit")
        if (
            sha256_file(checkout / "Cargo.lock")
            != self.bridgefu_lock["cargo_lock_sha256"]
        ):
            raise QualificationError(
                "Bridgefu Cargo.lock does not match the source lock"
            )
        site, digest = prepare_demo_site_archive(
            self.args.demo_site_archive.resolve(),
            self.args.demo_site_sha256,
            self.work / "site",
        )
        self.demo_site = site
        self.demo_site_sha256 = digest
        return site, digest

    def authenticate_agent(self) -> Path:
        credential = self.aws.secret(self.outputs["AgentCredentialSecretArn"])
        try:
            parsed = json.loads(credential)
        except json.JSONDecodeError as error:
            raise QualificationError(
                "Connect agent credential secret is invalid"
            ) from error
        if not isinstance(parsed, Mapping) or set(parsed) != {"username", "password"}:
            raise QualificationError(
                "Connect agent credential secret has an invalid shape"
            )
        storage = self.work / "connect-storage.json"
        process = self.runner.popen(
            [
                "node",
                os.fspath(QUALIFICATION / "browser" / "agent-workspace-playwright.mjs"),
                "auth",
                "--connect-url",
                self.outputs["ConnectLoginUrl"],
                "--storage-state",
                os.fspath(storage),
                "--timeout-seconds",
                "180",
                "--credential-stdin",
            ]
        )
        self.processes.append(process)
        stdout, stderr = process.communicate(json.dumps(parsed), timeout=240)
        if (
            process.returncode != 0
            or not storage.is_file()
            or stdout.strip() != os.fspath(storage)
        ):
            raise QualificationError(
                "Amazon Connect agent authentication failed: "
                + sanitize_diagnostic(stderr)
            )
        self.processes.remove(process)
        return storage

    def wait_for_process_file(
        self,
        process: subprocess.Popen[str],
        path: Path,
        timeout: int,
        label: str,
    ) -> Any:
        """Wait for a browser readiness file while retaining bounded failure detail."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.is_file():
                return read_private_json(path)
            if process.poll() is not None:
                _, stderr = process.communicate(timeout=10)
                if process in self.processes:
                    self.processes.remove(process)
                raise QualificationError(
                    f"{label} exited before readiness: "
                    + sanitize_diagnostic(stderr, 512)
                )
            time.sleep(0.25)
        _, stderr = terminate_owned_process(process)
        if process in self.processes:
            self.processes.remove(process)
        raise QualificationError(
            f"{label} readiness timed out: " + sanitize_diagnostic(stderr, 512)
        )

    def start_agent(
        self, session: Path, storage: Path, scenario: str
    ) -> tuple[subprocess.Popen[str], Path, Path, Path]:
        ready = self.work / f"{scenario}-agent-ready.json"
        observation = self.work / f"{scenario}-agent.json"
        screenshot = self.args.output / f"{scenario}-screen.png"
        process = self.runner.popen(
            [
                "node",
                os.fspath(QUALIFICATION / "browser" / "agent-workspace-playwright.mjs"),
                "observe",
                "--session",
                os.fspath(session),
                "--execution-id",
                self.args.execution_id,
                "--scenario-id",
                scenario,
                "--storage-state",
                os.fspath(storage),
                "--connect-url",
                self.outputs["ConnectLoginUrl"],
                "--screenshot",
                os.fspath(screenshot),
                "--ready",
                os.fspath(ready),
                "--observation",
                os.fspath(observation),
                "--timeout-seconds",
                "240",
            ]
        )
        self.processes.append(process)
        return process, observation, screenshot, ready

    def wait_for_agent_readiness(
        self, process: subprocess.Popen[str], ready: Path, scenario: str
    ) -> None:
        validate_agent_readiness(
            self.wait_for_process_file(
                process,
                ready,
                BROWSER_READINESS_TIMEOUT_SECONDS,
                "Amazon Connect smoke observer",
            ),
            self.args.execution_id,
            scenario,
        )

    def start_direct_secure_agent(
        self, storage: Path
    ) -> tuple[subprocess.Popen[str], Path]:
        """Launch the session-free observer and wait for its private readiness."""
        ready = self.work / "direct-secure-agent-ready.json"
        observation = self.work / "direct-secure-agent.json"
        process = self.runner.popen(
            [
                "node",
                os.fspath(QUALIFICATION / "browser" / "agent-workspace-playwright.mjs"),
                "observe-direct-secure",
                "--storage-state",
                os.fspath(storage),
                "--connect-url",
                self.outputs["ConnectLoginUrl"],
                "--ready",
                os.fspath(ready),
                "--observation",
                os.fspath(observation),
                "--timeout-seconds",
                "180",
            ]
        )
        self.processes.append(process)
        readiness = self.wait_for_process_file(
            process,
            ready,
            BROWSER_READINESS_TIMEOUT_SECONDS,
            "Amazon Connect direct secure observer",
        )
        validate_direct_agent_readiness(readiness)
        return process, observation

    def complete_process(
        self, process: subprocess.Popen[str], label: str, timeout: int = 300
    ) -> None:
        try:
            _, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            terminate_owned_process(process)
            raise QualificationError(f"{label} timed out")
        if process.returncode != 0:
            raise QualificationError(f"{label} failed: {sanitize_diagnostic(stderr)}")
        if process in self.processes:
            self.processes.remove(process)

    def send_owned_shell(self, instance_id: str, script: str) -> str:
        commands = [command for command in script.splitlines() if command]
        if "\r" in script:
            raise QualificationError("qualification SSM program is invalid")
        command_id = self.aws.text(
            [
                "ssm",
                "send-command",
                "--instance-ids",
                instance_id,
                "--document-name",
                "AWS-RunShellScript",
                "--parameters",
                encode_ssm_shell_parameters(commands),
                "--query",
                "Command.CommandId",
            ]
        )
        if not RESOURCE_ID.fullmatch(command_id):
            raise QualificationError("qualification SSM command ID is invalid")
        self.ssm_commands.append(command_id)
        return command_id

    def direct_secure_preflight(self, storage: Path) -> None:
        """Gate both release smokes on a restored direct SIPS/SDES-SRTP call."""
        digest = self.secure_preflight_binary_sha256
        bucket = self.outputs.get("ArtifactBucket")
        instance = self.outputs.get("BridgefuInstanceId")
        if (
            not isinstance(digest, str)
            or not SHA256.fullmatch(digest)
            or not isinstance(bucket, str)
            or not S3_BUCKET.fullmatch(bucket)
            or not isinstance(instance, str)
            or not RESOURCE_ID.fullmatch(instance)
        ):
            raise QualificationError("direct secure preflight target is invalid")
        if executable_sha256(self.args.direct_secure_probe) != digest:
            raise QualificationError(
                "direct secure probe binary changed after input validation"
            )

        unique = secrets.token_hex(16)
        key = (
            f"qualification/{self.args.execution_id}/direct-secure-preflight/"
            f"{unique}/bridgefu-direct-secure-probe"
        )
        paths = direct_secure_preflight.remote_paths(self.args.execution_id)
        try:
            probe_program = direct_secure_preflight.probe_script(
                self.args.execution_id,
                self.args.region,
                bucket,
                key,
                digest,
            )
            cleanup_program = direct_secure_preflight.cleanup_script(
                self.args.execution_id, paths.probe
            )
        except direct_secure_preflight.DirectSecurePreflightError as error:
            raise QualificationError(
                "direct secure preflight contract is invalid"
            ) from error

        self.secure_preflight_cleanup_required = True
        ensure_connect_agent_available(self.aws, self.outputs)
        agent_process, agent_observation = self.start_direct_secure_agent(storage)

        self.secure_preflight_object_key = key
        object_uri = f"s3://{bucket}/{key}"
        probe_command_id: str | None = None
        probe_dispatch_attempted = False
        probe_result: dict[str, Any] | None = None
        primary_error: BaseException | None = None
        cleanup_failures: list[str] = []
        receipt: dict[str, Any] | None = None
        object_versions_removed = False

        try:
            self.aws.text(
                [
                    "s3",
                    "cp",
                    os.fspath(self.args.direct_secure_probe),
                    object_uri,
                    "--sse",
                    "AES256",
                    "--only-show-errors",
                ],
                timeout=120,
            )
            probe_dispatch_attempted = True
            probe_command_id = self.send_owned_shell(instance, probe_program)
            wait_for_ssm_command(
                self.aws,
                probe_command_id,
                instance,
                timeout=360,
            )
            raw = read_ssm_output(self.aws, probe_command_id, instance)
            probe_result = direct_secure_preflight.parse_probe_result(raw)
        except BaseException as error:
            primary_error = error
        finally:
            if probe_command_id is None:
                probe_command_terminal = not probe_dispatch_attempted
            else:
                probe_command_terminal = cancel_and_wait_ssm_terminal(
                    self.aws, probe_command_id, instance
                )
                if probe_command_terminal and probe_command_id in self.ssm_commands:
                    self.ssm_commands.remove(probe_command_id)

            remote_cleanup = {
                name: False for name in direct_secure_preflight.CLEANUP_FIELDS
            }
            cleanup_command_id: str | None = None
            cleanup_command_terminal = False
            try:
                cleanup_command_id = self.send_owned_shell(instance, cleanup_program)
                wait_for_ssm_command(
                    self.aws,
                    cleanup_command_id,
                    instance,
                    timeout=240,
                )
                raw_cleanup = read_ssm_output(self.aws, cleanup_command_id, instance)
                remote_cleanup = direct_secure_preflight.parse_cleanup_receipt(
                    raw_cleanup
                )
                cleanup_command_terminal = True
                self.ssm_commands.remove(cleanup_command_id)
            except BaseException:
                cleanup_failures.append("direct secure remote cleanup failed")
                if cleanup_command_id is not None:
                    cleanup_command_terminal = cancel_and_wait_ssm_terminal(
                        self.aws, cleanup_command_id, instance
                    )
                    if (
                        cleanup_command_terminal
                        and cleanup_command_id in self.ssm_commands
                    ):
                        self.ssm_commands.remove(cleanup_command_id)

            try:
                receipt = direct_cleanup_receipt(
                    self.args.execution_id,
                    probe_command_terminal=probe_command_terminal,
                    cleanup_command_terminal=cleanup_command_terminal,
                    remote=remote_cleanup,
                )
                self.secure_preflight_restoration_passed = receipt["passed"] is True
                if not self.secure_preflight_restoration_passed:
                    cleanup_failures.append(
                        "direct secure runtime restoration proof failed"
                    )
            except QualificationError:
                self.secure_preflight_restoration_passed = False
                cleanup_failures.append("direct secure cleanup receipt failed")

            try:
                purge_object_versions_exact(self.aws, bucket, key, exact_key=True)
                self.secure_preflight_object_key = None
                object_versions_removed = True
            except QualificationError:
                cleanup_failures.append(
                    "direct secure executable version cleanup failed"
                )
            self.secure_preflight_cleanup_passed = (
                self.secure_preflight_restoration_passed and object_versions_removed
            )

        if primary_error is not None or cleanup_failures:
            if agent_process.poll() is None:
                agent_process.terminate()
                try:
                    agent_process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    agent_process.kill()
                    agent_process.communicate()
            if agent_process in self.processes:
                self.processes.remove(agent_process)
            parts = []
            if primary_error is not None:
                parts.append(sanitize_diagnostic(str(primary_error), 512))
            parts.extend(cleanup_failures)
            raise QualificationError("; ".join(parts)) from primary_error

        if probe_result is None or receipt is None:
            raise QualificationError("direct secure preflight result is unavailable")
        self.complete_process(
            agent_process, "Amazon Connect direct secure observer", 240
        )
        agent = read_private_json(agent_observation)
        validate_schema(agent, "direct-secure-agent-observation-v1.schema.json")
        checks = derive_direct_secure_checks(probe_result, agent, receipt)
        if receipt.get("passed") is not True or not all(checks.values()):
            raise QualificationError("direct secure preflight evidence did not pass")
        self.secure_preflight_evidence = {
            "binary_sha256": digest,
            "probe_result_sha256": canonical_sha256(probe_result),
            "agent_observation_sha256": sha256_file(agent_observation),
            "cleanup_receipt_sha256": canonical_sha256(receipt),
            "checks": checks,
            "passed": True,
        }

    def wait_for_vapi_call(
        self,
        *,
        assistant_id: str,
        started_after: dt.datetime,
        call_id: str | None = None,
        phone_id: str | None = None,
        timeout: int = 90,
    ) -> Mapping[str, Any]:
        if self.vapi is None:
            raise QualificationError("Vapi client is unavailable")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            matches: list[Mapping[str, Any]] = []
            # Use Vapi's server-side identity/time filters. An unfiltered page
            # is neither guaranteed newest-first nor small once call artifacts
            # are attached.
            for call in self.vapi.list_calls(
                assistant_id=assistant_id,
                created_at_ge=started_after - dt.timedelta(seconds=5),
                phone_number_id=phone_id,
                call_id=call_id,
            ):
                created = call.get("createdAt")
                try:
                    created_at = dt.datetime.fromisoformat(
                        str(created).replace("Z", "+00:00")
                    )
                except ValueError:
                    continue
                if created_at < started_after - dt.timedelta(seconds=5):
                    continue
                if call.get("assistantId") != assistant_id:
                    continue
                if call_id is not None and call.get("id") != call_id:
                    continue
                if phone_id is not None and call.get("phoneNumberId") != phone_id:
                    continue
                matches.append(call)
            if len(matches) == 1:
                value = self.vapi.get("call", str(matches[0]["id"]))
                if value is not None:
                    return value
            if len(matches) > 1:
                raise QualificationError("Vapi smoke call identity is ambiguous")
            time.sleep(0.5)
        raise QualificationError("Vapi smoke call did not become observable")

    def provision_temporary_vapi_phone(
        self,
        assistant_id: str | None = None,
    ) -> tuple[dict[str, str], str, str]:
        if self.vapi is None:
            raise QualificationError("Vapi client is unavailable")
        selected_assistant_id = assistant_id or self.outputs["VapiAssistantId"]
        if not isinstance(selected_assistant_id, str) or not RESOURCE_ID.fullmatch(
            selected_assistant_id
        ):
            raise QualificationError("temporary Vapi assistant is unavailable")
        if any(
            value is not None
            for value in (
                self.temp_phone_id,
                getattr(self, "temp_phone_intent", None),
                getattr(self, "temp_phone_intent_journal_object", None),
                getattr(self, "temp_phone_request_journal_object", None),
                getattr(self, "temp_phone_journal_object", None),
            )
        ):
            raise QualificationError("temporary Vapi endpoint state is not clean")
        authentication = {
            "realm": "sip.vapi.ai",
            "username": f"bfq_{secrets.token_hex(8)}",
            "password": secrets.token_urlsafe(24),
        }
        intent = vapi_phone_intent(
            self.args.execution_id,
            selected_assistant_id,
            authentication,
        )
        self.temp_phone_intent = intent
        self.write_phone_intent_journal(intent)
        self.write_phone_request_journal(intent)
        # From this point until exact returned-ID ownership is durably sealed,
        # a process stop may have happened after Vapi committed the POST.
        self.temp_phone_creation_ambiguous = True
        try:
            phone = self.vapi.create_phone(
                self.args.execution_id,
                selected_assistant_id,
                authentication,
            )
        except VapiPhoneReconciliationError:
            self.temp_phone_creation_ambiguous = True
            raise
        phone_id = phone.get("id")
        sip_uri = phone.get("sipUri")
        if not isinstance(phone_id, str) or not RESOURCE_ID.fullmatch(phone_id):
            raise QualificationError("temporary Vapi SIP endpoint is invalid")
        self.temp_phone_id = phone_id
        self.write_phone_ownership_journal(phone_id, selected_assistant_id)
        self.temp_phone_creation_ambiguous = False
        if sip_uri != intent["sip_uri"]:
            raise QualificationError("temporary Vapi SIP endpoint is invalid")
        wait_for_vapi_phone_active(
            self.vapi,
            phone_id,
            str(sip_uri),
            selected_assistant_id,
        )
        return authentication, phone_id, str(sip_uri)

    def put_secret_json(self, secret_arn: str, value: Mapping[str, Any]) -> None:
        if not secret_arn.startswith("arn:aws"):
            raise QualificationError("qualification secret identity is invalid")
        self.runner.run(
            [
                "aws",
                "secretsmanager",
                "put-secret-value",
                "--region",
                self.args.region,
                "--secret-id",
                secret_arn,
                "--secret-string",
                "file:///dev/stdin",
                "--output",
                "json",
            ],
            input_text=json.dumps(value, separators=(",", ":"), sort_keys=True),
            timeout=120,
        )

    def install_direct_assistant(self) -> None:
        """Create a direct-only assistant without mutating the product assistant."""
        if self.vapi is None:
            raise QualificationError("Vapi client is unavailable")
        product_assistant_id = self.outputs["VapiAssistantId"]
        product_assistant = self.vapi.get("assistant", product_assistant_id)
        if product_assistant is None:
            raise QualificationError("product Vapi assistant is unavailable")
        self.product_assistant_sha256 = canonical_sha256(product_assistant)
        try:
            product_binding = json.loads(
                self.aws.secret(self.outputs["ProductVapiIdentityBindingArn"])
            )
        except json.JSONDecodeError as error:
            raise QualificationError(
                "product Vapi identity binding is invalid"
            ) from error
        if (
            not isinstance(product_binding, Mapping)
            or set(product_binding) != {"status", "organization_id", "assistant_id"}
            or product_binding.get("status") != "bound"
            or product_binding.get("assistant_id") != product_assistant_id
            or not isinstance(product_binding.get("organization_id"), str)
            or not RESOURCE_ID.fullmatch(product_binding["organization_id"])
        ):
            raise QualificationError("product Vapi identity binding is invalid")
        endpoint = self.outputs["DirectHandoffUrl"]
        credential_id = self.outputs["VapiWebhookCredentialId"]
        try:
            desired_tool = bridgefu_web_handoff.direct_tool_payload(
                endpoint_url=endpoint,
                credential_id=credential_id,
                field_schema=qualification_field_schema(),
                execution_id=self.args.execution_id,
            )
        except bridgefu_web_handoff.DirectHandoffContractError as error:
            raise QualificationError("direct Vapi tool contract is invalid") from error
        self.direct_tool_desired = desired_tool
        self.direct_tool_intent = direct_tool_intent_journal(
            self.args.execution_id,
            self.args.region,
            endpoint,
            credential_id,
            desired_tool,
        )
        self.direct_tool_intent_journal_object = self.write_direct_vapi_journal(
            "vapi-direct-tool-intent.json", self.direct_tool_intent
        )
        self.direct_vapi_cleanup_required = True
        self.direct_tool_request_journal_object = self.write_direct_vapi_journal(
            "vapi-direct-tool-request.json",
            direct_vapi_request_journal(self.direct_tool_intent, secrets.token_hex(16)),
        )
        self.direct_tool_creation_ambiguous = True
        tool = self.vapi.create_direct_tool(
            execution_id=self.args.execution_id,
            endpoint_url=endpoint,
            credential_id=credential_id,
            desired=desired_tool,
        )
        tool_id = tool.get("id")
        if not isinstance(tool_id, str) or not RESOURCE_ID.fullmatch(tool_id):
            raise QualificationError("direct Vapi tool identity is invalid")
        self.direct_tool_id = tool_id
        self.direct_tool_journal_object = self.write_direct_vapi_journal(
            "vapi-direct-tool.json",
            direct_tool_ownership_journal(self.direct_tool_intent, tool_id),
        )
        self.direct_tool_creation_ambiguous = False
        try:
            desired_assistant, prompt_hash = (
                bridgefu_web_handoff.direct_assistant_payload(
                    execution_id=self.args.execution_id,
                    tool_id=tool_id,
                    model_name=self.outputs["VapiModel"],
                    voice_id=self.outputs["VapiVoiceId"],
                )
            )
        except bridgefu_web_handoff.DirectHandoffContractError as error:
            raise QualificationError("direct Vapi assistant is invalid") from error
        self.direct_assistant_desired = desired_assistant
        self.direct_tool_prompt_sha256 = prompt_hash
        self.direct_assistant_intent = direct_assistant_intent_journal(
            self.args.execution_id,
            self.args.region,
            product_binding["organization_id"],
            tool_id,
            self.outputs["VapiModel"],
            self.outputs["VapiVoiceId"],
            prompt_hash,
            desired_assistant,
        )
        self.direct_assistant_intent_journal_object = self.write_direct_vapi_journal(
            "vapi-direct-assistant-intent.json", self.direct_assistant_intent
        )
        self.direct_assistant_request_journal_object = self.write_direct_vapi_journal(
            "vapi-direct-assistant-request.json",
            direct_vapi_request_journal(
                self.direct_assistant_intent, secrets.token_hex(16)
            ),
        )
        self.direct_assistant_creation_ambiguous = True
        assistant = self.vapi.create_direct_assistant(
            execution_id=self.args.execution_id,
            tool_id=tool_id,
            prompt_sha256=prompt_hash,
            model_name=self.outputs["VapiModel"],
            voice_id=self.outputs["VapiVoiceId"],
            desired=desired_assistant,
        )
        assistant_id = assistant.get("id")
        if not isinstance(assistant_id, str) or not RESOURCE_ID.fullmatch(assistant_id):
            raise QualificationError("direct Vapi assistant identity is invalid")
        assistant_org_id = assistant.get("orgId")
        if assistant_org_id not in (
            None,
            "",
            product_binding["organization_id"],
        ):
            raise QualificationError("direct Vapi assistant organization changed")
        self.direct_assistant_id = assistant_id
        self.direct_assistant_journal_object = self.write_direct_vapi_journal(
            "vapi-direct-assistant.json",
            direct_assistant_ownership_journal(
                self.direct_assistant_intent, assistant_id
            ),
        )
        self.direct_assistant_creation_ambiguous = False
        # Treat the write as ambiguous until cleanup proves the secret is
        # either still unbound or has been restored to unbound. This closes the
        # commit-then-timeout window in Secrets Manager.
        self.direct_identity_binding_installed = True
        self.put_secret_json(
            self.outputs["DirectVapiIdentityBindingArn"],
            {
                "status": "bound",
                "organization_id": product_binding["organization_id"],
                "assistant_id": assistant_id,
            },
        )

    def cleanup_direct_assistant(self) -> list[str]:
        """Delete Vapi transients in unbind -> assistant -> tool order."""
        errors: list[str] = []
        endpoint = self.outputs.get("DirectHandoffUrl")
        credential_id = self.outputs.get("VapiWebhookCredentialId")
        tool_id = getattr(self, "direct_tool_id", None)
        prompt_hash = getattr(self, "direct_tool_prompt_sha256", None)
        if (
            self.temp_phone_id is not None
            or getattr(self, "temp_phone_intent", None) is not None
            or getattr(self, "temp_phone_creation_ambiguous", False)
        ):
            return ["direct Vapi assistant cleanup requires an absent phone"]
        if getattr(self, "direct_identity_binding_installed", False):
            try:
                current_binding = json.loads(
                    self.aws.secret(self.outputs["DirectVapiIdentityBindingArn"])
                )
                try:
                    product_binding = json.loads(
                        self.aws.secret(self.outputs["ProductVapiIdentityBindingArn"])
                    )
                except json.JSONDecodeError as error:
                    raise QualificationError(
                        "product Vapi identity binding is invalid"
                    ) from error
                expected_binding = {
                    "status": "bound",
                    "organization_id": product_binding.get("organization_id"),
                    "assistant_id": getattr(self, "direct_assistant_id", None),
                }
                if current_binding == {"status": "unbound"}:
                    self.direct_identity_binding_installed = False
                elif current_binding != expected_binding:
                    raise QualificationError(
                        "direct Vapi identity binding ownership changed"
                    )
                else:
                    self.put_secret_json(
                        self.outputs["DirectVapiIdentityBindingArn"],
                        {"status": "unbound"},
                    )
                    self.direct_identity_binding_installed = False
            except (QualificationError, json.JSONDecodeError):
                errors.append("direct Vapi identity unbind failed")
        if not getattr(self, "direct_identity_binding_installed", False):
            try:
                assistant_request_authorized = (
                    getattr(self, "direct_assistant_request_journal_object", None)
                    is not None
                )
                if (
                    self.vapi is None
                    or not isinstance(tool_id, str)
                    or not isinstance(prompt_hash, str)
                    or not isinstance(
                        getattr(self, "direct_assistant_desired", None), Mapping
                    )
                ):
                    if (
                        getattr(self, "direct_assistant_id", None) is not None
                        or getattr(self, "direct_assistant_creation_ambiguous", False)
                        or assistant_request_authorized
                    ):
                        raise QualificationError(
                            "direct Vapi assistant ownership proof is unavailable"
                        )
                else:
                    if getattr(self, "direct_assistant_id", None) is None and getattr(
                        self, "direct_assistant_creation_ambiguous", False
                    ):
                        found = self.vapi.find_direct_assistant(
                            execution_id=self.args.execution_id,
                            tool_id=tool_id,
                            prompt_sha256=prompt_hash,
                            model_name=self.outputs["VapiModel"],
                            voice_id=self.outputs["VapiVoiceId"],
                            desired=self.direct_assistant_desired,
                        )
                        if found is None:
                            raise QualificationError(
                                "direct Vapi assistant creation remains ambiguous"
                            )
                        self.direct_assistant_id = str(found["id"])
                        self.direct_assistant_creation_ambiguous = False
                    if getattr(self, "direct_assistant_id", None) is not None:
                        self.vapi.delete_direct_assistant(
                            self.direct_assistant_id,
                            execution_id=self.args.execution_id,
                            tool_id=tool_id,
                            prompt_sha256=prompt_hash,
                            model_name=self.outputs["VapiModel"],
                            voice_id=self.outputs["VapiVoiceId"],
                        )
                        self.direct_assistant_id = None
            except QualificationError:
                errors.append("direct Vapi assistant deletion failed")
        if getattr(self, "direct_assistant_id", None) is None and not getattr(
            self, "direct_assistant_creation_ambiguous", False
        ):
            try:
                if self.vapi is None or not isinstance(
                    getattr(self, "direct_tool_desired", None), Mapping
                ):
                    if tool_id is not None or getattr(
                        self, "direct_tool_creation_ambiguous", False
                    ):
                        raise QualificationError(
                            "direct Vapi tool ownership proof is unavailable"
                        )
                elif tool_id is None and getattr(
                    self, "direct_tool_creation_ambiguous", False
                ):
                    found = self.vapi.find_direct_tool(
                        execution_id=self.args.execution_id,
                        endpoint_url=str(endpoint),
                        credential_id=str(credential_id),
                        desired=self.direct_tool_desired,
                    )
                    if found is None:
                        raise QualificationError(
                            "direct Vapi tool creation remains ambiguous"
                        )
                    self.direct_tool_id = str(found["id"])
                    tool_id = self.direct_tool_id
                    self.direct_tool_creation_ambiguous = False
                if tool_id is not None:
                    if not isinstance(endpoint, str) or not isinstance(
                        credential_id, str
                    ):
                        raise QualificationError(
                            "direct Vapi tool ownership proof is unavailable"
                        )
                    self.vapi.delete_direct_tool(
                        tool_id,
                        execution_id=self.args.execution_id,
                        endpoint_url=endpoint,
                        credential_id=credential_id,
                        desired=self.direct_tool_desired,
                    )
                    self.direct_tool_id = None
            except QualificationError:
                errors.append("direct Vapi tool deletion failed")
        if getattr(self, "product_assistant_sha256", None) is not None:
            try:
                if self.vapi is None:
                    raise QualificationError("Vapi client is unavailable")
                product = self.vapi.get("assistant", self.outputs["VapiAssistantId"])
                if (
                    product is None
                    or canonical_sha256(product) != self.product_assistant_sha256
                ):
                    raise QualificationError("product Vapi assistant changed")
                self.product_assistant_sha256 = None
            except QualificationError:
                errors.append("product Vapi assistant unchanged proof failed")
        if (
            not errors
            and not getattr(self, "direct_identity_binding_installed", False)
            and getattr(self, "direct_assistant_id", None) is None
            and not getattr(self, "direct_assistant_creation_ambiguous", False)
            and getattr(self, "direct_tool_id", None) is None
            and not getattr(self, "direct_tool_creation_ambiguous", False)
        ):
            try:
                if self.vapi is None:
                    if getattr(self, "direct_vapi_cleanup_required", False):
                        raise QualificationError("Vapi client is unavailable")
                else:
                    if (
                        getattr(self, "direct_assistant_request_journal_object", None)
                        is not None
                    ):
                        if (
                            not isinstance(tool_id, str)
                            or not isinstance(prompt_hash, str)
                            or not isinstance(
                                getattr(self, "direct_assistant_desired", None),
                                Mapping,
                            )
                        ):
                            raise QualificationError(
                                "direct Vapi assistant absence proof is unavailable"
                            )
                        if (
                            self.vapi.find_direct_assistant(
                                execution_id=self.args.execution_id,
                                tool_id=tool_id,
                                prompt_sha256=prompt_hash,
                                model_name=self.outputs["VapiModel"],
                                voice_id=self.outputs["VapiVoiceId"],
                                desired=self.direct_assistant_desired,
                            )
                            is not None
                        ):
                            raise QualificationError(
                                "direct Vapi assistant remains after deletion"
                            )
                    if (
                        getattr(self, "direct_tool_request_journal_object", None)
                        is not None
                    ):
                        if (
                            not isinstance(endpoint, str)
                            or not isinstance(credential_id, str)
                            or not isinstance(
                                getattr(self, "direct_tool_desired", None), Mapping
                            )
                        ):
                            raise QualificationError(
                                "direct Vapi tool absence proof is unavailable"
                            )
                        if (
                            self.vapi.find_direct_tool(
                                execution_id=self.args.execution_id,
                                endpoint_url=endpoint,
                                credential_id=credential_id,
                                desired=self.direct_tool_desired,
                            )
                            is not None
                        ):
                            raise QualificationError(
                                "direct Vapi tool remains after deletion"
                            )
                self.direct_vapi_cleanup_required = False
                self.direct_tool_desired = None
                self.direct_tool_prompt_sha256 = None
                self.direct_tool_intent = None
                self.direct_assistant_desired = None
                self.direct_assistant_intent = None
                # The journals stay durably present until the final versioned-prefix
                # purge. Clearing only their in-memory recovery flags is safe after
                # exact remote absence has been proved.
                self.direct_tool_intent_journal_object = None
                self.direct_tool_request_journal_object = None
                self.direct_tool_journal_object = None
                self.direct_assistant_intent_journal_object = None
                self.direct_assistant_request_journal_object = None
                self.direct_assistant_journal_object = None
            except QualificationError:
                errors.append("direct Vapi resource absence proof failed")
        return errors

    @staticmethod
    def reserve_local_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            return int(listener.getsockname()[1])

    def start_ssm_tunnel(
        self, remote_port: int, local_port: int
    ) -> subprocess.Popen[str]:
        if not 1 <= remote_port <= 65535 or not 1024 <= local_port <= 65535:
            raise QualificationError("SSM tunnel port is invalid")
        process = self.runner.popen(
            [
                "aws",
                "ssm",
                "start-session",
                "--region",
                self.args.region,
                "--target",
                self.outputs["BridgefuInstanceId"],
                "--document-name",
                "AWS-StartPortForwardingSession",
                "--parameters",
                json.dumps(
                    {
                        "portNumber": [str(remote_port)],
                        "localPortNumber": [str(local_port)],
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ]
        )
        self.processes.append(process)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                _, stderr = terminate_owned_process(process, timeout=5)
                self.processes.remove(process)
                raise QualificationError(
                    "SSM local tunnel failed: " + sanitize_diagnostic(stderr, 256)
                )
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.2)
                if probe.connect_ex(("127.0.0.1", local_port)) == 0:
                    return process
            time.sleep(0.25)
        terminate_owned_process(process)
        self.processes.remove(process)
        raise QualificationError("SSM local tunnel did not become ready")

    def stop_local_process(self, process: subprocess.Popen[str]) -> None:
        terminate_owned_process(process)
        if process in self.processes:
            self.processes.remove(process)

    def run_web_runtime_ssm(self, script: str, label: str) -> Mapping[str, Any]:
        commands = [line for line in script.splitlines() if line]
        command_id = self.aws.text(
            [
                "ssm",
                "send-command",
                "--instance-ids",
                self.outputs["BridgefuInstanceId"],
                "--document-name",
                "AWS-RunShellScript",
                "--parameters",
                encode_ssm_shell_parameters(commands),
                "--query",
                "Command.CommandId",
            ]
        )
        self.ssm_commands.append(command_id)
        wait_for_ssm_command(
            self.aws,
            command_id,
            self.outputs["BridgefuInstanceId"],
            timeout=420,
        )
        result = self.aws.json(
            [
                "ssm",
                "get-command-invocation",
                "--command-id",
                command_id,
                "--instance-id",
                self.outputs["BridgefuInstanceId"],
            ]
        )
        self.ssm_commands.remove(command_id)
        output = result.get("StandardOutputContent")
        if not isinstance(output, str) or len(output.encode("utf-8")) > 4096:
            raise QualificationError(f"{label} returned invalid evidence")
        try:
            value = json.loads(output.strip())
        except json.JSONDecodeError as error:
            raise QualificationError(f"{label} returned invalid evidence") from error
        if not isinstance(value, Mapping):
            raise QualificationError(f"{label} returned invalid evidence")
        return value

    def install_web_runtime(
        self,
        *,
        authentication: Mapping[str, str],
        signaling_port: int,
    ) -> None:
        connect_flow_id = self.outputs["ConnectWrapperFlowArn"].rsplit("/", 1)[-1]
        sip_hostname = (
            f"{self.args.execution_id}.{self.args.hosted_zone_name.rstrip('.')}"
        )
        config = bridgefu_web_runtime.build_runtime_config(
            region=self.args.region,
            deployment_id=self.args.execution_id,
            sip_hostname=sip_hostname,
            public_ip=self.outputs["BridgefuPublicIp"],
            connect_instance_arn=self.outputs["ConnectInstanceArn"],
            connect_flow_id=connect_flow_id,
            vapi_sip_username=authentication["username"],
            signaling_port=signaling_port,
        )
        encoded = bridgefu_web_runtime.encode_runtime_config(config)
        config_path = self.work / "bridgefu-web-runtime.json"
        config_path.write_bytes(encoded)
        config_path.chmod(0o600)
        self.runner.run(
            [
                "cargo",
                "run",
                "--locked",
                "--quiet",
                "--bin",
                "bridgefu",
                "--",
                "--config",
                os.fspath(config_path),
                "validate",
            ],
            cwd=self.args.bridgefu_checkout,
            env=bridgefu_web_runtime.validation_environment(os.environ),
            timeout=1800,
        )
        bucket = self.outputs["ArtifactBucket"]
        object_key = f"qualification/{self.args.execution_id}/web-runtime/bridgefu.json"
        self.web_runtime_object_key = object_key
        self.aws.text(
            [
                "s3",
                "cp",
                os.fspath(config_path),
                f"s3://{bucket}/{object_key}",
                "--sse",
                "AES256",
                "--only-show-errors",
            ]
        )
        self.put_secret_json(self.outputs["DirectVapiSipAuthSecretArn"], authentication)
        self.web_runtime_secret_written = True
        script = bridgefu_web_runtime.install_script(
            execution_id=self.args.execution_id,
            region=self.args.region,
            bucket=bucket,
            object_key=object_key,
            config_sha256=sha256_bytes(encoded),
            auth_secret_arn=self.outputs["DirectVapiSipAuthSecretArn"],
        )
        self.web_runtime_cleanup_required = True
        result = self.run_web_runtime_ssm(script, "Bridgefu Web runtime install")
        bridgefu_web_runtime.validate_install_result(result)

    def cleanup_web_runtime(self) -> list[str]:
        errors: list[str] = []
        if getattr(self, "web_runtime_cleanup_required", False):
            try:
                result = self.run_web_runtime_ssm(
                    bridgefu_web_runtime.cleanup_script(
                        execution_id=self.args.execution_id
                    ),
                    "Bridgefu Web runtime cleanup",
                )
                bridgefu_web_runtime.validate_cleanup_result(result)
                self.web_runtime_cleanup_required = False
                self.web_runtime_restoration_passed = True
            except (
                QualificationError,
                bridgefu_web_runtime.WebRuntimeContractError,
            ):
                errors.append("Bridgefu Web runtime restoration failed")
        if getattr(self, "web_runtime_media_permission", None) is not None:
            try:
                permission = self.web_runtime_media_permission
                self.aws.json(
                    [
                        "ec2",
                        "revoke-security-group-ingress",
                        "--group-id",
                        self.outputs["BridgefuGatewaySecurityGroupId"],
                        "--ip-permissions",
                        json.dumps([permission], separators=(",", ":"), sort_keys=True),
                    ]
                )
                self.web_runtime_media_permission = None
            except QualificationError:
                errors.append("Bridgefu Web media admission cleanup failed")
        if getattr(self, "web_runtime_secret_written", False):
            try:
                self.put_secret_json(self.outputs["DirectVapiSipAuthSecretArn"], {})
                self.web_runtime_secret_written = False
            except QualificationError:
                errors.append("Bridgefu Web SIP secret cleanup failed")
        if getattr(self, "web_runtime_object_key", None) is not None:
            try:
                purge_object_versions_exact(
                    self.aws,
                    self.outputs["ArtifactBucket"],
                    self.web_runtime_object_key,
                    exact_key=True,
                )
                self.web_runtime_object_key = None
            except QualificationError:
                errors.append("Bridgefu Web runtime object cleanup failed")
        return errors

    def authorize_web_media(self) -> None:
        try:
            with urllib.request.urlopen(  # noqa: S310
                "https://checkip.amazonaws.com", timeout=10
            ) as response:
                raw = response.read(128).decode("ascii").strip()
            source = str(socket.inet_ntoa(socket.inet_aton(raw))) + "/32"
        except (OSError, UnicodeError) as error:
            raise QualificationError("browser public address is unavailable") from error
        permission = {
            "IpProtocol": "udp",
            "FromPort": 20000,
            "ToPort": 20399,
            "IpRanges": [
                {
                    "CidrIp": source,
                    "Description": f"BFQ {self.args.execution_id} browser media",
                }
            ],
        }
        self.aws.json(
            [
                "ec2",
                "authorize-security-group-ingress",
                "--group-id",
                self.outputs["BridgefuGatewaySecurityGroupId"],
                "--ip-permissions",
                json.dumps([permission], separators=(",", ":"), sort_keys=True),
            ]
        )
        self.web_runtime_media_permission = permission

    def create_direct_route(
        self,
        *,
        control_port: int,
        correlation_id: str,
        handoff_token: str,
    ) -> bridgefu_web_handoff.DirectRouteBinding:
        payload = bridgefu_web_handoff.route_request(correlation_id, handoff_token)
        bearer = self.aws.secret(self.outputs["BridgefuApiBearerSecretArn"])
        request = urllib.request.Request(
            f"http://127.0.0.1:{control_port}/v1/routes/"
            f"{bridgefu_web_runtime.WEB_ROUTE_ID}/calls",
            data=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            ),
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
                "Idempotency-Key": f"bfq-{secrets.token_hex(16)}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                raw = response.read(1024 * 1024 + 1)
                status = response.status
        except (urllib.error.HTTPError, OSError) as error:
            raise QualificationError("Bridgefu direct route creation failed") from error
        if status != 201 or len(raw) > 1024 * 1024:
            raise QualificationError("Bridgefu direct route creation failed")
        try:
            value = json.loads(raw)
            return bridgefu_web_handoff.parse_route_response(
                value, bridgefu_web_runtime.WEB_ROUTE_ID
            )
        except (
            json.JSONDecodeError,
            bridgefu_web_handoff.DirectHandoffContractError,
        ) as error:
            raise QualificationError(
                "Bridgefu direct route response is invalid"
            ) from error

    def stage_direct_context(
        self,
        *,
        correlation_id: str,
        token_id: str,
        binding: bridgefu_web_handoff.DirectRouteBinding,
        now: int,
    ) -> None:
        item = direct_context_item(
            correlation_id=correlation_id,
            token_id=token_id,
            binding=binding,
            schema_hash=self.outputs["ScreenPopSchemaHash"],
            now=now,
        )
        self.runner.run(
            [
                "aws",
                "dynamodb",
                "put-item",
                "--region",
                self.args.region,
                "--table-name",
                self.outputs["HandoffTableName"],
                "--item",
                "file:///dev/stdin",
                "--condition-expression",
                "attribute_not_exists(correlation_id)",
                "--output",
                "json",
            ],
            input_text=json.dumps(item, separators=(",", ":"), sort_keys=True),
            timeout=120,
        )
        self.direct_context_correlation_id = correlation_id

    def cleanup_direct_context(self) -> list[str]:
        correlation_id = getattr(self, "direct_context_correlation_id", None)
        if correlation_id is None:
            return []
        if not re.fullmatch(r"bf1_[A-Za-z0-9_-]{43}", correlation_id):
            return ["Bridgefu direct context ownership proof is invalid"]
        key = json.dumps(
            {"correlation_id": {"S": correlation_id}},
            separators=(",", ":"),
            sort_keys=True,
        )
        try:
            self.runner.run(
                [
                    "aws",
                    "dynamodb",
                    "delete-item",
                    "--region",
                    self.args.region,
                    "--table-name",
                    self.outputs["HandoffTableName"],
                    "--key",
                    "file:///dev/stdin",
                    "--return-values",
                    "NONE",
                    "--output",
                    "json",
                ],
                input_text=key,
                timeout=120,
            )
            raw = self.runner.run(
                [
                    "aws",
                    "dynamodb",
                    "get-item",
                    "--region",
                    self.args.region,
                    "--table-name",
                    self.outputs["HandoffTableName"],
                    "--key",
                    "file:///dev/stdin",
                    "--consistent-read",
                    "--projection-expression",
                    "correlation_id",
                    "--output",
                    "json",
                ],
                input_text=key,
                timeout=120,
            )
            value = json.loads(raw) if raw.strip() else {}
            if not isinstance(value, Mapping) or "Item" in value:
                raise QualificationError(
                    "Bridgefu direct context deletion was not verified"
                )
            self.direct_context_correlation_id = None
            return []
        except (QualificationError, json.JSONDecodeError):
            return ["Bridgefu direct context deletion failed"]

    def web_smoke(
        self, site: Path, site_digest: str, storage: Path, correlation_key: str
    ) -> None:
        primary_error: BaseException | None = None
        try:
            self._web_smoke(site, site_digest, storage, correlation_key)
        except BaseException as error:
            primary_error = error
        cleanup_errors = self.stop_active_work()
        cleanup_errors.extend(self.cleanup_direct_context())
        cleanup_errors.extend(self.cleanup_web_runtime())
        cleanup_errors.extend(self.cleanup_sip_transients())
        cleanup_errors.extend(self.cleanup_direct_assistant())
        if primary_error is not None:
            if cleanup_errors:
                raise QualificationError(
                    sanitize_diagnostic(str(primary_error))
                    + "; "
                    + "; ".join(cleanup_errors)
                ) from primary_error
            raise primary_error
        if cleanup_errors:
            raise QualificationError("; ".join(cleanup_errors))

    def _web_smoke(
        self, site: Path, site_digest: str, storage: Path, correlation_key: str
    ) -> None:
        if self.vapi is None:
            raise QualificationError("Vapi client is unavailable")
        scenario = WEB_SCENARIO
        reachability = self.run_web_runtime_ssm(
            bridgefu_web_runtime.vapi_tls_reachability_script(),
            "Vapi TLS reachability preflight",
        )
        bridgefu_web_runtime.validate_vapi_tls_reachability(reachability)
        self.install_direct_assistant()
        authentication, phone_id, _ = self.provision_temporary_vapi_phone(
            self.direct_assistant_id
        )
        signaling_port = self.reserve_local_port()
        control_port = self.reserve_local_port()
        self.install_web_runtime(
            authentication=authentication,
            signaling_port=signaling_port,
        )
        self.authorize_web_media()
        wss_tunnel = self.start_ssm_tunnel(8080, signaling_port)
        control_tunnel = self.start_ssm_tunnel(9090, control_port)
        try:
            ensure_connect_agent_available(self.aws, self.outputs)
            session_path = self.work / f"{scenario}-session.json"
            agent_process, agent_observation, _, agent_ready = self.start_agent(
                session_path, storage, scenario
            )
            self.wait_for_agent_readiness(agent_process, agent_ready, scenario)

            correlation_id = "bf1_" + secrets.token_urlsafe(32)
            token_id = "bfq_" + secrets.token_hex(16)
            signing_key = self.aws.secret(self.outputs["DirectHandoffSigningKeyArn"])
            handoff_token = bridgefu_web_handoff.issue_handoff_token(
                signing_key,
                correlation_id,
                token_id,
            )
            started = dt.datetime.now(dt.UTC)
            binding = self.create_direct_route(
                control_port=control_port,
                correlation_id=correlation_id,
                handoff_token=handoff_token,
            )
            self.stage_direct_context(
                correlation_id=correlation_id,
                token_id=token_id,
                binding=binding,
                now=int(started.timestamp()),
            )
            route_attachment = self.work / f"{scenario}-route.json"
            private_json(route_attachment, binding.browser_input())
            prompt = self.work / "web-prompt.pcm"
            speech = "Transfer me please."
            self.runner.run(
                [
                    "aws",
                    "polly",
                    "synthesize-speech",
                    "--region",
                    self.args.region,
                    "--output-format",
                    "pcm",
                    "--sample-rate",
                    "8000",
                    "--voice-id",
                    "Joanna",
                    "--text",
                    speech,
                    os.fspath(prompt),
                ],
                timeout=120,
            )
            prompt.chmod(0o600)
            ready = self.work / f"{scenario}-ready.json"
            trigger = self.work / f"{scenario}-trigger.json"
            source_observation = self.work / f"{scenario}-source.json"
            hostname = (
                f"{self.args.execution_id}.{self.args.hosted_zone_name.rstrip('.')}"
            )
            source_process = self.runner.popen(
                [
                    "node",
                    os.fspath(
                        QUALIFICATION / "browser" / "bridgefu-web-playwright.mjs"
                    ),
                    "observe",
                    "--site-dir",
                    os.fspath(site),
                    "--route-attachment",
                    os.fspath(route_attachment),
                    "--prompt-pcm",
                    os.fspath(prompt),
                    "--signaling-hostname",
                    hostname,
                    "--session",
                    os.fspath(session_path),
                    "--ready",
                    os.fspath(ready),
                    "--trigger",
                    os.fspath(trigger),
                    "--observation",
                    os.fspath(source_observation),
                    "--site-bundle-sha256",
                    site_digest,
                    "--hangup-origin",
                    "source",
                    "--timeout-seconds",
                    "300",
                ]
            )
            self.processes.append(source_process)
            ready_value = validate_web_source_readiness(
                self.wait_for_process_file(
                    source_process,
                    ready,
                    BROWSER_READINESS_TIMEOUT_SECONDS,
                    "Bridgefu Web SDK smoke source",
                )
            )
            bridgefu_call_id = str(ready_value["call_id"])
            if bridgefu_call_id != binding.call_id:
                raise QualificationError("Bridgefu WebRTC call identity changed")
            call = self.wait_for_vapi_call(
                assistant_id=str(self.direct_assistant_id),
                started_after=started,
                phone_id=phone_id,
                timeout=120,
            )
            session = make_session(
                execution_id=self.args.execution_id,
                scenario=scenario,
                call=call,
                correlation_key=correlation_key,
                bridgefu_commit=self.bridgefu_lock["commit"],
                release=self.args.release,
                sip_uri=None,
                source_call_id=bridgefu_call_id,
                correlation_id=correlation_id,
            )
            private_json(session_path, session)
            private_json(trigger, {"schema_version": 1, "execute": True})
            browser_errors: list[str] = []
            for process, label in (
                (source_process, "Bridgefu Web SDK smoke source"),
                (agent_process, "Amazon Connect Web smoke observer"),
            ):
                try:
                    self.complete_process(process, label, 360)
                except QualificationError as error:
                    browser_errors.append(str(error))
            if browser_errors:
                raise QualificationError("; ".join(browser_errors))
            self.verify_scenario(
                scenario, session, source_observation, agent_observation
            )
        finally:
            self.stop_local_process(control_tunnel)
            self.stop_local_process(wss_tunnel)

    def cleanup_sip_transients(self) -> list[str]:
        errors: list[str] = []
        intent = getattr(self, "temp_phone_intent", None)
        intent_journal = getattr(self, "temp_phone_intent_journal_object", None)
        request_journal = getattr(self, "temp_phone_request_journal_object", None)
        creation_ambiguous = getattr(self, "temp_phone_creation_ambiguous", False)
        phone_absent = (
            self.temp_phone_id is None
            and intent is None
            and self.temp_phone_journal_object is None
            and intent_journal is None
            and request_journal is None
        )
        if self.vapi is not None and intent is not None:
            try:
                if self.temp_phone_id is None:
                    reconciled = self.vapi.find_phone_for_intent(intent)
                    if reconciled is not None:
                        phone_id = reconciled.get("id")
                        if not isinstance(phone_id, str) or not RESOURCE_ID.fullmatch(
                            phone_id
                        ):
                            raise QualificationError(
                                "temporary Vapi SIP endpoint identity is invalid"
                            )
                        self.temp_phone_id = phone_id
                        self.write_phone_ownership_journal(
                            phone_id, intent["assistant_id"]
                        )
                    elif creation_ambiguous or request_journal is not None:
                        raise QualificationError(
                            "temporary Vapi SIP endpoint creation remains ambiguous"
                        )
                if self.temp_phone_id is not None:
                    self.vapi.delete_phone(self.temp_phone_id, intent)
                    self.temp_phone_id = None
                self.temp_phone_creation_ambiguous = False
                phone_absent = True
            except QualificationError:
                errors.append("temporary Vapi SIP endpoint deletion failed")
        elif (
            self.temp_phone_id is not None
            or intent is not None
            or self.temp_phone_journal_object is not None
            or intent_journal is not None
            or request_journal is not None
        ):
            errors.append("temporary Vapi SIP endpoint ownership proof is unavailable")
        if phone_absent and self.temp_phone_journal_object is not None:
            try:
                self.aws.text(
                    [
                        "s3",
                        "rm",
                        self.temp_phone_journal_object,
                        "--only-show-errors",
                    ]
                )
                self.temp_phone_journal_object = None
            except QualificationError:
                errors.append("temporary Vapi endpoint journal deletion failed")
        if (
            phone_absent
            and self.temp_phone_journal_object is None
            and request_journal is not None
        ):
            try:
                self.aws.text(
                    [
                        "s3",
                        "rm",
                        request_journal,
                        "--only-show-errors",
                    ]
                )
                self.temp_phone_request_journal_object = None
                request_journal = None
            except QualificationError:
                errors.append("temporary Vapi endpoint request journal deletion failed")
        if (
            phone_absent
            and self.temp_phone_journal_object is None
            and request_journal is None
            and intent_journal is not None
        ):
            try:
                self.aws.text(
                    [
                        "s3",
                        "rm",
                        intent_journal,
                        "--only-show-errors",
                    ]
                )
                self.temp_phone_intent_journal_object = None
                intent_journal = None
            except QualificationError:
                errors.append("temporary Vapi endpoint intent journal deletion failed")
        if (
            phone_absent
            and self.temp_phone_journal_object is None
            and request_journal is None
            and intent_journal is None
        ):
            self.temp_phone_intent = None
        if self.temp_sip_auth_object is not None:
            try:
                self.aws.text(
                    [
                        "s3",
                        "rm",
                        self.temp_sip_auth_object,
                        "--only-show-errors",
                    ]
                )
                self.temp_sip_auth_object = None
            except QualificationError:
                errors.append("temporary Vapi SIP authentication deletion failed")
        return errors

    def write_phone_ownership_journal(self, phone_id: str, assistant_id: str) -> None:
        bucket = self.outputs.get("ArtifactBucket")
        if not isinstance(bucket, str) or not S3_BUCKET.fullmatch(bucket):
            raise QualificationError("qualification artifact bucket is invalid")
        journal = vapi_phone_ownership_journal(
            self.args.execution_id,
            self.args.region,
            phone_id,
            assistant_id,
        )
        target = (
            f"s3://{bucket}/qualification/{self.args.execution_id}/"
            "ownership/vapi-phone.json"
        )
        self.temp_phone_journal_object = target
        self.runner.run(
            [
                "aws",
                "s3",
                "cp",
                "-",
                target,
                "--sse",
                "AES256",
                "--only-show-errors",
                "--region",
                self.args.region,
            ],
            input_text=json.dumps(journal, separators=(",", ":"), sort_keys=True),
            timeout=120,
        )

    def write_phone_intent_journal(self, intent: Mapping[str, str]) -> None:
        bucket = self.outputs.get("ArtifactBucket")
        if not isinstance(bucket, str) or not S3_BUCKET.fullmatch(bucket):
            raise QualificationError("qualification artifact bucket is invalid")
        journal = vapi_phone_intent_journal(
            self.args.execution_id,
            self.args.region,
            intent,
        )
        target = (
            f"s3://{bucket}/qualification/{self.args.execution_id}/"
            "ownership/vapi-phone-intent.json"
        )
        self.runner.run(
            [
                "aws",
                "s3",
                "cp",
                "-",
                target,
                "--sse",
                "AES256",
                "--only-show-errors",
                "--region",
                self.args.region,
            ],
            input_text=json.dumps(journal, separators=(",", ":"), sort_keys=True),
            timeout=120,
        )
        self.temp_phone_intent_journal_object = target

    def write_phone_request_journal(self, intent: Mapping[str, str]) -> None:
        bucket = self.outputs.get("ArtifactBucket")
        if not isinstance(bucket, str) or not S3_BUCKET.fullmatch(bucket):
            raise QualificationError("qualification artifact bucket is invalid")
        intent_journal = vapi_phone_intent_journal(
            self.args.execution_id,
            self.args.region,
            intent,
        )
        request = vapi_phone_request_journal(
            intent_journal,
            secrets.token_hex(16),
        )
        target = (
            f"s3://{bucket}/qualification/{self.args.execution_id}/"
            "ownership/vapi-phone-request.json"
        )
        self.runner.run(
            [
                "aws",
                "s3",
                "cp",
                "-",
                target,
                "--sse",
                "AES256",
                "--content-type",
                "application/json",
                "--only-show-errors",
                "--region",
                self.args.region,
            ],
            input_text=json.dumps(request, separators=(",", ":"), sort_keys=True),
            timeout=120,
        )
        self.temp_phone_request_journal_object = target

    def write_direct_vapi_journal(self, name: str, value: Mapping[str, Any]) -> str:
        if name not in {
            "vapi-direct-tool-intent.json",
            "vapi-direct-tool-request.json",
            "vapi-direct-tool.json",
            "vapi-direct-assistant-intent.json",
            "vapi-direct-assistant-request.json",
            "vapi-direct-assistant.json",
        }:
            raise QualificationError("direct Vapi journal name is invalid")
        bucket = self.outputs.get("ArtifactBucket")
        if not isinstance(bucket, str) or not S3_BUCKET.fullmatch(bucket):
            raise QualificationError("qualification artifact bucket is invalid")
        target = (
            f"s3://{bucket}/qualification/{self.args.execution_id}/ownership/{name}"
        )
        self.runner.run(
            [
                "aws",
                "s3",
                "cp",
                "-",
                target,
                "--sse",
                "AES256",
                "--content-type",
                "application/json",
                "--only-show-errors",
                "--region",
                self.args.region,
            ],
            input_text=json.dumps(value, separators=(",", ":"), sort_keys=True),
            timeout=120,
        )
        return target

    def sip_smoke(self, storage: Path, correlation_key: str) -> None:
        primary_error: BaseException | None = None
        try:
            self._sip_smoke(storage, correlation_key)
        except BaseException as error:
            primary_error = error
        cleanup_errors = self.cleanup_sip_transients()
        if primary_error is not None:
            if cleanup_errors:
                raise QualificationError(
                    sanitize_diagnostic(str(primary_error))
                    + "; "
                    + "; ".join(cleanup_errors)
                ) from primary_error
            raise primary_error
        if cleanup_errors:
            raise QualificationError("; ".join(cleanup_errors))

    def _sip_smoke(self, storage: Path, correlation_key: str) -> None:
        if self.vapi is None:
            raise QualificationError("Vapi client is unavailable")
        scenario = "vapi-sip-transfer"
        # Unlike the Web smoke, this source can ask Vapi to transfer as soon as
        # its prompt arrives, so status selection must precede SSM dispatch.
        ensure_connect_agent_available(self.aws, self.outputs)
        authentication, phone_id, sip_uri = self.provision_temporary_vapi_phone()
        prompt = self.work / "sip-prompt.pcm"
        speech = (
            "This is an automated Bridgefu qualification. My customer name is Bridgefu Synthetic Caller. "
            "My issue summary is exactly: Qualification SIP transfer source hangup. "
            "My intent is qualification. My verification status is synthetic. "
            "Please call prepare handoff with exactly those values and transfer me to a human now."
        )
        self.runner.run(
            [
                "aws",
                "polly",
                "synthesize-speech",
                "--region",
                self.args.region,
                "--output-format",
                "pcm",
                "--sample-rate",
                "8000",
                "--voice-id",
                "Joanna",
                "--text",
                speech,
                os.fspath(prompt),
            ],
            timeout=120,
        )
        prefix = f"qualification/{self.args.execution_id}"
        bucket = self.outputs["ArtifactBucket"]
        self.temp_sip_auth_object = f"s3://{bucket}/{prefix}/sip-auth.json"
        self.runner.run(
            [
                "aws",
                "s3",
                "cp",
                "-",
                self.temp_sip_auth_object,
                "--sse",
                "AES256",
                "--only-show-errors",
                "--region",
                self.args.region,
            ],
            input_text=json.dumps(authentication, separators=(",", ":")),
            timeout=120,
        )
        self.aws.text(
            [
                "s3",
                "cp",
                os.fspath(self.args.sip_client),
                f"s3://{bucket}/{prefix}/sip-client",
            ]
        )
        self.aws.text(
            ["s3", "cp", os.fspath(prompt), f"s3://{bucket}/{prefix}/prompt.pcm"]
        )
        instance = self.outputs["BridgefuInstanceId"]
        public_ip = self.aws.text(
            [
                "ec2",
                "describe-instances",
                "--instance-ids",
                instance,
                "--query",
                "Reservations[0].Instances[0].PublicIpAddress",
            ]
        )
        try:
            socket.inet_aton(public_ip)
        except OSError as error:
            raise QualificationError(
                "Bridgefu qualification host has no public IPv4 address"
            ) from error
        remote_output = f"s3://{bucket}/{prefix}/sip-source.json"
        remote_directory = f"/var/lib/bridgefu/qualification/{self.args.execution_id}"
        remote_client = f"{remote_directory}/sip-client"
        remote_prompt = f"{remote_directory}/prompt.pcm"
        remote_observation = f"{remote_directory}/sip-source.json"
        session_path = self.work / f"{scenario}-session.json"
        agent_process, agent_observation, _, agent_ready = self.start_agent(
            session_path, storage, scenario
        )
        self.wait_for_agent_readiness(agent_process, agent_ready, scenario)
        commands = [
            "set -euo pipefail",
            f"install -d -m 0700 {remote_directory}",
            f"aws s3 cp s3://{bucket}/{prefix}/sip-client {remote_client}",
            f"aws s3 cp s3://{bucket}/{prefix}/prompt.pcm {remote_prompt}",
            f"chmod 0700 {remote_client}",
            (
                f"aws s3 cp {self.temp_sip_auth_object} - --only-show-errors | "
                f"{remote_client} --auth-stdin --sip-uri {sip_uri} --prompt-pcm {remote_prompt} "
                f"--public-ip {public_ip} --execution-id {self.args.execution_id} "
                f"--output {remote_observation} --timeout-seconds 240"
            ),
            f"aws s3 cp {remote_observation} {remote_output}",
            f"rm -f {remote_client} {remote_prompt} {remote_observation}",
            f"rmdir {remote_directory}",
        ]
        # Establish the discovery window before dispatching the remote client.
        # SSM can start the SIP call before send-command returns, so taking this
        # timestamp afterward races Vapi's server-side createdAtGe filter.
        started = dt.datetime.now(dt.UTC)
        command_id = self.aws.text(
            [
                "ssm",
                "send-command",
                "--instance-ids",
                instance,
                "--document-name",
                "AWS-RunShellScript",
                "--parameters",
                encode_ssm_shell_parameters(commands),
                "--query",
                "Command.CommandId",
            ]
        )
        self.ssm_commands.append(command_id)
        call = self.wait_for_vapi_call(
            assistant_id=self.outputs["VapiAssistantId"],
            started_after=started,
            phone_id=phone_id,
            timeout=120,
        )
        session = make_session(
            execution_id=self.args.execution_id,
            scenario=scenario,
            call=call,
            correlation_key=correlation_key,
            bridgefu_commit=self.bridgefu_lock["commit"],
            release=self.args.release,
            sip_uri=sip_uri,
        )
        private_json(session_path, session)
        wait_for_ssm_command(
            self.aws,
            command_id,
            instance,
            timeout=360,
        )
        self.ssm_commands.remove(command_id)
        self.complete_process(agent_process, "Amazon Connect SIP smoke observer", 360)
        source_observation = self.work / f"{scenario}-source.json"
        self.aws.text(["s3", "cp", remote_output, os.fspath(source_observation)])
        self.verify_scenario(scenario, session, source_observation, agent_observation)

    def verify_scenario(
        self,
        scenario: str,
        session: Mapping[str, Any],
        source_path: Path,
        agent_path: Path,
    ) -> None:
        source = read_json(source_path)
        agent = read_json(agent_path)
        validate_schema(
            source,
            "bridgefu-browser-source-observation-v1.schema.json"
            if scenario == WEB_SCENARIO
            else "source-observation-v1.schema.json",
        )
        validate_schema(agent, "participant-observation-v1.schema.json")
        if (
            source.get("execution_id") != self.args.execution_id
            or agent.get("execution_id") != self.args.execution_id
            or source.get("scenario_id") != scenario
            or agent.get("scenario_id") != scenario
            or agent.get("correlation_fingerprint")
            != session["correlation_fingerprint"]
        ):
            raise QualificationError(
                "browser observations do not bind to the smoke session"
            )
        deadline = time.monotonic() + 180
        while True:
            latest = (
                self.vapi.get("call", session["vapi_call_id"]) if self.vapi else None
            )
            if latest is not None and call_contains_transfer(latest, scenario):
                break
            if time.monotonic() >= deadline:
                raise QualificationError(
                    "Vapi call did not prove tool and transfer activity"
                )
            time.sleep(2)
        item = self.aws.json(
            [
                "dynamodb",
                "get-item",
                "--table-name",
                self.outputs["HandoffTableName"],
                "--key",
                json.dumps({"correlation_id": {"S": session["correlation_id"]}}),
                "--consistent-read",
            ]
        )
        handoff = verify_handoff_item(
            item.get("Item") if isinstance(item, Mapping) else None, session
        )
        start_time = str(max(0, int(session["started_epoch_ms"]) - 60_000))
        fingerprint = session["correlation_fingerprint"]
        deadline = time.monotonic() + 180
        while True:
            runtime = self.aws.json(
                [
                    "logs",
                    "filter-log-events",
                    "--log-group-name",
                    self.outputs["RuntimeLogGroupName"],
                    "--start-time",
                    start_time,
                    "--filter-pattern",
                    f'"{fingerprint}"',
                ]
            )
            lookup = self.aws.json(
                [
                    "logs",
                    "filter-log-events",
                    "--log-group-name",
                    self.outputs["LookupLogGroupName"],
                    "--start-time",
                    start_time,
                    "--filter-pattern",
                    f'"{fingerprint}"',
                ]
            )
            try:
                log_proof = verify_log_evidence(
                    runtime,
                    lookup,
                    fingerprint,
                    str(session["security"]),
                    scenario,
                )
                break
            except QualificationError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(3)
        checks = derive_scenario_checks(
            scenario, source, agent, latest, handoff, log_proof
        )
        passed = all(checks.values())
        if not passed:
            failed = ", ".join(key for key, value in checks.items() if not value)
            raise QualificationError(
                f"scenario evidence did not converge: {sanitize_diagnostic(failed, 512)}"
            )
        self.scenario_evidence.append(
            {
                "id": scenario,
                "source_observation_sha256": sha256_file(source_path),
                "agent_observation_sha256": sha256_file(agent_path),
                "runtime_security_evidence_sha256": log_proof[
                    "vapi_destination_security_evidence_sha256"
                ],
                "runtime_security_media_profile": log_proof[
                    "vapi_destination_media_profile"
                ],
                "runtime_security_media_keying": log_proof[
                    "vapi_destination_media_keying"
                ],
                "runtime_security_media_suite": log_proof[
                    "vapi_destination_media_suite"
                ],
                "runtime_security_srtp_negotiated": log_proof[
                    "vapi_destination_srtp_negotiated"
                ],
                "checks": checks,
                "passed": passed,
            }
        )

    def stop_active_work(self) -> list[str]:
        errors: list[str] = []
        for process in self.processes:
            try:
                terminate_owned_process(process)
            except QualificationError:
                errors.append("qualification subprocess cleanup failed")
        self.processes.clear()
        for command_id in self.ssm_commands:
            try:
                self.aws.text(["ssm", "cancel-command", "--command-id", command_id])
            except QualificationError:
                errors.append("qualification SSM command cancellation failed")
        self.ssm_commands.clear()
        return errors

    def record_retained_environment(self) -> None:
        private_json(
            self.args.output / "retained-state.json",
            {
                "schema_version": 1,
                "producer": PRODUCER,
                "producer_revision_sha256": sha256_file(Path(__file__)),
                "execution_id": self.args.execution_id,
                "region": self.args.region,
                "stack_name": self.stack_name,
                "observed_at": utc_now(),
                "redacted": True,
            },
        )

    def record_failure_evidence(self, error: BaseException) -> None:
        """Persist bounded stack diagnostics before any disposable cleanup."""
        stack_status: str | None = None
        failed_events: list[dict[str, Any]] = []
        capture_errors: list[str] = []
        if self.created_stack:
            try:
                description = self.aws.json(
                    [
                        "cloudformation",
                        "describe-stacks",
                        "--stack-name",
                        self.stack_name,
                    ],
                    timeout=120,
                )
                stacks = (
                    description.get("Stacks")
                    if isinstance(description, Mapping)
                    else None
                )
                if isinstance(stacks, list) and len(stacks) == 1:
                    observed_status = stacks[0].get("StackStatus")
                    if isinstance(observed_status, str):
                        stack_status = sanitize_diagnostic(observed_status, 128)
            except QualificationError as capture:
                capture_errors.append(sanitize_diagnostic(str(capture), 256))
            failed_events, event_error = collect_cloudformation_failure_events(
                self.aws, self.stack_name
            )
            if event_error is not None:
                capture_errors.append(event_error)
        capture_error = (
            sanitize_diagnostic("; ".join(capture_errors), 512)
            if capture_errors
            else None
        )
        value: dict[str, Any] = {
            "schema_version": 1,
            "producer": PRODUCER,
            "producer_revision_sha256": sha256_file(Path(__file__)),
            "execution_id": self.args.execution_id,
            "region": self.args.region,
            "stack_name": self.stack_name,
            "observed_at": utc_now(),
            "phase": self.phase,
            "summary": sanitize_diagnostic(str(error)),
            "cloudformation": {
                "observed": stack_status is not None or bool(failed_events),
                "stack_status": stack_status,
                "failed_events": failed_events,
                "capture_error": capture_error,
            },
            "redacted": True,
        }
        validate_schema(value, "failure-evidence-v1.schema.json")
        private_json(self.args.output / "failure-evidence.json", value)

    def cleanup(self) -> dict[str, Any]:
        errors = self.stop_active_work()
        errors.extend(self.cleanup_direct_context())
        errors.extend(self.cleanup_web_runtime())
        try:
            self.initialize_cleanup_vapi_verifier()
        except QualificationError:
            errors.append("Vapi cleanup verifier initialization failed")
        errors.extend(self.cleanup_vapi_provisioning_resilience())
        errors.extend(self.cleanup_sip_transients())
        errors.extend(self.cleanup_direct_assistant())
        try:
            self.ensure_acm_validation_journal()
        except QualificationError:
            errors.append("qualification ACM ownership sealing failed")
        phone_recovery_required = (
            self.temp_phone_id is not None
            or getattr(self, "temp_phone_intent", None) is not None
            or getattr(self, "temp_phone_creation_ambiguous", False)
            or self.temp_phone_journal_object is not None
            or getattr(self, "temp_phone_intent_journal_object", None) is not None
            or getattr(self, "temp_phone_request_journal_object", None) is not None
        )
        acm_recovery_required = (
            self.created_stack and not self.acm_validation_discovery_complete
        )
        direct_vapi_recovery_required = (
            getattr(self, "direct_vapi_cleanup_required", False)
            or getattr(self, "direct_identity_binding_installed", False)
            or getattr(self, "direct_assistant_id", None) is not None
            or getattr(self, "direct_assistant_creation_ambiguous", False)
            or getattr(self, "direct_tool_id", None) is not None
            or getattr(self, "direct_tool_creation_ambiguous", False)
        )
        ownership_recovery_required = (
            phone_recovery_required
            or direct_vapi_recovery_required
            or acm_recovery_required
            or getattr(self, "vapi_provisioning_cleanup_required", False)
        )
        if phone_recovery_required and not any(
            "Vapi" in error or "journal" in error for error in errors
        ):
            errors.append("temporary Vapi endpoint ownership cleanup is incomplete")
        if acm_recovery_required and not any("ACM" in error for error in errors):
            errors.append("qualification ACM ownership cleanup is incomplete")
        if direct_vapi_recovery_required and not any(
            "direct Vapi" in error for error in errors
        ):
            errors.append("direct Vapi resource ownership cleanup is incomplete")
        if getattr(self, "vapi_provisioning_cleanup_required", False) and not any(
            "provisioning resilience" in error for error in errors
        ):
            errors.append("Vapi provisioning resilience cleanup is incomplete")
        if (
            self.created_stack
            and not ownership_recovery_required
            and self.aws.exists(
                ["cloudformation", "describe-stacks", "--stack-name", self.stack_name]
            )
        ):
            try:
                self.aws.text(
                    ["cloudformation", "delete-stack", "--stack-name", self.stack_name]
                )
                self.aws.text(
                    [
                        "cloudformation",
                        "wait",
                        "stack-delete-complete",
                        "--stack-name",
                        self.stack_name,
                    ],
                    timeout=3600,
                )
            except QualificationError:
                errors.append("qualification stack deletion failed")
        stack_absent = not self.aws.exists(
            ["cloudformation", "describe-stacks", "--stack-name", self.stack_name]
        )
        acm_validation_absent = self.acm_validation_journal is None
        if self.acm_validation_journal is not None:
            if not stack_absent:
                acm_validation_absent = False
                errors.append("qualification ACM cleanup requires an absent stack")
            else:
                try:
                    delete_acm_validation_records_exact(
                        self.aws, self.acm_validation_journal
                    )
                    acm_validation_absent = True
                except QualificationError:
                    acm_validation_absent = False
                    errors.append("qualification ACM validation-record cleanup failed")
        artifact_bucket = self.outputs.get("ArtifactBucket")
        if (
            isinstance(artifact_bucket, str)
            and not ownership_recovery_required
            and acm_validation_absent
        ):
            try:
                purge_object_versions_exact(
                    self.aws,
                    artifact_bucket,
                    f"qualification/{self.args.execution_id}/",
                )
                self.acm_validation_journal_object = None
            except QualificationError:
                errors.append("qualification object version cleanup failed")
        connect_absent = True
        if self.outputs.get("ConnectInstanceId"):
            connect_absent = not self.aws.exists(
                [
                    "connect",
                    "describe-instance",
                    "--instance-id",
                    self.outputs["ConnectInstanceId"],
                ]
            )
        secret_absent = True
        if self.outputs.get("AgentCredentialSecretArn"):
            secret_absent = not self.aws.exists(
                [
                    "secretsmanager",
                    "describe-secret",
                    "--secret-id",
                    self.outputs["AgentCredentialSecretArn"],
                ]
            )
        objects_absent = True
        if self.outputs.get("ArtifactBucket"):
            try:
                objects_absent = not list_object_versions_exact(
                    self.aws,
                    self.outputs["ArtifactBucket"],
                    f"qualification/{self.args.execution_id}/",
                )
            except QualificationError:
                objects_absent = False
                errors.append("qualification object version proof failed")
        private_dns_absent = True
        if self.outputs.get("QualificationSipPrivateHostedZoneId"):
            try:
                private_dns_absent = not self.aws.exists(
                    [
                        "route53",
                        "get-hosted-zone",
                        "--id",
                        self.outputs["QualificationSipPrivateHostedZoneId"],
                    ]
                )
            except QualificationError:
                private_dns_absent = False
                errors.append("qualification private DNS proof failed")
        ids = [
            ("assistant", self.outputs.get("VapiAssistantId")),
            ("tool", self.outputs.get("VapiPrepareToolId")),
            ("credential", self.outputs.get("VapiWebhookCredentialId")),
            ("phone-number", self.temp_phone_id),
            ("assistant", getattr(self, "direct_assistant_id", None)),
            ("tool", getattr(self, "direct_tool_id", None)),
        ]
        vapi_absent = self.vapi is not None or not any(
            isinstance(resource_id, str) for _, resource_id in ids
        )
        if self.vapi is not None:
            for resource, resource_id in ids:
                if (
                    isinstance(resource_id, str)
                    and self.vapi.get(resource, resource_id) is not None
                ):
                    vapi_absent = False
        if phone_recovery_required or direct_vapi_recovery_required:
            vapi_absent = False
        zero = {
            "schema_version": 1,
            "producer": PRODUCER,
            "producer_revision_sha256": sha256_file(Path(__file__)),
            "execution_id": self.args.execution_id,
            "observed_at": utc_now(),
            "customer_stack_absent": stack_absent,
            "connect_instance_absent": connect_absent,
            "temporary_vapi_resources_absent": vapi_absent,
            "test_credentials_absent": secret_absent,
            "qualification_objects_absent": objects_absent,
            "qualification_private_dns_absent": private_dns_absent,
            "qualification_acm_validation_records_absent": acm_validation_absent,
            "redacted": True,
        }
        private_json(self.args.output / "zero-state.json", zero)
        try:
            validate_schema(zero, "zero-state-observation-v1.schema.json")
        except QualificationError:
            errors.append("zero-resource proof failed")
        if errors:
            raise QualificationError("; ".join(errors))
        return zero

    def run(self) -> None:
        primary_error: BaseException | None = None
        zero: dict[str, Any] | None = None
        try:
            self.phase = "input_validation"
            self.validate_inputs()
            self.phase = "web_site_validation"
            site, site_digest = self.build_site()
            self.phase = "preflight"
            self.preflight()
            self.phase = "cloudformation_deploy"
            self.deploy()
            self.phase = "connect_authentication"
            storage = self.authenticate_agent()
            self.phase = "direct_secure_preflight"
            self.direct_secure_preflight(storage)
            self.phase = "credential_initialization"
            self.initialize_vapi()
            correlation_key = self.aws.secret(self.outputs["CorrelationKeySecretArn"])
            self.phase = "vapi_web_transfer"
            self.web_smoke(site, site_digest, storage, correlation_key)
            self.phase = "vapi_sip_transfer"
            self.sip_smoke(storage, correlation_key)
            self.phase = "vapi_provisioning_resilience"
            self.vapi_provisioning_resilience()
        except BaseException as error:
            primary_error = error
            try:
                self.record_failure_evidence(error)
            except BaseException as capture_error:
                if isinstance(primary_error, QualificationError):
                    primary_error = QualificationError(
                        f"{primary_error}; failure evidence capture failed: "
                        + sanitize_diagnostic(str(capture_error), 512)
                    )
        try:
            retain_environment = (
                primary_error is not None
                and self.args.retain_on_failure
                and (
                    not self.secure_preflight_cleanup_required
                    or self.secure_preflight_cleanup_passed
                )
                and not getattr(self, "web_runtime_cleanup_required", False)
                and self.temp_phone_id is None
                and getattr(self, "temp_phone_intent", None) is None
                and not getattr(self, "temp_phone_creation_ambiguous", False)
                and getattr(self, "temp_phone_intent_journal_object", None) is None
                and getattr(self, "temp_phone_request_journal_object", None) is None
                and getattr(self, "temp_phone_journal_object", None) is None
                and not getattr(self, "direct_vapi_cleanup_required", False)
                and not getattr(self, "direct_identity_binding_installed", False)
                and getattr(self, "direct_assistant_id", None) is None
                and not getattr(self, "direct_assistant_creation_ambiguous", False)
                and getattr(self, "direct_tool_id", None) is None
                and not getattr(self, "direct_tool_creation_ambiguous", False)
                and not getattr(self, "vapi_provisioning_cleanup_required", False)
            )
            if retain_environment:
                self.phase = "retained_after_failure"
                retention_errors = self.stop_active_work()
                try:
                    self.ensure_acm_validation_journal()
                except BaseException as error:
                    retention_errors.append(
                        "qualification ACM ownership sealing failed: "
                        + sanitize_diagnostic(str(error), 512)
                    )
                try:
                    self.record_retained_environment()
                except BaseException as error:
                    retention_errors.append(
                        "retained environment receipt failed: "
                        + sanitize_diagnostic(str(error), 512)
                    )
                if retention_errors:
                    primary_error = combine_failures(
                        primary_error,
                        QualificationError("; ".join(retention_errors)),
                        label="retention",
                    )
            else:
                try:
                    self.phase = "cleanup"
                    zero = self.cleanup()
                except BaseException as error:
                    primary_error = combine_failures(primary_error, error)
        finally:
            shutil.rmtree(self.work, ignore_errors=True)
        if primary_error is not None:
            if isinstance(primary_error, QualificationError):
                raise primary_error
            raise QualificationError(
                "qualification failed unexpectedly"
            ) from primary_error
        if (
            zero is None
            or self.secure_preflight_evidence is None
            or self.vapi_provisioning_resilience_evidence is None
            or {item["id"] for item in self.scenario_evidence} != set(SCENARIOS)
            or len(self.scenario_evidence) != len(SCENARIOS)
        ):
            raise QualificationError(
                "secure preflight and both release smokes did not pass"
            )
        evidence = {
            "schema_version": 2,
            "release": self.args.release,
            "execution_id": self.args.execution_id,
            "region": self.args.region,
            "started_at": self.started_at,
            "ended_at": utc_now(),
            "bridgefu_commit": self.bridgefu_lock["commit"],
            "secure_preflight": self.secure_preflight_evidence,
            "vapi_provisioning_resilience": (
                self.vapi_provisioning_resilience_evidence
            ),
            "scenarios": sorted(self.scenario_evidence, key=lambda item: item["id"]),
            "teardown": {
                "customer_stack_absent": zero["customer_stack_absent"],
                "connect_instance_absent": zero["connect_instance_absent"],
                "temporary_vapi_resources_absent": zero[
                    "temporary_vapi_resources_absent"
                ],
                "test_credentials_absent": zero["test_credentials_absent"],
                "qualification_objects_absent": zero["qualification_objects_absent"],
                "qualification_private_dns_absent": zero[
                    "qualification_private_dns_absent"
                ],
                "qualification_acm_validation_records_absent": zero[
                    "qualification_acm_validation_records_absent"
                ],
            },
            "redacted": True,
        }
        validate_schema(evidence, "evidence-v2.schema.json")
        private_json(self.args.output / "evidence.json", evidence)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("run", nargs="?")
    value.add_argument("--execution-id", required=True)
    value.add_argument("--release", required=True)
    value.add_argument("--region", required=True, choices=sorted(REGIONS))
    value.add_argument("--template-url", required=True)
    value.add_argument("--vapi-secret-arn", required=True)
    value.add_argument("--hosted-zone-id", required=True)
    value.add_argument("--hosted-zone-name", required=True)
    value.add_argument("--cloudformation-role-arn", required=True)
    value.add_argument("--bridgefu-checkout", required=True, type=Path)
    value.add_argument("--sip-client", required=True, type=Path)
    value.add_argument("--direct-secure-probe", required=True, type=Path)
    value.add_argument("--demo-site-archive", required=True, type=Path)
    value.add_argument("--demo-site-sha256", required=True)
    value.add_argument("--instance-type", default="c7g.2xlarge")
    value.add_argument(
        "--retain-on-failure",
        action="store_true",
        help=(
            "disable CloudFormation rollback and retain disposable AWS and Vapi "
            "resources after a failed troubleshooting run"
        ),
    )
    value.add_argument("--output", type=Path, default=Path("target/qualification"))
    return value


def main() -> int:
    args = parser().parse_args()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        Controller(args).run()
    except QualificationError as error:
        print(f"qualification failed: {error}", file=os.sys.stderr)
        return 1
    print(args.output / "evidence.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
