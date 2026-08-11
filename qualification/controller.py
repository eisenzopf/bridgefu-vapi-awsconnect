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
import shutil
import socket
import subprocess
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

ROOT = Path(__file__).resolve().parents[1]
QUALIFICATION = ROOT / "qualification"
PRODUCER = "bridgefu-vapi-awsconnect-qualification@1"
RECIPE = "vapi-amazon-connect-screen-pop@1"
VAPI_BASE_URL = "https://api.vapi.ai"
REGIONS = {"us-west-2", "us-east-1"}
EXECUTION_ID = re.compile(r"^bfq-[a-z0-9-]{4,20}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")
RESOURCE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SCENARIOS = ("vapi-web-transfer", "vapi-sip-transfer")
CONTEXT = {
    "customer_name": "Bridgefu Synthetic Caller",
    "intent": "qualification",
    "verification_status": "synthetic",
}
CHECKS = {
    "vapi_call_connected": True,
    "vapi_transfer_invoked": True,
    "bridgefu_received_correlation_header": True,
    "amazon_connect_contact_connected": True,
    "configured_screen_pop_visible": True,
    "audio_source_to_agent": True,
    "audio_agent_to_source": True,
    "source_call_ended": True,
}


class QualificationError(RuntimeError):
    """Expected qualification failure with a non-sensitive message."""


def utc_now() -> str:
    return (
        dt.datetime.now(dt.UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


class CommandRunner:
    """Subprocess boundary kept injectable for fail-closed unit tests."""

    def run(
        self,
        arguments: list[str],
        *,
        input_text: str | None = None,
        cwd: Path | None = None,
        timeout: int = 900,
    ) -> str:
        try:
            result = subprocess.run(
                arguments,
                cwd=cwd,
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
            raise QualificationError(f"command failed: {arguments[0]} {arguments[1]}")
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
        missing = (
            "does not exist",
            "ResourceNotFoundException",
            "not found",
            "not exist",
        )
        if any(marker.lower() in error.lower() for marker in missing):
            return False
        raise QualificationError("AWS existence check failed")

    def secret(self, arn: str) -> str:
        value = self.json(["secretsmanager", "get-secret-value", "--secret-id", arn])
        secret = value.get("SecretString") if isinstance(value, Mapping) else None
        if not isinstance(secret, str) or not 8 <= len(secret) <= 16384:
            raise QualificationError("Secrets Manager value is missing or invalid")
        return secret


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
            raise QualificationError(
                f"Vapi API {method} failed with HTTP {error.code}"
            ) from error
        except (OSError, TimeoutError) as error:
            raise QualificationError(f"Vapi API {method} request failed") from error
        if len(raw) > 4 * 1024 * 1024:
            raise QualificationError("Vapi API response exceeded its bound")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise QualificationError("Vapi API returned invalid JSON") from error

    def get(self, resource: str, resource_id: str) -> Mapping[str, Any] | None:
        if not RESOURCE_ID.fullmatch(resource_id):
            raise QualificationError("Vapi resource ID is invalid")
        value = self.request("GET", f"/{resource}/{resource_id}", allow_missing=True)
        if value is not None and not isinstance(value, Mapping):
            raise QualificationError("Vapi API resource has an invalid shape")
        return value

    def list(self, resource: str) -> list[Mapping[str, Any]]:
        value = self.request("GET", f"/{resource}?limit=100")
        if not isinstance(value, list) or any(
            not isinstance(item, Mapping) for item in value
        ):
            raise QualificationError("Vapi API list has an invalid shape")
        return list(value)

    def create_phone(self, execution_id: str, assistant_id: str) -> Mapping[str, Any]:
        suffix = hashlib.sha256(execution_id.encode("ascii")).hexdigest()[:16]
        value = self.request(
            "POST",
            "/phone-number",
            {
                "provider": "vapi",
                "name": f"Bridgefu qualification {execution_id}",
                "sipUri": f"sip:bfq_{suffix}@sip.vapi.ai",
                "assistantId": assistant_id,
            },
        )
        if not isinstance(value, Mapping):
            raise QualificationError(
                "Vapi SIP endpoint creation returned an invalid shape"
            )
        return value

    def delete(self, resource: str, resource_id: str) -> None:
        if self.get(resource, resource_id) is not None:
            self.request("DELETE", f"/{resource}/{resource_id}")


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
        else f"Qualification {scenario} source hangup."
    )
    return {
        **CONTEXT,
        "issue_summary": issue,
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
) -> dict[str, Any]:
    call_id = call.get("id")
    org_id = call.get("orgId")
    if not isinstance(call_id, str) or not isinstance(org_id, str):
        raise QualificationError("Vapi call is missing its exact identity")
    correlation = derive_correlation_id(correlation_key, execution_id, org_id, call_id)
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
        "session_id": hashlib.sha256(f"{scenario}:{call_id}".encode()).hexdigest()[:24],
        "scenario_id": scenario,
        "hangup_origin": "source",
        "security": "sips_srtp",
        "codec": "negotiated" if scenario == "vapi-web-transfer" else "pcmu",
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
        "source_call_id": call_id,
        "source_org_id": org_id,
        "source_call_fingerprint": sha256_bytes(call_id.encode("ascii"))[:12],
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
        "ConnectInstanceId",
        "ConnectLoginUrl",
        "AgentCredentialSecretArn",
        "BridgefuInstanceId",
        "ArtifactBucket",
        "VapiAssistantId",
        "VapiPrepareToolId",
        "VapiWebhookCredentialId",
        "HandoffTableName",
        "CorrelationKeySecretArn",
        "RuntimeLogGroupName",
        "LookupLogGroupName",
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


def verify_handoff_item(item: Any, session: Mapping[str, Any]) -> None:
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


def json_objects_from_logs(
    events: Iterable[Mapping[str, Any]],
) -> Iterable[Mapping[str, Any]]:
    for event in events:
        message = event.get("message")
        if not isinstance(message, str):
            continue
        for candidate in (message, *message.splitlines()):
            start = candidate.find("{")
            if start < 0:
                continue
            try:
                value = json.loads(candidate[start:])
            except json.JSONDecodeError:
                continue
            if isinstance(value, Mapping):
                yield value
                fields = value.get("fields")
                if isinstance(fields, Mapping):
                    yield fields


def verify_log_evidence(runtime: Any, lookup: Any, fingerprint: str) -> None:
    runtime_events = runtime.get("events", []) if isinstance(runtime, Mapping) else []
    lookup_events = lookup.get("events", []) if isinstance(lookup, Mapping) else []
    header = any(
        value.get("event") == "bridgefu_sip_invite_evidence"
        and value.get("correlation_fingerprint") == fingerprint
        and value.get("header_name") == "x-correlation-id"
        and value.get("header_count") == 1
        for value in json_objects_from_logs(runtime_events)
    )
    available = any(
        value.get("event") == "bridgefu_correlation_evidence"
        and value.get("operation") == "connect_lookup"
        and value.get("correlation_fingerprint") == fingerprint
        and value.get("result") == "available"
        for value in json_objects_from_logs(lookup_events)
    )
    if not header or not available:
        raise QualificationError(
            "correlated Bridgefu and Connect log evidence did not converge"
        )


def call_contains_transfer(value: Any) -> bool:
    """Require both the owned tool and transfer activity in the final Vapi call."""
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
    return (
        isinstance(value, Mapping)
        and value.get("status") == "ended"
        and "prepare_handoff" in names
        and "transferCall" in names
        and transfer
    )


def create_failure_arguments(retain_on_failure: bool) -> list[str]:
    if retain_on_failure:
        return ["--disable-rollback"]
    return ["--on-failure", "DELETE"]


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
        self.created_stack = False
        self.processes: list[subprocess.Popen[str]] = []
        self.ssm_commands: list[str] = []
        self.started_at = utc_now()
        self.scenario_evidence: list[dict[str, Any]] = []
        self.bridgefu_lock = read_json(ROOT / "bridgefu.lock.json")

    def validate_inputs(self) -> None:
        if not EXECUTION_ID.fullmatch(self.args.execution_id):
            raise QualificationError("execution ID is invalid")
        if self.args.region not in REGIONS or not VERSION.fullmatch(self.args.release):
            raise QualificationError("release version or region is invalid")
        if not re.fullmatch(r"[A-Z0-9]{1,64}", self.args.hosted_zone_id):
            raise QualificationError("hosted zone ID is invalid")
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
        commit = self.bridgefu_lock.get("commit")
        lock_digest = self.bridgefu_lock.get("cargo_lock_sha256")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise QualificationError("Bridgefu source lock is invalid")
        if not isinstance(lock_digest, str) or not SHA256.fullmatch(lock_digest):
            raise QualificationError("Bridgefu Cargo lock digest is invalid")
        if not self.args.bridgefu_checkout.is_dir():
            raise QualificationError("pinned Bridgefu checkout is unavailable")

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
        private_key = extract_vapi_key(self.aws.secret(self.args.vapi_secret_arn))
        self.vapi = Vapi(private_key)
        for assistant in self.vapi.list("assistant"):
            metadata = assistant.get("metadata")
            if (
                isinstance(metadata, Mapping)
                and metadata.get("bridgefu_deployment") == self.args.execution_id
            ):
                raise QualificationError("execution Vapi assistant already exists")
        phone_name = f"Bridgefu qualification {self.args.execution_id}"
        if any(
            phone.get("name") == phone_name for phone in self.vapi.list("phone-number")
        ):
            raise QualificationError("execution Vapi SIP endpoint already exists")

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
                'commands=["systemctl is-active bridgefu.service","curl --fail --silent --show-error --max-time 5 http://127.0.0.1:9090/readyz"]',
                "--query",
                "Command.CommandId",
            ]
        )
        self.aws.text(
            [
                "ssm",
                "wait",
                "command-executed",
                "--command-id",
                command_id,
                "--instance-id",
                self.outputs["BridgefuInstanceId"],
            ],
            timeout=300,
        )

    def build_site(self) -> tuple[Path, str]:
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
        output = (
            checkout / "target" / f"qualification-demo-site-{self.args.execution_id}"
        )
        self.runner.run(
            [
                "python3",
                "scripts/build-recipe-demo-site.py",
                "--output",
                os.fspath(output),
            ],
            cwd=checkout,
            timeout=600,
        )
        archive = output / "demo-site.zip"
        digest = sha256_file(archive)
        site = self.work / "site"
        site.mkdir(mode=0o700)
        with zipfile.ZipFile(archive) as bundle:
            for info in bundle.infolist():
                destination = (site / info.filename).resolve()
                if site.resolve() not in destination.parents or info.is_dir():
                    raise QualificationError("demo site bundle contains an unsafe path")
            bundle.extractall(site)
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
        stdout, _ = process.communicate(json.dumps(parsed), timeout=240)
        if (
            process.returncode != 0
            or not storage.is_file()
            or stdout.strip() != os.fspath(storage)
        ):
            raise QualificationError("Amazon Connect agent authentication failed")
        self.processes.remove(process)
        return storage

    def wait_for_file(self, path: Path, timeout: int) -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.is_file():
                return read_json(path)
            time.sleep(0.25)
        raise QualificationError("qualification browser handshake timed out")

    def start_agent(
        self, session: Path, storage: Path, scenario: str
    ) -> tuple[subprocess.Popen[str], Path, Path]:
        observation = self.work / f"{scenario}-agent.json"
        screenshot = self.args.output / f"{scenario}-screen.png"
        process = self.runner.popen(
            [
                "node",
                os.fspath(QUALIFICATION / "browser" / "agent-workspace-playwright.mjs"),
                "observe",
                "--session",
                os.fspath(session),
                "--storage-state",
                os.fspath(storage),
                "--connect-url",
                self.outputs["ConnectLoginUrl"],
                "--screenshot",
                os.fspath(screenshot),
                "--observation",
                os.fspath(observation),
                "--timeout-seconds",
                "240",
            ]
        )
        self.processes.append(process)
        return process, observation, screenshot

    def complete_process(
        self, process: subprocess.Popen[str], label: str, timeout: int = 300
    ) -> None:
        try:
            process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise QualificationError(f"{label} timed out")
        if process.returncode != 0:
            raise QualificationError(f"{label} failed")
        if process in self.processes:
            self.processes.remove(process)

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
            for call in self.vapi.list("call"):
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

    def web_smoke(
        self, site: Path, site_digest: str, storage: Path, correlation_key: str
    ) -> None:
        scenario = "vapi-web-transfer"
        session_path = self.work / f"{scenario}-session.json"
        ready = self.work / f"{scenario}-ready.json"
        trigger = self.work / f"{scenario}-trigger.json"
        source_observation = self.work / f"{scenario}-source.json"
        env = dict(os.environ)
        env["VAPI_PUBLIC_KEY"] = self.args.vapi_public_key
        started = dt.datetime.now(dt.UTC)
        source_process = self.runner.popen(
            [
                "node",
                os.fspath(QUALIFICATION / "browser" / "vapi-web-playwright.mjs"),
                "observe",
                "--site-dir",
                os.fspath(site),
                "--assistant-id",
                self.outputs["VapiAssistantId"],
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
            ],
            env=env,
        )
        self.processes.append(source_process)
        ready_value = self.wait_for_file(ready, 120)
        call_id = (
            ready_value.get("call_id") if isinstance(ready_value, Mapping) else None
        )
        if not isinstance(call_id, str):
            raise QualificationError("Vapi browser did not report its call ID")
        call = self.wait_for_vapi_call(
            assistant_id=self.outputs["VapiAssistantId"],
            started_after=started,
            call_id=call_id,
        )
        session = make_session(
            execution_id=self.args.execution_id,
            scenario=scenario,
            call=call,
            correlation_key=correlation_key,
            bridgefu_commit=self.bridgefu_lock["commit"],
            release=self.args.release,
            sip_uri=None,
        )
        private_json(session_path, session)
        agent_process, agent_observation, _ = self.start_agent(
            session_path, storage, scenario
        )
        private_json(trigger, {"schema_version": 1, "execute": True})
        self.complete_process(source_process, "Vapi Web smoke source", 360)
        self.complete_process(agent_process, "Amazon Connect Web smoke observer", 360)
        self.verify_scenario(scenario, session, source_observation, agent_observation)

    def sip_smoke(self, storage: Path, correlation_key: str) -> None:
        if self.vapi is None:
            raise QualificationError("Vapi client is unavailable")
        scenario = "vapi-sip-transfer"
        phone = self.vapi.create_phone(
            self.args.execution_id, self.outputs["VapiAssistantId"]
        )
        phone_id = phone.get("id")
        sip_uri = phone.get("sipUri")
        if (
            not isinstance(phone_id, str)
            or not RESOURCE_ID.fullmatch(phone_id)
            or not isinstance(sip_uri, str)
            or not re.fullmatch(r"sip:[A-Za-z0-9_-]{8,128}@sip\.vapi\.ai", sip_uri)
        ):
            raise QualificationError("temporary Vapi SIP endpoint is invalid")
        self.temp_phone_id = phone_id
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
        commands = [
            "set -euo pipefail",
            f"install -d -m 0700 {remote_directory}",
            f"aws s3 cp s3://{bucket}/{prefix}/sip-client {remote_client}",
            f"aws s3 cp s3://{bucket}/{prefix}/prompt.pcm {remote_prompt}",
            f"chmod 0700 {remote_client}",
            (
                f"{remote_client} --sip-uri {sip_uri} --prompt-pcm {remote_prompt} "
                f"--public-ip {public_ip} --execution-id {self.args.execution_id} "
                f"--output {remote_observation} --timeout-seconds 240"
            ),
            f"aws s3 cp {remote_observation} {remote_output}",
            f"rm -f {remote_client} {remote_prompt} {remote_observation}",
            f"rmdir {remote_directory}",
        ]
        command_id = self.aws.text(
            [
                "ssm",
                "send-command",
                "--instance-ids",
                instance,
                "--document-name",
                "AWS-RunShellScript",
                "--parameters",
                "commands=" + json.dumps(commands, separators=(",", ":")),
                "--query",
                "Command.CommandId",
            ]
        )
        self.ssm_commands.append(command_id)
        started = dt.datetime.now(dt.UTC)
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
        session_path = self.work / f"{scenario}-session.json"
        private_json(session_path, session)
        agent_process, agent_observation, _ = self.start_agent(
            session_path, storage, scenario
        )
        self.aws.text(
            [
                "ssm",
                "wait",
                "command-executed",
                "--command-id",
                command_id,
                "--instance-id",
                instance,
            ],
            timeout=360,
        )
        self.ssm_commands.remove(command_id)
        self.complete_process(agent_process, "Amazon Connect SIP smoke observer", 360)
        source_observation = self.work / f"{scenario}-source.json"
        self.aws.text(["s3", "cp", remote_output, os.fspath(source_observation)])
        self.verify_scenario(scenario, session, source_observation, agent_observation)
        self.vapi.delete("phone-number", phone_id)
        self.temp_phone_id = None

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
            "vapi-source-observation-v1.schema.json"
            if scenario == "vapi-web-transfer"
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
                self.vapi.get("call", session["source_call_id"]) if self.vapi else None
            )
            if latest is not None and call_contains_transfer(latest):
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
        verify_handoff_item(
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
                verify_log_evidence(runtime, lookup, fingerprint)
                break
            except QualificationError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(3)
        self.scenario_evidence.append(
            {
                "id": scenario,
                "source_observation_sha256": sha256_file(source_path),
                "agent_observation_sha256": sha256_file(agent_path),
                "checks": dict(CHECKS),
                "passed": True,
            }
        )

    def stop_active_work(self) -> list[str]:
        errors: list[str] = []
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
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

    def cleanup(self) -> dict[str, Any]:
        errors = self.stop_active_work()
        if self.vapi is not None and self.temp_phone_id is not None:
            try:
                self.vapi.delete("phone-number", self.temp_phone_id)
            except QualificationError:
                errors.append("temporary Vapi SIP endpoint deletion failed")
        if self.outputs.get("ArtifactBucket"):
            try:
                self.aws.text(
                    [
                        "s3",
                        "rm",
                        f"s3://{self.outputs['ArtifactBucket']}/qualification/{self.args.execution_id}/",
                        "--recursive",
                    ]
                )
            except QualificationError:
                errors.append("qualification object cleanup failed")
        if self.created_stack and self.aws.exists(
            ["cloudformation", "describe-stacks", "--stack-name", self.stack_name]
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
            listed = self.aws.json(
                [
                    "s3api",
                    "list-objects-v2",
                    "--bucket",
                    self.outputs["ArtifactBucket"],
                    "--prefix",
                    f"qualification/{self.args.execution_id}/",
                    "--max-keys",
                    "1",
                ]
            )
            objects_absent = isinstance(listed, Mapping) and listed.get("KeyCount") == 0
        vapi_absent = True
        if self.vapi is not None:
            ids = [
                ("assistant", self.outputs.get("VapiAssistantId")),
                ("tool", self.outputs.get("VapiPrepareToolId")),
                ("credential", self.outputs.get("VapiWebhookCredentialId")),
                ("phone-number", self.temp_phone_id),
            ]
            for resource, resource_id in ids:
                if (
                    isinstance(resource_id, str)
                    and self.vapi.get(resource, resource_id) is not None
                ):
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
            "preexisting_connect_resources_mutated": False,
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
            self.validate_inputs()
            self.preflight()
            self.deploy()
            site, site_digest = self.build_site()
            storage = self.authenticate_agent()
            correlation_key = self.aws.secret(self.outputs["CorrelationKeySecretArn"])
            self.web_smoke(site, site_digest, storage, correlation_key)
            self.sip_smoke(storage, correlation_key)
        except BaseException as error:
            primary_error = error
        try:
            retain_environment = (
                primary_error is not None and self.args.retain_on_failure
            )
            if retain_environment:
                self.stop_active_work()
                self.record_retained_environment()
            else:
                try:
                    zero = self.cleanup()
                except BaseException as error:
                    if primary_error is None:
                        primary_error = error
        finally:
            shutil.rmtree(self.work, ignore_errors=True)
        if primary_error is not None:
            if isinstance(primary_error, QualificationError):
                raise primary_error
            raise QualificationError(
                "qualification failed unexpectedly"
            ) from primary_error
        if zero is None or {item["id"] for item in self.scenario_evidence} != set(
            SCENARIOS
        ):
            raise QualificationError("both release smokes did not pass")
        evidence = {
            "schema_version": 1,
            "release": self.args.release,
            "execution_id": self.args.execution_id,
            "region": self.args.region,
            "started_at": self.started_at,
            "ended_at": utc_now(),
            "bridgefu_commit": self.bridgefu_lock["commit"],
            "scenarios": sorted(self.scenario_evidence, key=lambda item: item["id"]),
            "teardown": {
                "customer_stack_absent": zero["customer_stack_absent"],
                "connect_instance_absent": zero["connect_instance_absent"],
                "temporary_vapi_resources_absent": zero[
                    "temporary_vapi_resources_absent"
                ],
                "test_credentials_absent": zero["test_credentials_absent"],
                "qualification_objects_absent": zero["qualification_objects_absent"],
            },
            "redacted": True,
        }
        validate_schema(evidence, "evidence-v1.schema.json")
        private_json(self.args.output / "evidence.json", evidence)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("run", nargs="?")
    value.add_argument("--execution-id", required=True)
    value.add_argument("--release", required=True)
    value.add_argument("--region", required=True, choices=sorted(REGIONS))
    value.add_argument("--template-url", required=True)
    value.add_argument("--vapi-secret-arn", required=True)
    value.add_argument(
        "--vapi-public-key", default=os.environ.get("VAPI_PUBLIC_KEY", "")
    )
    value.add_argument("--hosted-zone-id", required=True)
    value.add_argument("--hosted-zone-name", required=True)
    value.add_argument("--cloudformation-role-arn", required=True)
    value.add_argument("--bridgefu-checkout", required=True, type=Path)
    value.add_argument("--sip-client", required=True, type=Path)
    value.add_argument("--instance-type", default="t4g.large")
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
