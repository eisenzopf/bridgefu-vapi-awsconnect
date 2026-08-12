#!/usr/bin/env python3
"""Capture one redacted Vapi transfer SDP from an explicitly retained test stack.

This maintainer diagnostic is deliberately separate from normal qualification.
It temporarily redirects only the two stack-configured Vapi signaling /32s to
the one-shot rvoip observer and retains only its closed-vocabulary summary.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import re
import secrets
import shlex
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if os.fspath(ROOT) not in sys.path:
    sys.path.insert(0, os.fspath(ROOT))

from qualification.controller import (
    EXECUTION_ID,
    RESOURCE_ID,
    Aws,
    CommandRunner,
    QualificationError,
    Vapi,
    extract_vapi_key,
    list_object_versions_exact,
    private_json,
    purge_object_versions_exact,
    sanitize_diagnostic,
    wait_for_vapi_phone_active,
)

PRODUCER = "bridgefu-vapi-sdp-capture@1"
REGIONS = {"us-west-2", "us-east-1"}
PROFILE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
STACK_NAME = re.compile(r"^[A-Za-z][-A-Za-z0-9]{0,127}$")
REMOTE_PATH = re.compile(r"^/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
STACK_ARN = re.compile(
    r"^arn:aws[-a-z0-9]*:cloudformation:(us-west-2|us-east-1):[0-9]{12}:"
    r"stack/[A-Za-z][-A-Za-z0-9]{0,127}/[A-Za-z0-9-]+$"
)
INSTANCE_ID = re.compile(r"^i-[0-9a-f]{8,17}$")
SECRET_ARN = re.compile(
    r"^arn:aws[-a-z0-9]*:secretsmanager:(us-west-2|us-east-1):[0-9]{12}:"
    r"secret:[A-Za-z0-9/_+=.@-]+$"
)
COMMAND_ID = re.compile(r"^[0-9a-f-]{16,64}$")
TERMINAL_SSM = {"Success", "Cancelled", "Failed", "TimedOut"}
ACTIVE_SSM = {"Pending", "InProgress", "Delayed", "Cancelling"}
MAX_SSM_OUTPUT = 24 * 1024

MEDIA_KINDS = {"audio", "video", "application", "text", "message", "other"}
TRANSPORTS = {
    "RTP/AVP",
    "RTP/AVPF",
    "RTP/SAVP",
    "RTP/SAVPF",
    "UDP/TLS/RTP/SAVP",
    "UDP/TLS/RTP/SAVPF",
    "TCP/TLS/RTP/SAVP",
    "TCP/TLS/RTP/SAVPF",
    "UDP/DTLS/SCTP",
    "TCP/DTLS/SCTP",
    "DTLS/SCTP",
    "TCP/MSRP",
    "TCP/TLS/MSRP",
    "other",
}
CODECS = {
    "PCMU",
    "PCMA",
    "G722",
    "GSM",
    "opus",
    "CN",
    "telephone-event",
    "red",
    "ulpfec",
    "rtx",
    "VP8",
    "VP9",
    "H264",
    "AV1",
    "other",
}
SDES_SUITES = {
    "AES_CM_128_HMAC_SHA1_80",
    "AES_CM_128_HMAC_SHA1_32",
    "AES_192_CM_HMAC_SHA1_80",
    "AES_192_CM_HMAC_SHA1_32",
    "AES_256_CM_HMAC_SHA1_80",
    "AES_256_CM_HMAC_SHA1_32",
    "F8_128_HMAC_SHA1_80",
    "F8_192_HMAC_SHA1_80",
    "F8_256_HMAC_SHA1_80",
    "AEAD_AES_128_GCM",
    "AEAD_AES_256_GCM",
}
FINGERPRINT_ALGORITHMS = {"sha-1", "sha-224", "sha-256", "sha-384", "sha-512"}
SETUP_VALUES = {"active", "passive", "actpass", "holdconn"}
WIRE_FRAMING = {
    "complete",
    "header-too-large",
    "line-too-long",
    "too-many-headers",
    "invalid-header-syntax",
    "invalid-header-name",
    "missing-content-length",
    "duplicate-content-length",
    "invalid-content-length",
    "content-length-overflow",
    "body-too-large",
    "message-too-large",
    "diagnostic-limit",
    "eof-empty",
    "eof-incomplete",
    "read-failed",
    "read-timeout",
}
WIRE_PARSE = {"accepted", "rejected", "not-attempted"}
WIRE_METHODS = {
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "REGISTER",
    "OPTIONS",
    "SUBSCRIBE",
    "NOTIFY",
    "UPDATE",
    "REFER",
    "INFO",
    "MESSAGE",
    "PRACK",
    "PUBLISH",
    "other",
    "none",
}


class DiagnosticError(RuntimeError):
    """Expected fail-closed diagnostic error without remote body reflection."""


class ProfileRunner(CommandRunner):
    """Inject one explicit AWS profile without changing inherited environment."""

    def __init__(self, profile: str) -> None:
        if not PROFILE.fullmatch(profile):
            raise DiagnosticError("AWS profile is invalid")
        self.profile = profile

    def arguments(self, values: list[str]) -> list[str]:
        if values and values[0] == "aws":
            return ["aws", "--profile", self.profile, *values[1:]]
        return values

    def run(self, arguments: list[str], **kwargs: Any) -> str:
        return super().run(self.arguments(arguments), **kwargs)

    def probe(self, arguments: list[str], **kwargs: Any) -> tuple[int, str, str]:
        return super().probe(self.arguments(arguments), **kwargs)


@dataclass(frozen=True)
class Target:
    instance_id: str
    assistant_id: str
    artifact_bucket: str
    signaling_cidrs: tuple[str, str]


def exact_object(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise DiagnosticError(f"{label} has an invalid shape")
    return value


def stack_parameters(description: Any) -> dict[str, str]:
    try:
        values = description["Stacks"][0]["Parameters"]
    except (KeyError, IndexError, TypeError) as error:
        raise DiagnosticError("stack parameters are unavailable") from error
    result = {
        item["ParameterKey"]: item["ParameterValue"]
        for item in values
        if isinstance(item, Mapping)
        and isinstance(item.get("ParameterKey"), str)
        and isinstance(item.get("ParameterValue"), str)
    }
    return result


def stack_outputs(description: Any) -> dict[str, str]:
    try:
        values = description["Stacks"][0]["Outputs"]
    except (KeyError, IndexError, TypeError) as error:
        raise DiagnosticError("stack outputs are unavailable") from error
    return {
        item["OutputKey"]: item["OutputValue"]
        for item in values
        if isinstance(item, Mapping)
        and isinstance(item.get("OutputKey"), str)
        and isinstance(item.get("OutputValue"), str)
    }


def described_stack(description: Any, expected_name: str) -> Mapping[str, Any]:
    try:
        stacks = description["Stacks"]
    except (KeyError, TypeError) as error:
        raise DiagnosticError("stack description is unavailable") from error
    if (
        not isinstance(stacks, list)
        or len(stacks) != 1
        or not isinstance(stacks[0], Mapping)
    ):
        raise DiagnosticError("stack description is ambiguous")
    stack = stacks[0]
    if stack.get("StackName") != expected_name or stack.get("StackStatus") not in {
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
    }:
        raise DiagnosticError("retained stack identity or status is invalid")
    return stack


def nested_stack_arn(aws: Aws, parent: str, logical_id: str) -> str:
    response = aws.json(
        ["cloudformation", "list-stack-resources", "--stack-name", parent]
    )
    values = (
        response.get("StackResourceSummaries")
        if isinstance(response, Mapping)
        else None
    )
    matches = [
        item
        for item in values or []
        if isinstance(item, Mapping)
        and item.get("LogicalResourceId") == logical_id
        and item.get("ResourceType") == "AWS::CloudFormation::Stack"
        and item.get("ResourceStatus") in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
        and isinstance(item.get("PhysicalResourceId"), str)
        and STACK_ARN.fullmatch(item["PhysicalResourceId"])
        and STACK_ARN.fullmatch(item["PhysicalResourceId"]).group(1) == aws.region
    ]
    if len(matches) != 1:
        raise DiagnosticError(f"{logical_id} nested stack identity is not exact")
    return str(matches[0]["PhysicalResourceId"])


def exact_stack_resource(
    aws: Aws,
    stack: str,
    logical_id: str,
    resource_type: str,
    identity: re.Pattern[str],
) -> str:
    response = aws.json(
        ["cloudformation", "list-stack-resources", "--stack-name", stack]
    )
    values = (
        response.get("StackResourceSummaries")
        if isinstance(response, Mapping)
        else None
    )
    matches = [
        item
        for item in values or []
        if isinstance(item, Mapping)
        and item.get("LogicalResourceId") == logical_id
        and item.get("ResourceType") == resource_type
        and item.get("ResourceStatus") in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
        and isinstance(item.get("PhysicalResourceId"), str)
        and identity.fullmatch(item["PhysicalResourceId"])
    ]
    if len(matches) != 1:
        raise DiagnosticError(f"{logical_id} stack resource identity is not exact")
    return str(matches[0]["PhysicalResourceId"])


def exact_signaling_cidrs(parameters: Mapping[str, str]) -> tuple[str, str]:
    if any(parameters.get(f"VapiSignalingCidr{index}", "") for index in (3, 4)):
        raise DiagnosticError("runtime has more than two signaling CIDRs")
    result: list[str] = []
    for name in ("VapiSignalingCidr1", "VapiSignalingCidr2"):
        value = parameters.get(name)
        try:
            network = ipaddress.ip_network(value or "", strict=True)
        except ValueError as error:
            raise DiagnosticError("signaling CIDR is invalid") from error
        if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 32:
            raise DiagnosticError("signaling CIDRs must be IPv4 /32s")
        result.append(network.with_prefixlen)
    if len(set(result)) != 2:
        raise DiagnosticError("exactly two distinct signaling /32s are required")
    return result[0], result[1]


def tags(value: Any) -> dict[str, str]:
    if not isinstance(value, list):
        raise DiagnosticError("instance tags are unavailable")
    return {
        item["Key"]: item["Value"]
        for item in value
        if isinstance(item, Mapping)
        and isinstance(item.get("Key"), str)
        and isinstance(item.get("Value"), str)
    }


def validate_sdp_summary(value: Any) -> Mapping[str, Any]:
    root = exact_object(
        value,
        {
            "schema_version",
            "producer",
            "wire",
            "sdp_present",
            "media",
            "sdes",
            "dtls",
            "redacted",
        },
        "SDP summary",
    )
    if (
        root["schema_version"] != 2
        or root["producer"] != "bridgefu-sdp-observer@2"
        or not isinstance(root["sdp_present"], bool)
        or root["redacted"] is not True
        or not isinstance(root["media"], list)
        or len(root["media"]) > 16
    ):
        raise DiagnosticError("SDP summary root is invalid")
    wire = exact_object(
        root["wire"],
        {
            "tls_handshake",
            "decrypted_payload_present",
            "framing",
            "rvoip_sip_parse",
            "message_kind",
            "method",
            "request_uri_scheme",
            "header_count",
            "via_count",
            "contact_count",
            "content_type_count",
            "content_length_count",
            "correlation_header_count",
            "content_type",
            "body_present",
            "rvoip_sdp_parse",
        },
        "SIP wire summary",
    )
    wire_counts = [
        wire[name]
        for name in (
            "header_count",
            "via_count",
            "contact_count",
            "content_type_count",
            "content_length_count",
            "correlation_header_count",
        )
    ]
    if (
        wire["tls_handshake"] != "accepted"
        or not isinstance(wire["decrypted_payload_present"], bool)
        or wire["framing"] not in WIRE_FRAMING
        or wire["rvoip_sip_parse"] not in WIRE_PARSE
        or wire["message_kind"] not in {"request", "response", "unknown"}
        or wire["method"] not in WIRE_METHODS
        or wire["request_uri_scheme"] not in {"sip", "sips", "other", "none", "unknown"}
        or any(type(item) is not int or not 0 <= item <= 100 for item in wire_counts)
        or wire["content_type"]
        not in {"absent", "application/sdp", "other", "conflicting"}
        or not isinstance(wire["body_present"], bool)
        or wire["rvoip_sdp_parse"] not in WIRE_PARSE
        or (wire["framing"] == "complete")
        != (wire["rvoip_sip_parse"] in {"accepted", "rejected"})
        or (
            wire["rvoip_sdp_parse"] in {"accepted", "rejected"}
            and (
                wire["content_type"] != "application/sdp"
                or wire["body_present"] is not True
            )
        )
    ):
        raise DiagnosticError("SIP wire summary is invalid")
    for media in root["media"]:
        media = exact_object(
            media, {"kind", "transport", "payload_types", "codecs"}, "media summary"
        )
        if (
            media["kind"] not in MEDIA_KINDS
            or media["transport"] not in TRANSPORTS
            or not isinstance(media["payload_types"], list)
            or len(media["payload_types"]) > 128
            or any(
                type(item) is not int or not 0 <= item <= 127
                for item in media["payload_types"]
            )
            or not isinstance(media["codecs"], list)
            or len(media["codecs"]) > 128
        ):
            raise DiagnosticError("media summary is invalid")
        for codec in media["codecs"]:
            codec = exact_object(codec, {"payload_type", "name"}, "codec summary")
            if (
                type(codec["payload_type"]) is not int
                or not 0 <= codec["payload_type"] <= 127
                or codec["name"] not in CODECS
            ):
                raise DiagnosticError("codec summary is invalid")
    sdes = exact_object(
        root["sdes"],
        {"crypto_line_count", "suites", "unrecognized_suite_count"},
        "SDES summary",
    )
    dtls = exact_object(
        root["dtls"],
        {
            "fingerprint_present",
            "fingerprint_line_count",
            "fingerprint_algorithms",
            "unrecognized_fingerprint_algorithm_count",
            "setup_values",
            "unrecognized_setup_value_count",
        },
        "DTLS summary",
    )
    counts = (
        sdes["crypto_line_count"],
        sdes["unrecognized_suite_count"],
        dtls["fingerprint_line_count"],
        dtls["unrecognized_fingerprint_algorithm_count"],
        dtls["unrecognized_setup_value_count"],
    )
    if (
        any(type(item) is not int or not 0 <= item <= 2048 for item in counts)
        or not isinstance(sdes["suites"], list)
        or any(item not in SDES_SUITES for item in sdes["suites"])
        or not isinstance(dtls["fingerprint_present"], bool)
        or not isinstance(dtls["fingerprint_algorithms"], list)
        or any(
            item not in FINGERPRINT_ALGORITHMS
            for item in dtls["fingerprint_algorithms"]
        )
        or not isinstance(dtls["setup_values"], list)
        or any(item not in SETUP_VALUES for item in dtls["setup_values"])
    ):
        raise DiagnosticError("SDP security summary is invalid")
    return root


def validate_cleanup_receipt(value: Any) -> Mapping[str, Any]:
    receipt = exact_object(
        value,
        {
            "schema_version",
            "producer",
            "execution_id",
            "observed_at",
            "ssm_commands_cancelled",
            "redirect_rules_absent",
            "observer_process_absent",
            "source_process_absent",
            "bridgefu_active",
            "temporary_vapi_endpoint_absent",
            "temporary_auth_object_absent",
            "passed",
            "redacted",
        },
        "cleanup receipt",
    )
    if (
        receipt["schema_version"] != 1
        or receipt["producer"] != PRODUCER
        or not EXECUTION_ID.fullmatch(str(receipt["execution_id"]))
        or not isinstance(receipt["observed_at"], str)
        or receipt["redacted"] is not True
    ):
        raise DiagnosticError("cleanup receipt identity is invalid")
    checks = [
        receipt[name]
        for name in (
            "ssm_commands_cancelled",
            "redirect_rules_absent",
            "observer_process_absent",
            "source_process_absent",
            "bridgefu_active",
            "temporary_vapi_endpoint_absent",
            "temporary_auth_object_absent",
        )
    ]
    if any(not isinstance(item, bool) for item in checks) or receipt["passed"] != all(
        checks
    ):
        raise DiagnosticError("cleanup receipt checks are invalid")
    return receipt


def utc_now() -> str:
    return (
        dt.datetime.now(dt.UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


class SdpCapture:
    def __init__(
        self, args: argparse.Namespace, runner: CommandRunner | None = None
    ) -> None:
        self.args = args
        self.runner = runner or ProfileRunner(args.profile)
        self.aws = Aws(args.region, self.runner)
        self.vapi: Vapi | None = None
        self.target: Target | None = None
        self.phone_id: str | None = None
        self.auth_object: str | None = None
        self.observer_command_id: str | None = None
        self.source_command_id: str | None = None
        self.summary: Mapping[str, Any] | None = None
        self.cleanup_receipt: Mapping[str, Any] | None = None

    def validate_inputs(self) -> None:
        if (
            not PROFILE.fullmatch(self.args.profile)
            or self.args.region not in REGIONS
            or not EXECUTION_ID.fullmatch(self.args.execution)
            or self.args.stack != f"bridgefu-{self.args.execution}"
            or not STACK_NAME.fullmatch(self.args.stack)
            or not SECRET_ARN.fullmatch(self.args.vapi_secret_arn)
            or SECRET_ARN.fullmatch(self.args.vapi_secret_arn).group(1)
            != self.args.region
            or any(
                not REMOTE_PATH.fullmatch(value)
                for value in (
                    self.args.observer_path,
                    self.args.sip_client,
                    self.args.prompt,
                )
            )
            or self.args.observer_path == self.args.sip_client
            or self.args.output.exists()
        ):
            raise DiagnosticError("diagnostic inputs are invalid")

    def discover_target(self) -> Target:
        description = self.aws.json(
            ["cloudformation", "describe-stacks", "--stack-name", self.args.stack]
        )
        described_stack(description, self.args.stack)
        outputs = stack_outputs(description)
        candidate = nested_stack_arn(self.aws, self.args.stack, "Candidate")
        candidate_description = self.aws.json(
            ["cloudformation", "describe-stacks", "--stack-name", candidate]
        )
        described_stack(candidate_description, candidate.split("/")[-2])
        candidate_parameters = stack_parameters(candidate_description)
        if (
            candidate_parameters.get("DataRetentionMode") != "TestDelete"
            or candidate_parameters.get("DeploymentId") != self.args.execution
        ):
            raise DiagnosticError("candidate is not the retained TestDelete deployment")
        runtime = nested_stack_arn(self.aws, candidate, "Runtime")
        runtime_description = self.aws.json(
            ["cloudformation", "describe-stacks", "--stack-name", runtime]
        )
        described_stack(runtime_description, runtime.split("/")[-2])
        runtime_parameters = stack_parameters(runtime_description)
        if runtime_parameters.get("DataRetentionMode") != "TestDelete":
            raise DiagnosticError("runtime is not TestDelete")
        cidrs = exact_signaling_cidrs(runtime_parameters)
        instance_id = outputs.get("BridgefuInstanceId", "")
        assistant_id = outputs.get("VapiAssistantId", "")
        bucket = outputs.get("ArtifactBucket", "")
        if (
            not INSTANCE_ID.fullmatch(instance_id)
            or not RESOURCE_ID.fullmatch(assistant_id)
            or not BUCKET.fullmatch(bucket)
        ):
            raise DiagnosticError("stack diagnostic outputs are invalid")
        if (
            exact_stack_resource(
                self.aws,
                runtime,
                "GatewayInstance",
                "AWS::EC2::Instance",
                INSTANCE_ID,
            )
            != instance_id
        ):
            raise DiagnosticError("stack output does not identify its exact runtime")
        instances = self.aws.json(
            ["ec2", "describe-instances", "--instance-ids", instance_id]
        )
        try:
            values = [
                instance
                for reservation in instances["Reservations"]
                for instance in reservation["Instances"]
            ]
        except (KeyError, TypeError) as error:
            raise DiagnosticError("instance description is unavailable") from error
        if len(values) != 1 or not isinstance(values[0], Mapping):
            raise DiagnosticError("instance identity is ambiguous")
        instance = values[0]
        instance_tags = tags(instance.get("Tags"))
        if (
            instance.get("InstanceId") != instance_id
            or instance.get("State", {}).get("Name") != "running"
            or instance_tags.get("Project") != "bridgefu-vapi-awsconnect"
            or instance_tags.get("ManagedBy") != "bridgefu-cloudformation"
            or instance_tags.get("BridgefuExecutionId") != self.args.execution
        ):
            raise DiagnosticError("instance is not the exact stack-owned runtime")
        return Target(instance_id, assistant_id, bucket, cidrs)

    def connect_vapi(self, target: Target) -> Vapi:
        vapi = Vapi(extract_vapi_key(self.aws.secret(self.args.vapi_secret_arn)))
        assistant = vapi.get("assistant", target.assistant_id)
        metadata = assistant.get("metadata") if isinstance(assistant, Mapping) else None
        if (
            not isinstance(metadata, Mapping)
            or metadata.get("bridgefu_deployment") != self.args.execution
        ):
            raise DiagnosticError("assistant is not owned by the retained stack")
        return vapi

    def prepare_phone(self, target: Target) -> tuple[dict[str, str], str]:
        if self.vapi is None:
            raise DiagnosticError("Vapi client is unavailable")
        authentication = {
            "realm": "sip.vapi.ai",
            "username": f"bfq_{secrets.token_hex(8)}",
            "password": secrets.token_urlsafe(24),
        }
        phone = self.vapi.create_phone(
            self.args.execution, target.assistant_id, authentication
        )
        phone_id = phone.get("id")
        expected_uri = f"sip:{authentication['username']}@sip.vapi.ai"
        if not isinstance(phone_id, str) or not RESOURCE_ID.fullmatch(phone_id):
            raise DiagnosticError("temporary Vapi endpoint identity is invalid")
        self.phone_id = phone_id
        if phone.get("sipUri") != expected_uri:
            raise DiagnosticError("temporary Vapi endpoint identity is invalid")
        wait_for_vapi_phone_active(
            self.vapi, phone_id, expected_uri, target.assistant_id
        )
        return authentication, expected_uri

    def object_uri(self, target: Target) -> str:
        return (
            f"s3://{target.artifact_bucket}/qualification/{self.args.execution}/"
            "diagnostics/sip-auth.json"
        )

    def upload_auth(self, target: Target, authentication: Mapping[str, str]) -> None:
        self.auth_object = self.object_uri(target)
        self.runner.run(
            [
                "aws",
                "s3",
                "cp",
                "-",
                self.auth_object,
                "--sse",
                "AES256",
                "--only-show-errors",
                "--region",
                self.args.region,
            ],
            input_text=json.dumps(authentication, separators=(",", ":")),
            timeout=120,
        )

    def rule(self, cidr: str) -> str:
        comment = f"bfq-sdp-{self.args.execution}"
        return " ".join(
            shlex.quote(value)
            for value in (
                "-p",
                "tcp",
                "-s",
                cidr,
                "--dport",
                "5061",
                "-m",
                "comment",
                "--comment",
                comment,
                "-j",
                "REDIRECT",
                "--to-ports",
                "15061",
            )
        )

    def run_directory(self) -> str:
        return f"/run/bridgefu-qualification/sdp-{self.args.execution}"

    def remote_cleanup_script(self, target: Target) -> str:
        run = shlex.quote(self.run_directory())
        observer = shlex.quote(self.args.observer_path)
        source = shlex.quote(self.args.sip_client)
        rules = [self.rule(cidr) for cidr in target.signaling_cidrs]
        remove_rules = "\n".join(
            f"while iptables -t nat -C PREROUTING {rule} >/dev/null 2>&1; do "
            f"iptables -t nat -D PREROUTING {rule} >/dev/null 2>&1 || break; done"
            for rule in rules
        )
        verify_rules = " && ".join(
            f"! iptables -t nat -C PREROUTING {rule} >/dev/null 2>&1" for rule in rules
        )
        return f"""set +e
run={run}
stop_owned() {{
  pid_file="$1"
  expected="$2"
  if [ -f "$pid_file" ]; then
    pid="$(cat "$pid_file" 2>/dev/null)"
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    actual="$(readlink -f "/proc/$pid/exe" 2>/dev/null)"
    if [ -n "$actual" ] && [ "$actual" != "$expected" ]; then return 1; fi
    if [ -n "$actual" ]; then
      kill "$pid" >/dev/null 2>&1
      for _ in $(seq 1 20); do kill -0 "$pid" >/dev/null 2>&1 || break; sleep 0.25; done
      kill -9 "$pid" >/dev/null 2>&1
    fi
    rm -f "$pid_file"
  fi
  return 0
}}
binary_absent() {{
  expected="$1"
  for entry in /proc/[0-9]*/exe; do
    [ "$(readlink -f "$entry" 2>/dev/null)" = "$expected" ] && return 1
  done
  return 0
}}
stop_owned "$run/source.pid" {source}; source_absent=$?
stop_owned "$run/observer.pid" {observer}; observer_absent=$?
{remove_rules}
rules_absent=1
command -v iptables >/dev/null 2>&1 && {verify_rules} && rules_absent=0
binary_absent {source} || source_absent=1
binary_absent {observer} || observer_absent=1
ss -H -ltn 'sport = :15061' 2>/dev/null | grep -q . && observer_absent=1
systemctl is-active --quiet bridgefu.service; bridgefu_active=$?
[ "$source_absent" -eq 0 ] && source_json=true || source_json=false
[ "$observer_absent" -eq 0 ] && observer_json=true || observer_json=false
[ "$rules_absent" -eq 0 ] && rules_json=true || rules_json=false
[ "$bridgefu_active" -eq 0 ] && bridgefu_json=true || bridgefu_json=false
rm -f "$run/ready" "$run/source.json" "$run/sdp-summary.json" "$run/source.pid" "$run/observer.pid"
[ "$source_absent" -eq 0 ] && [ "$observer_absent" -eq 0 ] && [ "$rules_absent" -eq 0 ] && rmdir "$run" >/dev/null 2>&1
printf '{{"redirect_rules_absent":%s,"observer_process_absent":%s,"source_process_absent":%s,"bridgefu_active":%s}}\\n' "$rules_json" "$observer_json" "$source_json" "$bridgefu_json"
exit 0"""

    def observer_script(self, target: Target) -> str:
        base = shlex.quote("/run/bridgefu-qualification")
        run = shlex.quote(self.run_directory())
        observer = shlex.quote(self.args.observer_path)
        rules = [self.rule(cidr) for cidr in target.signaling_cidrs]
        insert = "\n".join(
            f"iptables -t nat -I PREROUTING 1 {rule}" for rule in reversed(rules)
        )
        remove = "\n".join(
            f"while iptables -t nat -C PREROUTING {rule} >/dev/null 2>&1; do "
            f"iptables -t nat -D PREROUTING {rule} >/dev/null 2>&1 || break; done"
            for rule in rules
        )
        return f"""set -euo pipefail
umask 077
base={base}
run={run}
install -d -m 0700 -o root -g root "$base"
mkdir -m 0700 "$run"
summary="$run/sdp-summary.json"
ready="$run/ready"
observer_pid=''
cleanup() {{
  set +e
  rm -f "$ready"
{remove}
  if [ -n "$observer_pid" ] && kill -0 "$observer_pid" >/dev/null 2>&1; then kill "$observer_pid" >/dev/null 2>&1; wait "$observer_pid" >/dev/null 2>&1; fi
  rm -f "$run/observer.pid"
}}
trap cleanup EXIT INT TERM
[ "$(id -u)" -eq 0 ]
command -v iptables >/dev/null 2>&1
[ -x {observer} ]
[ -r /etc/bridgefu/tls/fullchain.pem ]
[ -r /etc/bridgefu/tls/private-key.pem ]
imds_token="$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)"
public_ip="$(curl -fsS -H "X-aws-ec2-metadata-token: $imds_token" http://169.254.169.254/latest/meta-data/public-ipv4)"
case "$public_ip" in ''|*[!0-9.]*) exit 1 ;; esac
{observer} --tls-bind 0.0.0.0:15061 --advertised "$public_ip:5061" --certificate /etc/bridgefu/tls/fullchain.pem --private-key /etc/bridgefu/tls/private-key.pem --output "$summary" --timeout-seconds 120 >/dev/null 2>/dev/null &
observer_pid=$!
printf '%s\\n' "$observer_pid" > "$run/observer.pid"
for _ in $(seq 1 120); do
  kill -0 "$observer_pid" >/dev/null 2>&1 || exit 1
  ss -H -ltn 'sport = :15061' 2>/dev/null | grep -q . && break
  sleep 0.25
done
ss -H -ltn 'sport = :15061' 2>/dev/null | grep -q .
{insert}
touch "$ready"
wait "$observer_pid"
[ -s "$summary" ]
cat "$summary"
rm -f "$summary"
""".replace("\n  ", "\n  ")

    def source_script(self, target: Target) -> str:
        run = shlex.quote(self.run_directory())
        source = shlex.quote(self.args.sip_client)
        prompt = shlex.quote(self.args.prompt)
        auth_object = shlex.quote(self.object_uri(target))
        rules = [self.rule(cidr) for cidr in target.signaling_cidrs]
        verify_rules = " && ".join(
            f"iptables -t nat -C PREROUTING {rule} >/dev/null 2>&1" for rule in rules
        )
        return f"""set -euo pipefail
umask 077
run={run}
for _ in $(seq 1 240); do
  [ -f "$run/ready" ] && ss -H -ltn 'sport = :15061' 2>/dev/null | grep -q . && {verify_rules} && break
  sleep 0.5
done
[ -f "$run/ready" ]
{verify_rules}
[ -x {source} ]
[ -r {prompt} ]
auth="$(aws s3 cp {auth_object} - --only-show-errors)"
username="$(printf '%s' "$auth" | jq -er '.username | select(test("^bfq_[a-f0-9]{{16}}$"))')"
imds_token="$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)"
public_ip="$(curl -fsS -H "X-aws-ec2-metadata-token: $imds_token" http://169.254.169.254/latest/meta-data/public-ipv4)"
case "$public_ip" in ''|*[!0-9.]*) exit 1 ;; esac
printf '%s' "$auth" | {source} --auth-stdin --sip-uri "sip:${{username}}@sip.vapi.ai" --prompt-pcm {prompt} --public-ip "$public_ip" --execution-id {shlex.quote(self.args.execution)} --output "$run/source.json" --timeout-seconds 180 >/dev/null 2>/dev/null &
source_pid=$!
unset auth username imds_token public_ip
printf '%s\\n' "$source_pid" > "$run/source.pid"
wait "$source_pid"
rm -f "$run/source.pid" "$run/source.json"
""".replace("\n  ", "\n  ")

    def send_shell(self, target: Target, script: str) -> str:
        # AWS-RunShellScript joins the `commands` array with real newlines. A
        # single JSON string containing a multiline script is instead written
        # with literal `\\n` bytes by the AWS CLI/SSM parameter path, which
        # makes bash parse the whole program as one malformed command.
        commands = script.splitlines()
        if (
            not commands
            or len(commands) > 512
            or any(not line or len(line.encode("utf-8")) > 8192 for line in commands)
        ):
            raise DiagnosticError("remote diagnostic script is invalid")
        command_id = self.aws.text(
            [
                "ssm",
                "send-command",
                "--instance-ids",
                target.instance_id,
                "--document-name",
                "AWS-RunShellScript",
                "--parameters",
                json.dumps({"commands": commands}, separators=(",", ":")),
                "--query",
                "Command.CommandId",
            ],
            timeout=120,
        )
        if not COMMAND_ID.fullmatch(command_id):
            raise DiagnosticError("SSM command identity is invalid")
        return command_id

    def invocation(
        self, target: Target, command_id: str, timeout: int
    ) -> Mapping[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            try:
                value = self.aws.json(
                    [
                        "ssm",
                        "get-command-invocation",
                        "--command-id",
                        command_id,
                        "--instance-id",
                        target.instance_id,
                    ],
                    timeout=60,
                )
            except QualificationError as error:
                if "InvocationDoesNotExist" not in str(error):
                    raise DiagnosticError("SSM invocation lookup failed") from error
                value = {"Status": "Pending"}
            if not isinstance(value, Mapping):
                raise DiagnosticError("SSM invocation shape is invalid")
            status = value.get("Status")
            if status in TERMINAL_SSM:
                return value
            if status not in ACTIVE_SSM:
                raise DiagnosticError("SSM invocation status is invalid")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DiagnosticError("SSM invocation timed out")
            time.sleep(min(0.5, remaining))

    def cancel_command(self, target: Target, command_id: str | None) -> bool:
        if command_id is None:
            return True
        try:
            current = self.aws.json(
                [
                    "ssm",
                    "get-command-invocation",
                    "--command-id",
                    command_id,
                    "--instance-id",
                    target.instance_id,
                ],
                timeout=60,
            )
            if isinstance(current, Mapping) and current.get("Status") in TERMINAL_SSM:
                return True
            self.aws.text(
                ["ssm", "cancel-command", "--command-id", command_id], timeout=60
            )
            terminal = self.invocation(target, command_id, 120)
            return terminal.get("Status") in TERMINAL_SSM
        except (QualificationError, DiagnosticError):
            return False

    def parse_ssm_json(
        self, invocation: Mapping[str, Any], label: str
    ) -> Mapping[str, Any]:
        raw = invocation.get("StandardOutputContent")
        if (
            not isinstance(raw, str)
            or not 2 <= len(raw.encode("utf-8")) <= MAX_SSM_OUTPUT
        ):
            raise DiagnosticError(f"{label} output is unavailable")
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise DiagnosticError(f"{label} output is invalid") from error
        if not isinstance(value, Mapping):
            raise DiagnosticError(f"{label} output shape is invalid")
        return value

    def remote_cleanup(self, target: Target) -> Mapping[str, bool]:
        try:
            command_id = self.send_shell(target, self.remote_cleanup_script(target))
            invocation = self.invocation(target, command_id, 180)
            if invocation.get("Status") != "Success":
                raise DiagnosticError("remote cleanup command failed")
            value = exact_object(
                self.parse_ssm_json(invocation, "cleanup"),
                {
                    "redirect_rules_absent",
                    "observer_process_absent",
                    "source_process_absent",
                    "bridgefu_active",
                },
                "remote cleanup",
            )
            if any(not isinstance(item, bool) for item in value.values()):
                raise DiagnosticError("remote cleanup checks are invalid")
            return dict(value)
        except (QualificationError, DiagnosticError):
            return {
                "redirect_rules_absent": False,
                "observer_process_absent": False,
                "source_process_absent": False,
                "bridgefu_active": False,
            }

    def delete_phone(self) -> bool:
        if self.phone_id is None:
            return True
        if self.vapi is None:
            return False
        try:
            self.vapi.delete("phone-number", self.phone_id)
            self.phone_id = None
            return True
        except QualificationError:
            return False

    def delete_auth(self) -> bool:
        if self.auth_object is None:
            return True
        try:
            if self.target is None:
                return False
            key = f"qualification/{self.args.execution}/diagnostics/sip-auth.json"
            purge_object_versions_exact(
                self.aws,
                self.target.artifact_bucket,
                key,
                exact_key=True,
            )
            self.auth_object = None
            return True
        except QualificationError:
            # A bounded delete can succeed even if the final verification read
            # is interrupted. Re-prove the exact key once; never infer success
            # merely from the delete request.
            try:
                if self.target is None or list_object_versions_exact(
                    self.aws,
                    self.target.artifact_bucket,
                    f"qualification/{self.args.execution}/diagnostics/sip-auth.json",
                    exact_key=True,
                ):
                    return False
                self.auth_object = None
                return True
            except QualificationError:
                return False

    def cleanup(self) -> Mapping[str, Any]:
        remote = {
            "redirect_rules_absent": False,
            "observer_process_absent": False,
            "source_process_absent": False,
            "bridgefu_active": False,
        }
        commands_cancelled = False
        if self.target is not None:
            source_cancelled = self.cancel_command(self.target, self.source_command_id)
            observer_cancelled = self.cancel_command(
                self.target, self.observer_command_id
            )
            commands_cancelled = source_cancelled and observer_cancelled
            remote = self.remote_cleanup(self.target)
        phone_absent = self.delete_phone()
        auth_absent = self.delete_auth()
        checks = [commands_cancelled, *remote.values(), phone_absent, auth_absent]
        receipt = {
            "schema_version": 1,
            "producer": PRODUCER,
            "execution_id": self.args.execution,
            "observed_at": utc_now(),
            "ssm_commands_cancelled": commands_cancelled,
            **remote,
            "temporary_vapi_endpoint_absent": phone_absent,
            "temporary_auth_object_absent": auth_absent,
            "passed": all(checks),
            "redacted": True,
        }
        return validate_cleanup_receipt(receipt)

    def execute(self) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        self.target = self.discover_target()
        self.vapi = self.connect_vapi(self.target)
        primary: BaseException | None = None
        summary: Mapping[str, Any] | None = None
        try:
            authentication, _ = self.prepare_phone(self.target)
            self.upload_auth(self.target, authentication)
            preflight = self.remote_cleanup(self.target)
            if not all(preflight.values()):
                raise DiagnosticError("remote diagnostic preflight cleanup failed")
            self.observer_command_id = self.send_shell(
                self.target, self.observer_script(self.target)
            )
            self.source_command_id = self.send_shell(
                self.target, self.source_script(self.target)
            )
            observer = self.invocation(self.target, self.observer_command_id, 180)
            if observer.get("Status") != "Success":
                raise DiagnosticError("SDP observer command failed")
            summary = validate_sdp_summary(self.parse_ssm_json(observer, "observer"))
            self.summary = summary
        except BaseException as error:
            primary = error
        receipt = self.cleanup()
        self.cleanup_receipt = receipt
        if primary is not None:
            if isinstance(primary, (DiagnosticError, QualificationError)):
                raise DiagnosticError(
                    sanitize_diagnostic(str(primary), 512)
                ) from primary
            raise DiagnosticError("SDP diagnostic failed unexpectedly") from primary
        if summary is None or receipt["passed"] is not True:
            raise DiagnosticError("SDP diagnostic or cleanup did not pass")
        return summary, receipt

    def run(self) -> None:
        self.validate_inputs()
        self.args.output.mkdir(parents=True, mode=0o700)
        self.args.output.chmod(0o700)
        try:
            self.execute()
        finally:
            if self.summary is not None:
                private_json(self.args.output / "sdp-summary.json", self.summary)
            if self.cleanup_receipt is not None:
                private_json(
                    self.args.output / "cleanup-receipt.json", self.cleanup_receipt
                )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("run", nargs="?", choices=("run",))
    value.add_argument("--profile", required=True)
    value.add_argument("--region", required=True, choices=sorted(REGIONS))
    value.add_argument("--stack", required=True)
    value.add_argument("--execution", required=True)
    value.add_argument("--observer-path", required=True)
    value.add_argument("--sip-client", required=True)
    value.add_argument("--prompt", required=True)
    value.add_argument("--vapi-secret-arn", required=True)
    value.add_argument("--output", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    args.output = args.output.resolve()
    try:
        SdpCapture(args).run()
    except (DiagnosticError, QualificationError):
        print("qualification SDP diagnostic failed", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
