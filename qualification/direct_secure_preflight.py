"""Pure contracts and remote programs for the direct-secure qualification gate.

This module deliberately has no AWS, SSM, subprocess, or diagnostic-module
dependencies.  The qualification controller owns transport and orchestration;
the helpers here only validate closed-vocabulary results and render deterministic
remote shell programs.

The remote probe obtains the already-uploaded static executable by an exact S3
key, verifies its SHA-256 before execution, and keeps the bearer, reservation
URI, and correlation value in remote process memory.  The private probe request
crosses only the child's standard input.  Successful stdout is therefore the
redacted Rust observation and cleanup stdout is an exact object of booleans.
"""

from __future__ import annotations

import copy
import json
import re
import shlex
import textwrap
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NoReturn

PRODUCER = "bridgefu-direct-secure-preflight@1"
PROBE_PRODUCER = "bridgefu-direct-secure-probe@1"
REGIONS = frozenset({"us-east-1", "us-west-2"})
REMOTE_BASE = "/run/bridgefu-qualification"
MAX_RESULT_BYTES = 16 * 1024

_EXECUTION_ID = re.compile(r"^bfq-[a-z0-9-]{4,20}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

PROBE_PHASES = frozenset(
    {
        "preflight",
        "preflight_identity",
        "preflight_runtime_files",
        "preflight_runtime_ownership",
        "preflight_workspace",
        "download_probe",
        "backup",
        "patch_configuration",
        "restart_patched_runtime",
        "restart_patched_service",
        "restart_patched_readiness",
        "reserve_and_probe",
        "restore",
        "validate_result",
        "emit_result",
        "complete",
    }
)
PROBE_DETAILS = frozenset(
    {
        "load_credentials",
        "reserve_route",
        "reserve_unavailable",
        "parse_reservation",
        "validate_reservation",
        "reservation_uri_missing",
        "reservation_scheme_mismatch",
        "reservation_target_mismatch",
        "reservation_token_length_mismatch",
        "reservation_token_charset_mismatch",
        "start_probe",
        "wait_probe",
        "validate_probe_output",
        "complete",
    }
)
CLEANUP_FIELDS = (
    "probe_process_absent",
    "configuration_restored",
    "private_dns_verified",
    "run_artifacts_absent",
    "bridgefu_active",
)

_EXPECTED_PROBE_RESULT: dict[str, Any] = {
    "schema_version": 1,
    "producer": PROBE_PRODUCER,
    "signaling": {
        "scheme": "sips",
        "transport": "tls",
        "invite_count": 1,
        "correlation_header_count": 1,
        "answered": True,
        "inbound_200": True,
        "outbound_ack": True,
        "contact_host": "dns",
        "contact_sips": True,
        "contact_tls": True,
        "trace_redacted": True,
    },
    "media": {
        "profile": "RTP/SAVP",
        "keying": "SDES-SRTP",
        "contexts_installed": True,
        "audio_opened": True,
        "marker_frames_sent": 10,
        "codec": "PCMU",
        "dtmf_requested": True,
        "in_band_dtmf_frames_sent": 15,
        "rfc4733_dtmf_sent": True,
    },
    "hangup": {"local_bye_completed": True, "cleanup_observed": True},
    "redacted": True,
}


class DirectSecurePreflightError(ValueError):
    """Expected, non-sensitive preflight contract failure."""


@dataclass(frozen=True)
class RemotePaths:
    """The exact owned paths for one execution's remote preflight."""

    base: str
    run: str
    probe: str
    result: str
    pid: str
    phase: str


def remote_paths(execution_id: str) -> RemotePaths:
    """Return exact remote paths after validating the execution identity."""
    _validate_execution_id(execution_id)
    run = f"{REMOTE_BASE}/direct-{execution_id}"
    return RemotePaths(
        base=REMOTE_BASE,
        run=run,
        probe=f"{run}/bridgefu-direct-secure-probe",
        result=f"{run}/probe.json",
        pid=f"{run}/probe.pid",
        phase=f"{run}/probe-phase",
    )


def expected_probe_result() -> dict[str, Any]:
    """Return a caller-owned copy of the fixed successful probe contract."""
    return copy.deepcopy(_EXPECTED_PROBE_RESULT)


def _validate_execution_id(execution_id: Any) -> None:
    if not isinstance(execution_id, str) or not _EXECUTION_ID.fullmatch(execution_id):
        raise DirectSecurePreflightError("direct secure execution ID is invalid")


def _validate_object_target(
    execution_id: str, region: Any, bucket: Any, key: Any, sha256: Any
) -> None:
    _validate_execution_id(execution_id)
    if not isinstance(region, str) or region not in REGIONS:
        raise DirectSecurePreflightError("direct secure region is invalid")
    if (
        not isinstance(bucket, str)
        or not _BUCKET.fullmatch(bucket)
        or ".." in bucket
        or ".-" in bucket
        or "-." in bucket
        or re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", bucket)
    ):
        raise DirectSecurePreflightError("direct secure artifact bucket is invalid")
    prefix = f"qualification/{execution_id}/"
    if (
        not isinstance(key, str)
        or not _KEY.fullmatch(key)
        or not key.startswith(prefix)
        or key.endswith("/")
        or "//" in key
        or any(part in {"", ".", ".."} for part in key.split("/"))
    ):
        raise DirectSecurePreflightError("direct secure artifact key is invalid")
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        raise DirectSecurePreflightError("direct secure executable digest is invalid")


def _typed_equal(observed: Any, expected: Any) -> bool:
    """Compare JSON-like values without Python's bool/int equivalence."""
    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(observed) == set(expected) and all(
            _typed_equal(observed[name], value) for name, value in expected.items()
        )
    if isinstance(expected, list):
        return len(observed) == len(expected) and all(
            _typed_equal(left, right) for left, right in zip(observed, expected)
        )
    return observed == expected


def validate_probe_result(value: Any) -> dict[str, Any]:
    """Accept only the Rust probe's exact, fully redacted success contract."""
    if not _typed_equal(value, _EXPECTED_PROBE_RESULT):
        raise DirectSecurePreflightError("direct secure probe result did not pass")
    return copy.deepcopy(value)


def validate_cleanup_receipt(value: Any) -> dict[str, bool]:
    """Validate the remote cleanup program's exact boolean-only receipt."""
    if (
        not isinstance(value, Mapping)
        or set(value) != set(CLEANUP_FIELDS)
        or any(type(value[name]) is not bool for name in CLEANUP_FIELDS)
    ):
        raise DirectSecurePreflightError("direct secure cleanup receipt is invalid")
    return {name: value[name] for name in CLEANUP_FIELDS}


def _reject_constant(_: str) -> NoReturn:
    raise ValueError("non-finite JSON value")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate JSON member")
        value[name] = item
    return value


def _parse_json(raw: Any, label: str) -> Any:
    if not isinstance(raw, str):
        raise DirectSecurePreflightError(f"direct secure {label} is unavailable")
    try:
        encoded_size = len(raw.encode("utf-8"))
    except UnicodeError as error:
        raise DirectSecurePreflightError(f"direct secure {label} is invalid") from error
    if not 2 <= encoded_size <= MAX_RESULT_BYTES:
        raise DirectSecurePreflightError(f"direct secure {label} is unavailable")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise DirectSecurePreflightError(f"direct secure {label} is invalid") from error


def parse_probe_result(raw: Any) -> dict[str, Any]:
    """Parse a bounded SSM stdout value and validate the probe contract."""
    return validate_probe_result(_parse_json(raw, "probe output"))


def parse_cleanup_receipt(raw: Any) -> dict[str, bool]:
    """Parse bounded SSM stdout and validate the cleanup receipt."""
    return validate_cleanup_receipt(_parse_json(raw, "cleanup output"))


def probe_script(
    execution_id: str,
    region: str,
    bucket: str,
    key: str,
    sha256: str,
) -> str:
    """Render the strict one-shot direct-secure remote probe program.

    All arguments are public identifiers.  Sensitive route inputs are created
    remotely, retained in Python memory, and delivered to the static executable
    only through stdin.
    """
    _validate_object_target(execution_id, region, bucket, key, sha256)
    paths = remote_paths(execution_id)
    substitutions = {
        "__EXECUTION__": shlex.quote(execution_id),
        "__REGION__": shlex.quote(region),
        "__BUCKET__": shlex.quote(bucket),
        "__KEY__": shlex.quote(key),
        "__SHA256__": shlex.quote(sha256),
        "__BASE__": shlex.quote(paths.base),
        "__RUN__": shlex.quote(paths.run),
        "__PROBE__": shlex.quote(paths.probe),
        "__RESULT__": shlex.quote(paths.result),
        "__PID__": shlex.quote(paths.pid),
        "__PHASE_FILE__": shlex.quote(paths.phase),
        "__MARKER__": shlex.quote(f"bfq-direct-secure-preflight-{execution_id}"),
    }
    script = _PROBE_SCRIPT
    for token, replacement in substitutions.items():
        script = script.replace(token, replacement)
    if re.search(r"__[A-Z0-9_]+__", script):
        raise AssertionError("direct secure probe template substitution is incomplete")
    return script


def cleanup_script(execution_id: str, probe_path: str) -> str:
    """Render an idempotent cleanup/proof program for exact owned paths."""
    paths = remote_paths(execution_id)
    if probe_path != paths.probe:
        raise DirectSecurePreflightError("direct secure probe path is invalid")
    substitutions = {
        "__BASE__": shlex.quote(paths.base),
        "__RUN__": shlex.quote(paths.run),
        "__PROBE__": shlex.quote(paths.probe),
        "__MARKER__": shlex.quote(f"bfq-direct-secure-preflight-{execution_id}"),
    }
    script = _CLEANUP_SCRIPT
    for token, replacement in substitutions.items():
        script = script.replace(token, replacement)
    if re.search(r"__[A-Z0-9_]+__", script):
        raise AssertionError(
            "direct secure cleanup template substitution is incomplete"
        )
    return script


_PROBE_SCRIPT = textwrap.dedent(
    r"""
    set -euo pipefail
    umask 077
    exec 3>&2 2>/dev/null
    execution=__EXECUTION__
    region=__REGION__
    bucket=__BUCKET__
    key=__KEY__
    expected_sha256=__SHA256__
    base=__BASE__
    run=__RUN__
    probe=__PROBE__
    result=__RESULT__
    pid_file=__PID__
    phase_file=__PHASE_FILE__
    marker=__MARKER__
    config=/etc/bridgefu/bridgefu.yaml
    runtime_config=/etc/bridgefu/runtime.conf
    runtime_secrets=/run/bridgefu/runtime.env
    config_temp="/etc/bridgefu/.bridgefu.yaml.$marker.tmp"
    phase=preflight
    restored=false

    owned_paths_safe() {
      if [ -e "$base" ] || [ -L "$base" ]; then
        [ -d "$base" ] && [ ! -L "$base" ] || return 1
        [ "$(stat -c '%U:%G:%a' "$base")" = 'root:root:700' ] || return 1
      fi
      if [ -e "$run" ] || [ -L "$run" ]; then
        [ -d "$run" ] && [ ! -L "$run" ] || return 1
        [ "$(stat -c '%U:%G:%a' "$run")" = 'root:root:700' ] || return 1
      fi
      return 0
    }

    stop_owned() {
      [ ! -L "$pid_file" ] || return 1
      if [ -f "$pid_file" ]; then
        pid="$(cat "$pid_file" 2>/dev/null)"
        case "$pid" in ''|*[!0-9]*) pid='' ;; esac
        if [ -n "$pid" ] \
          && [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" = "$probe" ]; then
          kill "$pid" >/dev/null 2>&1 || true
        fi
      fi
      for entry in /proc/[0-9]*/exe; do
        [ "$(readlink -f "$entry" 2>/dev/null)" = "$probe" ] || continue
        pid="${entry#/proc/}"
        pid="${pid%/exe}"
        case "$pid" in ''|*[!0-9]*) return 1 ;; esac
        kill "$pid" >/dev/null 2>&1 || true
      done
      for _ in $(seq 1 20); do
        binary_absent && break
        sleep 0.25
      done
      if ! binary_absent; then
        for entry in /proc/[0-9]*/exe; do
          [ "$(readlink -f "$entry" 2>/dev/null)" = "$probe" ] || continue
          pid="${entry#/proc/}"
          pid="${pid%/exe}"
          case "$pid" in ''|*[!0-9]*) return 1 ;; esac
          kill -9 "$pid" >/dev/null 2>&1 || true
        done
      fi
      binary_absent || return 1
      rm -f "$pid_file"
    }

    binary_absent() {
      for entry in /proc/[0-9]*/exe; do
        [ "$(readlink -f "$entry" 2>/dev/null)" = "$probe" ] && return 1
      done
      return 0
    }

    restore_owned() {
      [ "$restored" = false ] || return 0
      owned_paths_safe || return 1
      stop_owned || return 1
      binary_absent || return 1
      [ -f "$config" ] && [ ! -L "$config" ] || return 1
      [ "$(stat -c '%U:%G:%a' "$config")" = 'root:bridgefu:640' ] || return 1
      changed=false
      if [ -e "$run/bridgefu.yaml.original" ] || [ -L "$run/bridgefu.yaml.original" ]; then
        [ -f "$run/bridgefu.yaml.original" ] && [ ! -L "$run/bridgefu.yaml.original" ] || return 1
        cp --preserve=all "$run/bridgefu.yaml.original" "$config" >/dev/null 2>&1 || return 1
        cmp -s "$run/bridgefu.yaml.original" "$config" || return 1
        changed=true
      elif grep -Fq -- "$marker" "$config" 2>/dev/null; then
        return 1
      fi
      if [ "$changed" = true ]; then
        systemctl restart bridgefu.service >/dev/null 2>&1 || return 1
      fi
      for _ in $(seq 1 120); do
        if systemctl is-active --quiet bridgefu.service \
          && curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1; then
          restored=true
          return 0
        fi
        sleep 0.5
      done
      return 1
    }

    on_exit() {
      status=$?
      trap - EXIT INT TERM
      set +e
      restore_owned || status=1
      if [ "$status" -ne 0 ]; then
        case "$phase" in
          preflight|preflight_identity|preflight_runtime_files|preflight_runtime_ownership|preflight_workspace|download_probe|backup|patch_configuration|restart_patched_runtime|restart_patched_service|restart_patched_readiness|reserve_and_probe|restore|validate_result|emit_result|complete)
            printf 'direct_secure_preflight_phase=%s\n' "$phase" >&3
            ;;
          *) printf 'direct_secure_preflight_phase=preflight\n' >&3 ;;
        esac
        if [ -f "$phase_file" ]; then
          detail="$(cat "$phase_file" 2>/dev/null)"
          case "$detail" in
            load_credentials|reserve_route|reserve_unavailable|reserve_http_[1-5][0-9][0-9]|parse_reservation|validate_reservation|reservation_uri_missing|reservation_scheme_mismatch|reservation_target_mismatch|reservation_token_length_mismatch|reservation_token_charset_mismatch|start_probe|wait_probe|validate_probe_output|complete)
              printf 'direct_secure_preflight_detail=%s\n' "$detail" >&3
              ;;
          esac
        fi
      fi
      exit "$status"
    }
    trap on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM

    phase=preflight_identity
    [ "$(id -u)" -eq 0 ]
    phase=preflight_runtime_files
    for path in "$config" "$runtime_config" "$runtime_secrets"; do
      [ -f "$path" ] && [ ! -L "$path" ]
    done
    phase=preflight_runtime_ownership
    [ "$(stat -c '%U:%G:%a' "$config")" = 'root:bridgefu:640' ]
    [ "$(stat -c '%U:%G:%a' "$runtime_config")" = 'root:bridgefu:640' ]
    [ "$(stat -c '%U:%G:%a' "$runtime_secrets")" = 'bridgefu:bridgefu:600' ]
    phase=preflight_workspace
    if [ -e "$base" ]; then
      [ -d "$base" ] && [ ! -L "$base" ]
      [ "$(stat -c '%U:%G:%a' "$base")" = 'root:root:700' ]
    else
      install -d -o root -g root -m 0700 "$base"
    fi
    [ ! -e "$run" ]
    mkdir -m 0700 "$run"
    [ "$(stat -c '%U:%G:%a' "$run")" = 'root:root:700' ]

    phase=download_probe
    aws s3api get-object --region "$region" --bucket "$bucket" --key "$key" \
      "$probe" --no-cli-pager >/dev/null 2>&1
    [ -f "$probe" ] && [ ! -L "$probe" ]
    [ "$(stat -c '%U:%G' "$probe")" = 'root:root' ]
    printf '%s  %s\n' "$expected_sha256" "$probe" \
      | sha256sum --check --status - >/dev/null 2>&1
    chmod 0700 "$probe"
    [ "$(stat -c '%U:%G:%a' "$probe")" = 'root:root:700' ]

    phase=backup
    cp --preserve=all "$config" "$run/bridgefu.yaml.original"
    [ -f "$run/bridgefu.yaml.original" ] && [ ! -L "$run/bridgefu.yaml.original" ]

    imds_token="$(curl -fsS -X PUT \
      -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
      http://169.254.169.254/latest/api/token)"
    private_ip="$(curl -fsS -H "X-aws-ec2-metadata-token: $imds_token" \
      http://169.254.169.254/latest/meta-data/local-ipv4)"
    unset imds_token
    case "$private_ip" in ''|*[!0-9.]*) exit 1 ;; esac

    # runtime.conf is root-owned and mode-checked above.  Do not export it: in
    # particular, secret ARNs must not enter the probe child's environment.
    # shellcheck source=/dev/null
    source "$runtime_config"
    [ "${BRIDGEFU_DEPLOYMENT_ID:-}" = "$execution" ]
    [ "${AWS_REGION:-}" = "$region" ]
    case "${BRIDGEFU_SIP_SECURITY:-}" in
      sips_optional_srtp|sips_srtp) ;;
      *) exit 1 ;;
    esac
    case "${BRIDGEFU_SIP_HOSTNAME:-}" in ''|*[!A-Za-z0-9.-]*|.*|*.) exit 1 ;; esac
    export BFQ_PRIVATE_IP="$private_ip"
    export BFQ_PUBLIC_IP="$BRIDGEFU_PUBLIC_IP"
    export BFQ_SIP_HOSTNAME="$BRIDGEFU_SIP_HOSTNAME"
    export BFQ_EXPECTED_CIDRS="$VAPI_SIGNALING_CIDRS"
    export BFQ_MARKER="$marker"
    export BFQ_CONFIG="$config"
    export BFQ_RUN="$run"
    export BFQ_PROBE="$probe"
    export BFQ_RESULT="$result"
    export BFQ_PID_FILE="$pid_file"
    export BFQ_PHASE_FILE="$phase_file"
    export BFQ_RUNTIME_SECRETS="$runtime_secrets"
    unset BRIDGEFU_API_BEARER_SECRET_ARN BRIDGEFU_CONTROL_HMAC_SECRET_ARN
    unset CERTIFICATE_PASSPHRASE_SECRET_ARN

    phase=patch_configuration
    python3 - <<'PY' >/dev/null 2>&1
    import ipaddress
    import os
    import pathlib
    import socket
    import stat

    config = pathlib.Path(os.environ["BFQ_CONFIG"])
    run = pathlib.Path(os.environ["BFQ_RUN"])
    marker = os.environ["BFQ_MARKER"]
    private = ipaddress.ip_address(os.environ["BFQ_PRIVATE_IP"])
    public = ipaddress.ip_address(os.environ["BFQ_PUBLIC_IP"])
    private_ranges = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    if not isinstance(private, ipaddress.IPv4Address) or not any(
        private in network for network in private_ranges
    ):
        raise SystemExit(1)
    if not isinstance(public, ipaddress.IPv4Address) or public.is_private:
        raise SystemExit(1)
    hostname = os.environ["BFQ_SIP_HOSTNAME"].lower()
    try:
        resolved = {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(
                hostname, 5061, socket.AF_INET, socket.SOCK_STREAM
            )
        }
    except (OSError, ValueError):
        raise SystemExit(1) from None
    if resolved != {private}:
        raise SystemExit(1)
    private_cidr = f"{private}/32"
    expected = [
        str(ipaddress.ip_network(item, strict=True))
        for item in os.environ["BFQ_EXPECTED_CIDRS"].split(",")
    ]
    if len(expected) != 2 or len(set(expected)) != 2:
        raise SystemExit(1)
    if any(
        ipaddress.ip_network(item).version != 4 or not item.endswith("/32")
        for item in expected
    ):
        raise SystemExit(1)

    def bounded(path: pathlib.Path) -> str:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise SystemExit(1)
        return path.read_text(encoding="utf-8")

    def exclusive_text(path: pathlib.Path, value: str, mode: int, uid: int, gid: int) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                # The remote shell intentionally uses umask 077. Apply the
                # reviewed source mode and ownership to the already-open,
                # exclusively-created inode so the bridgefu service user can
                # still read the atomic replacement.
                os.fchown(handle.fileno(), uid, gid)
                os.fchmod(handle.fileno(), mode)
                handle.write(value)
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    config_text = bounded(config)
    if marker in config_text or private_cidr in config_text:
        raise SystemExit(1)
    lines = config_text.splitlines(keepends=True)
    # The qualification-owned private hosted zone keeps the SIPS Contact on its
    # production DNS name while resolving it privately in this VPC. Only the
    # SDP media address still needs a guarded private rewrite for same-host RTP.
    media_public = f"  media_public_addr: {public}:0\n"
    if lines.count(media_public) != 1:
        raise SystemExit(1)
    lines[lines.index(media_public)] = (
        f"  media_public_addr: {private}:0 # {marker}\n"
    )
    anchors = [
        index
        for index, line in enumerate(lines)
        if line.rstrip("\n") == "      vapi_signaling_cidrs:"
    ]
    if len(anchors) != 1:
        raise SystemExit(1)
    index = anchors[0] + 1
    observed = []
    while index < len(lines) and lines[index].startswith("        - "):
        value = lines[index].strip()[2:].split(" #", 1)[0]
        observed.append(str(ipaddress.ip_network(value, strict=True)))
        index += 1
    if observed != expected:
        raise SystemExit(1)
    lines.insert(index, f"        - {private_cidr} # {marker}\n")
    config_temp = config.parent / f".bridgefu.yaml.{marker}.tmp"
    info = config.stat()
    exclusive_text(
        config_temp,
        "".join(lines),
        stat.S_IMODE(info.st_mode),
        info.st_uid,
        info.st_gid,
    )
    os.replace(config_temp, config)

    PY
    grep -Fq -- "$marker" "$config"

    phase=restart_patched_service
    systemctl restart bridgefu.service >/dev/null 2>&1
    phase=restart_patched_readiness
    ready=false
    for _ in $(seq 1 120); do
      if systemctl is-active --quiet bridgefu.service \
        && curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1; then
        ready=true
        break
      fi
      sleep 0.5
    done

    [ "$ready" = true ]

    phase=reserve_and_probe
    python3 - <<'PY' >/dev/null 2>&1
    import json
    import os
    import pathlib
    import re
    import secrets
    import subprocess
    import urllib.error
    import urllib.request

    run = pathlib.Path(os.environ["BFQ_RUN"])
    probe = os.environ["BFQ_PROBE"]
    output = pathlib.Path(os.environ["BFQ_RESULT"])
    pid_file = pathlib.Path(os.environ["BFQ_PID_FILE"])
    phase_file = pathlib.Path(os.environ["BFQ_PHASE_FILE"])
    private_ip = os.environ["BFQ_PRIVATE_IP"]
    hostname = os.environ["BFQ_SIP_HOSTNAME"].lower()
    runtime_secrets = pathlib.Path(os.environ["BFQ_RUNTIME_SECRETS"])

    allowed = {
        "load_credentials",
        "reserve_route",
        "reserve_unavailable",
        "parse_reservation",
        "validate_reservation",
        "reservation_uri_missing",
        "reservation_scheme_mismatch",
        "reservation_target_mismatch",
        "reservation_token_length_mismatch",
        "reservation_token_charset_mismatch",
        "start_probe",
        "wait_probe",
        "validate_probe_output",
        "complete",
    }

    def mark(value: str) -> None:
        if value not in allowed and re.fullmatch(r"reserve_http_[1-5][0-9]{2}", value) is None:
            raise SystemExit(1)
        descriptor = os.open(
            phase_file,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(value)

    mark("load_credentials")
    bearer_values = []
    for line in runtime_secrets.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator and name == "BRIDGEFU_API_BEARER_TOKEN":
            bearer_values.append(value)
    if len(bearer_values) != 1:
        raise SystemExit(1)
    bearer = bearer_values[0]
    del bearer_values
    if not 32 <= len(bearer) <= 4096 or "\n" in bearer or "\r" in bearer:
        raise SystemExit(1)

    correlation = "bf1_" + secrets.token_urlsafe(32)
    idempotency = "bfq-direct-" + secrets.token_hex(16)
    body = json.dumps(
        {"ingress": "sip", "context": {"correlation_id": correlation, "metadata": {}}},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        "http://127.0.0.1:9090/v1/routes/support/calls",
        data=body,
        method="POST",
        headers={
            "Authorization": "Bearer " + bearer,
            "Content-Type": "application/json",
            "Idempotency-Key": idempotency,
            "User-Agent": "bridgefu-direct-secure-preflight/1",
        },
    )
    del bearer, body, idempotency

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, file_pointer, code, message, headers, new_url):
            return None

    mark("reserve_route")
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
            if response.status != 201:
                mark(f"reserve_http_{response.status}")
                raise SystemExit(1)
            raw = response.read(16_385)
    except urllib.error.HTTPError as error:
        mark(f"reserve_http_{error.code}")
        raise SystemExit(1) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        mark("reserve_unavailable")
        raise SystemExit(1) from None
    finally:
        del request
    if len(raw) > 16_384:
        raise SystemExit(1)

    mark("parse_reservation")
    try:
        reservation = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError):
        raise SystemExit(1) from None
    finally:
        del raw
    uri = reservation.get("attachment", {}).get("uri") if isinstance(reservation, dict) else None
    del reservation
    mark("validate_reservation")
    if not isinstance(uri, str):
        mark("reservation_uri_missing")
        raise SystemExit(1)
    if not uri.startswith("sips:"):
        mark("reservation_scheme_mismatch")
        raise SystemExit(1)
    suffix = f"@{hostname}:5061;transport=tls"
    if not uri.endswith(suffix):
        mark("reservation_target_mismatch")
        raise SystemExit(1)
    token = uri[len("sips:") : -len(suffix)]
    if len(token) != 43:
        mark("reservation_token_length_mismatch")
        raise SystemExit(1)
    if re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
        mark("reservation_token_charset_mismatch")
        raise SystemExit(1)
    del token, suffix

    private_request = json.dumps(
        {
            "schema_version": 1,
            "sip_uri": uri,
            "correlation_id": correlation,
            "media_advertised_ip": private_ip,
        },
        separators=(",", ":"),
    )
    del uri, correlation
    mark("start_probe")
    process = subprocess.Popen(
        [
            probe,
            "--request-stdin",
            "--output",
            str(output),
            "--sip-port",
            "5077",
            "--media-port-start",
            "41000",
            "--timeout-seconds",
            "90",
            "--send-dtmf",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        close_fds=True,
    )
    try:
        descriptor = os.open(pid_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(f"{process.pid}\n")
    except BaseException:
        process.kill()
        process.wait()
        pid_file.unlink(missing_ok=True)
        raise
    try:
        mark("wait_probe")
        process.communicate(private_request, timeout=120)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise SystemExit(1) from None
    finally:
        private_request = ""
        if process.poll() is None:
            process.kill()
            process.wait()
        pid_file.unlink(missing_ok=True)
    if process.returncode != 0 or not output.is_file() or output.is_symlink():
        raise SystemExit(1)
    if not 2 <= output.stat().st_size <= 16_384:
        raise SystemExit(1)

    mark("validate_probe_output")
    try:
        observed = json.loads(output.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        output.unlink(missing_ok=True)
        raise SystemExit(1) from None
    expected = {
        "schema_version": 1,
        "producer": "bridgefu-direct-secure-probe@1",
        "signaling": {
            "scheme": "sips",
            "transport": "tls",
            "invite_count": 1,
            "correlation_header_count": 1,
            "answered": True,
            "inbound_200": True,
            "outbound_ack": True,
            "contact_host": "dns",
            "contact_sips": True,
            "contact_tls": True,
            "trace_redacted": True,
        },
        "media": {
            "profile": "RTP/SAVP",
            "keying": "SDES-SRTP",
            "contexts_installed": True,
            "audio_opened": True,
            "marker_frames_sent": 10,
            "codec": "PCMU",
            "dtmf_requested": True,
            "in_band_dtmf_frames_sent": 15,
            "rfc4733_dtmf_sent": True,
        },
        "hangup": {"local_bye_completed": True, "cleanup_observed": True},
        "redacted": True,
    }
    if observed != expected:
        output.unlink(missing_ok=True)
        raise SystemExit(1)
    mark("complete")
    PY

    phase=restore
    restore_owned
    phase=validate_result
    [ -f "$result" ] && [ ! -L "$result" ]
    [ "$(stat -c '%U:%G:%a' "$result")" = 'root:root:600' ]
    [ "$(wc -c < "$result")" -le 16384 ]
    phase=emit_result
    cat "$result"
    phase=complete
    """
).strip()


_CLEANUP_SCRIPT = textwrap.dedent(
    r"""
    set +e
    umask 077
    exec 2>/dev/null
    base=__BASE__
    run=__RUN__
    probe=__PROBE__
    marker=__MARKER__
    config=/etc/bridgefu/bridgefu.yaml
    config_temp="/etc/bridgefu/.bridgefu.yaml.$marker.tmp"

    run_safe=false
    if [ -e "$base" ] || [ -L "$base" ]; then
      if [ -d "$base" ] && [ ! -L "$base" ] \
        && [ "$(stat -c '%U:%G:%a' "$base")" = 'root:root:700' ]; then
        if [ -e "$run" ] || [ -L "$run" ]; then
          [ -d "$run" ] && [ ! -L "$run" ] \
            && [ "$(stat -c '%U:%G:%a' "$run")" = 'root:root:700' ] \
            && run_safe=true
        else
          run_safe=true
        fi
      fi
    elif [ ! -L "$base" ] && [ ! -e "$run" ] && [ ! -L "$run" ]; then
      run_safe=true
    fi

    stop_owned() {
      [ "$run_safe" = true ] || return 1
      [ ! -L "$run/probe.pid" ] || return 1
      if [ -f "$run/probe.pid" ]; then
        pid="$(cat "$run/probe.pid" 2>/dev/null)"
        case "$pid" in ''|*[!0-9]*) pid='' ;; esac
        if [ -n "$pid" ] \
          && [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" = "$probe" ]; then
          kill "$pid" >/dev/null 2>&1 || true
        fi
      fi
      for entry in /proc/[0-9]*/exe; do
        [ "$(readlink -f "$entry" 2>/dev/null)" = "$probe" ] || continue
        pid="${entry#/proc/}"
        pid="${pid%/exe}"
        case "$pid" in ''|*[!0-9]*) return 1 ;; esac
        kill "$pid" >/dev/null 2>&1 || true
      done
      for _ in $(seq 1 20); do
        binary_absent && break
        sleep 0.25
      done
      if ! binary_absent; then
        for entry in /proc/[0-9]*/exe; do
          [ "$(readlink -f "$entry" 2>/dev/null)" = "$probe" ] || continue
          pid="${entry#/proc/}"
          pid="${pid%/exe}"
          case "$pid" in ''|*[!0-9]*) return 1 ;; esac
          kill -9 "$pid" >/dev/null 2>&1 || true
        done
      fi
      binary_absent || return 1
      rm -f "$run/probe.pid"
    }

    binary_absent() {
      [ "$run_safe" = true ] || return 1
      for entry in /proc/[0-9]*/exe; do
        [ "$(readlink -f "$entry" 2>/dev/null)" = "$probe" ] && return 1
      done
      return 0
    }

    stop_owned
    stop_status=$?
    binary_absent
    binary_status=$?
    [ "$stop_status" -eq 0 ] && [ "$binary_status" -eq 0 ] \
      && probe_absent=0 || probe_absent=1

    config_safe=false
    [ -f "$config" ] && [ ! -L "$config" ] \
      && [ "$(stat -c '%U:%G:%a' "$config")" = 'root:bridgefu:640' ] \
      && config_safe=true
    had_config_backup=false
    config_backup_safe=false
    if [ "$run_safe" = true ] \
      && [ ! -e "$run/bridgefu.yaml.original" ] \
      && [ ! -L "$run/bridgefu.yaml.original" ]; then
      config_backup_safe=true
    elif [ "$run_safe" = true ] \
      && [ -f "$run/bridgefu.yaml.original" ] \
      && [ ! -L "$run/bridgefu.yaml.original" ]; then
      config_backup_safe=true
      had_config_backup=true
      [ "$config_safe" = true ] \
        && cp --preserve=all "$run/bridgefu.yaml.original" "$config" >/dev/null 2>&1
    fi

    configuration_restored=1
    if [ "$config_safe" != true ] || [ "$config_backup_safe" != true ]; then
      configuration_restored=1
    elif [ "$had_config_backup" = true ]; then
      cmp -s "$run/bridgefu.yaml.original" "$config" && configuration_restored=0
    elif ! grep -Fq -- "$marker" "$config" 2>/dev/null; then
      configuration_restored=0
    fi
    if [ "$had_config_backup" = true ]; then
      systemctl restart bridgefu.service >/dev/null 2>&1
    fi
    bridgefu_active=1
    for _ in $(seq 1 120); do
      if systemctl is-active --quiet bridgefu.service \
        && curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1; then
        bridgefu_active=0
        break
      fi
      sleep 0.5
    done

    private_dns_verified=1
    if [ -f /etc/bridgefu/runtime.conf ] \
      && [ ! -L /etc/bridgefu/runtime.conf ] \
      && [ "$(stat -c '%U:%G:%a' /etc/bridgefu/runtime.conf)" = 'root:bridgefu:640' ]; then
      (
        # shellcheck source=/dev/null
        source /etc/bridgefu/runtime.conf
        case "${BRIDGEFU_SIP_HOSTNAME:-}" in ''|*[!A-Za-z0-9.-]*|.*|*.) exit 1 ;; esac
        imds_token="$(curl -fsS -X PUT \
          -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
          http://169.254.169.254/latest/api/token)"
        BFQ_PRIVATE_IP="$(curl -fsS \
          -H "X-aws-ec2-metadata-token: $imds_token" \
          http://169.254.169.254/latest/meta-data/local-ipv4)"
        export BFQ_PRIVATE_IP BRIDGEFU_SIP_HOSTNAME
        python3 - <<'PY'
    import ipaddress
    import os
    import socket

    private = ipaddress.ip_address(os.environ["BFQ_PRIVATE_IP"])
    resolved = {
        ipaddress.ip_address(item[4][0])
        for item in socket.getaddrinfo(
            os.environ["BRIDGEFU_SIP_HOSTNAME"],
            5061,
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
    }
    if resolved != {private}:
        raise SystemExit(1)
    PY
      ) >/dev/null 2>&1 && private_dns_verified=0
    fi

    if [ "$probe_absent" -eq 0 ] \
      && [ "$configuration_restored" -eq 0 ] \
      && [ "$bridgefu_active" -eq 0 ]; then
      rm -f "$run/probe.json" "$run/probe.pid" "$run/probe-phase" \
        "$run/bridgefu.yaml.original" "$probe" "$config_temp"
      rmdir "$run" >/dev/null 2>&1 || true
    fi
    [ "$run_safe" = true ] && [ ! -e "$run" ] && [ ! -L "$run" ] \
      && [ ! -e "$config_temp" ] && [ ! -L "$config_temp" ] \
      && run_absent=0 || run_absent=1

    [ "$probe_absent" -eq 0 ] && probe_json=true || probe_json=false
    [ "$configuration_restored" -eq 0 ] && config_json=true || config_json=false
    [ "$private_dns_verified" -eq 0 ] && dns_json=true || dns_json=false
    [ "$run_absent" -eq 0 ] && run_json=true || run_json=false
    [ "$bridgefu_active" -eq 0 ] && bridgefu_json=true || bridgefu_json=false
    printf '{"probe_process_absent":%s,"configuration_restored":%s,"private_dns_verified":%s,"run_artifacts_absent":%s,"bridgefu_active":%s}\n' \
      "$probe_json" "$config_json" "$dns_json" "$run_json" "$bridgefu_json"
    exit 0
    """
).strip()
