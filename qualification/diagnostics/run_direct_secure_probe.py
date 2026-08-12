#!/usr/bin/env python3
"""Run one qualification-only direct rvoip SIPS/SRTP control probe.

This diagnostic targets an explicitly retained TestDelete stack. It briefly
admits only that stack instance's private /32 and temporarily advertises its
private media address. Split-horizon Route53 keeps the production SIP hostname
on the private path inside the qualification VPC.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if os.fspath(ROOT) not in sys.path:
    sys.path.insert(0, os.fspath(ROOT))

from qualification.controller import (  # noqa: E402
    EXECUTION_ID,
    QualificationError,
    private_json,
    sanitize_diagnostic,
)
from qualification.diagnostics.capture_vapi_sdp import (  # noqa: E402
    PROFILE,
    REGIONS,
    REMOTE_PATH,
    STACK_NAME,
    DiagnosticError,
    ProfileRunner,
    SdpCapture,
    Target,
    exact_object,
    utc_now,
)

PRODUCER = "bridgefu-direct-secure-orchestrator@1"
PROBE_PRODUCER = "bridgefu-direct-secure-probe@1"
MAX_OUTPUT = 16 * 1024


def validate_probe_result(value: Any) -> Mapping[str, Any]:
    root = exact_object(
        value,
        {"schema_version", "producer", "signaling", "media", "hangup", "redacted"},
        "direct secure probe",
    )
    signaling = exact_object(
        root["signaling"],
        {
            "scheme",
            "transport",
            "invite_count",
            "correlation_header_count",
            "answered",
            "inbound_200",
            "outbound_ack",
            "contact_host",
            "contact_sips",
            "contact_tls",
            "trace_redacted",
        },
        "direct secure signaling",
    )
    media = exact_object(
        root["media"],
        {
            "profile",
            "keying",
            "contexts_installed",
            "audio_opened",
            "marker_frames_sent",
            "codec",
            "dtmf_requested",
            "in_band_dtmf_frames_sent",
            "rfc4733_dtmf_sent",
        },
        "direct secure media",
    )
    hangup = exact_object(
        root["hangup"],
        {"local_bye_completed", "cleanup_observed"},
        "direct secure hangup",
    )
    if (
        root["schema_version"] != 1
        or root["producer"] != PROBE_PRODUCER
        or root["redacted"] is not True
        or signaling
        != {
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
        }
        or media
        != {
            "profile": "RTP/SAVP",
            "keying": "SDES-SRTP",
            "contexts_installed": True,
            "audio_opened": True,
            "marker_frames_sent": 120,
            "codec": "PCMU",
            "dtmf_requested": True,
            "in_band_dtmf_frames_sent": 15,
            "rfc4733_dtmf_sent": True,
        }
        or hangup != {"local_bye_completed": True, "cleanup_observed": True}
    ):
        raise DiagnosticError("direct secure probe result did not pass")
    return root


def validate_cleanup_receipt(value: Any) -> Mapping[str, Any]:
    receipt = exact_object(
        value,
        {
            "schema_version",
            "producer",
            "execution_id",
            "observed_at",
            "ssm_command_terminal",
            "probe_process_absent",
            "configuration_restored",
            "private_dns_verified",
            "run_artifacts_absent",
            "bridgefu_active",
            "passed",
            "redacted",
        },
        "direct secure cleanup receipt",
    )
    checks = [
        receipt[name]
        for name in (
            "ssm_command_terminal",
            "probe_process_absent",
            "configuration_restored",
            "private_dns_verified",
            "run_artifacts_absent",
            "bridgefu_active",
        )
    ]
    if (
        receipt["schema_version"] != 1
        or receipt["producer"] != PRODUCER
        or not EXECUTION_ID.fullmatch(str(receipt["execution_id"]))
        or not isinstance(receipt["observed_at"], str)
        or receipt["redacted"] is not True
        or any(not isinstance(item, bool) for item in checks)
        or receipt["passed"] != all(checks)
    ):
        raise DiagnosticError("direct secure cleanup receipt is invalid")
    return receipt


class DirectSecureProbe(SdpCapture):
    def __init__(self, args: argparse.Namespace, runner=None) -> None:
        super().__init__(args, runner or ProfileRunner(args.profile))
        self.command_id: str | None = None
        self.result: Mapping[str, Any] | None = None
        self.direct_cleanup_receipt: Mapping[str, Any] | None = None

    def validate_inputs(self) -> None:
        if (
            not PROFILE.fullmatch(self.args.profile)
            or self.args.region not in REGIONS
            or not EXECUTION_ID.fullmatch(self.args.execution)
            or self.args.stack != f"bridgefu-{self.args.execution}"
            or not STACK_NAME.fullmatch(self.args.stack)
            or not REMOTE_PATH.fullmatch(self.args.probe_path)
            or self.args.output.exists()
        ):
            raise DiagnosticError("direct secure diagnostic inputs are invalid")

    def run_directory(self) -> str:
        return f"/run/bridgefu-qualification/direct-{self.args.execution}"

    def marker(self) -> str:
        return f"bfq-direct-secure-probe-{self.args.execution}"

    def remote_cleanup_script(self) -> str:
        run = shlex.quote(self.run_directory())
        probe = shlex.quote(self.args.probe_path)
        marker = shlex.quote(self.marker())
        script = f"""set +e
run={run}
probe={probe}
marker={marker}
config=/etc/bridgefu/bridgefu.yaml
config_temp="/etc/bridgefu/.bridgefu.yaml.$marker.tmp"
stop_owned() {{
  if [ -f "$run/probe.pid" ]; then
    pid="$(cat "$run/probe.pid" 2>/dev/null)"
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    actual="$(readlink -f "/proc/$pid/exe" 2>/dev/null)"
    if [ -n "$actual" ] && [ "$actual" != "$probe" ]; then return 1; fi
    if [ -n "$actual" ]; then
      kill "$pid" >/dev/null 2>&1
      for _ in $(seq 1 20); do kill -0 "$pid" >/dev/null 2>&1 || break; sleep 0.25; done
      kill -9 "$pid" >/dev/null 2>&1
    fi
    rm -f "$run/probe.pid"
  fi
  return 0
}}
binary_absent() {{
  for entry in /proc/[0-9]*/exe; do
    [ "$(readlink -f "$entry" 2>/dev/null)" = "$probe" ] && return 1
  done
  return 0
}}
stop_owned; probe_absent=$?
binary_absent || probe_absent=1
had_config_backup=false
if [ -f "$run/bridgefu.yaml.original" ]; then
  had_config_backup=true
  cp --preserve=all "$run/bridgefu.yaml.original" "$config" >/dev/null 2>&1 || true
fi
configuration_restored=1
if [ "$had_config_backup" = true ]; then
  cmp -s "$run/bridgefu.yaml.original" "$config" && configuration_restored=0
elif ! grep -Fq -- "$marker" "$config" 2>/dev/null; then
  configuration_restored=0
fi
if [ "$had_config_backup" = true ]; then
  systemctl restart bridgefu.service >/dev/null 2>&1 || true
fi
bridgefu_active=1
for _ in $(seq 1 120); do
  systemctl is-active --quiet bridgefu.service && curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && {{ bridgefu_active=0; break; }}
  sleep 0.5
done
private_dns_verified=1
if [ -f /etc/bridgefu/runtime.conf ] && [ ! -L /etc/bridgefu/runtime.conf ]; then
  (
    # shellcheck source=/dev/null
    source /etc/bridgefu/runtime.conf
    case "${{BRIDGEFU_SIP_HOSTNAME:-}}" in ''|*[!A-Za-z0-9.-]*|.*|*.) exit 1 ;; esac
    imds_token="$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)"
    BFQ_PRIVATE_IP="$(curl -fsS -H "X-aws-ec2-metadata-token: $imds_token" http://169.254.169.254/latest/meta-data/local-ipv4)"
    export BFQ_PRIVATE_IP BRIDGEFU_SIP_HOSTNAME
    python3 - <<'PY'
import ipaddress
import os
import socket

private = ipaddress.ip_address(os.environ["BFQ_PRIVATE_IP"])
resolved = {{
    ipaddress.ip_address(item[4][0])
    for item in socket.getaddrinfo(
        os.environ["BRIDGEFU_SIP_HOSTNAME"], 5061, socket.AF_INET, socket.SOCK_STREAM
    )
}}
if resolved != {{private}}:
    raise SystemExit(1)
PY
  ) >/dev/null 2>&1 && private_dns_verified=0
fi
if [ "$probe_absent" -eq 0 ] && [ "$configuration_restored" -eq 0 ] && [ "$bridgefu_active" -eq 0 ]; then
  rm -f "$run/probe.json" "$run/probe.pid" "$run/probe-phase" "$run/bridgefu.yaml.original" "$config_temp"
  rmdir "$run" >/dev/null 2>&1 || true
fi
[ ! -e "$run" ] && [ ! -e "$config_temp" ] && run_absent=0 || run_absent=1
[ "$probe_absent" -eq 0 ] && probe_json=true || probe_json=false
[ "$configuration_restored" -eq 0 ] && config_json=true || config_json=false
[ "$private_dns_verified" -eq 0 ] && dns_json=true || dns_json=false
[ "$run_absent" -eq 0 ] && run_json=true || run_json=false
[ "$bridgefu_active" -eq 0 ] && bridgefu_json=true || bridgefu_json=false
printf '{{"probe_process_absent":%s,"configuration_restored":%s,"private_dns_verified":%s,"run_artifacts_absent":%s,"bridgefu_active":%s}}\n' "$probe_json" "$config_json" "$dns_json" "$run_json" "$bridgefu_json"
exit 0"""
        return "\n".join(line for line in script.splitlines() if line)

    def probe_script(self) -> str:
        run = shlex.quote(self.run_directory())
        probe = shlex.quote(self.args.probe_path)
        marker = shlex.quote(self.marker())
        execution = shlex.quote(self.args.execution)
        script = f"""set -euo pipefail
umask 077
[ "$(id -u)" -eq 0 ]
run={run}
probe={probe}
marker={marker}
execution={execution}
phase=preflight
config=/etc/bridgefu/bridgefu.yaml
[ -x "$probe" ]
[ -f "$config" ] && [ ! -L "$config" ]
[ -f /etc/bridgefu/runtime.conf ] && [ ! -L /etc/bridgefu/runtime.conf ]
[ "$(stat -c '%U:%G:%a' "$config")" = 'root:bridgefu:640' ]
[ "$(stat -c '%U:%G:%a' /etc/bridgefu/runtime.conf)" = 'root:bridgefu:640' ]
install -d -o root -g root -m 0700 /run/bridgefu-qualification
[ "$(stat -c '%U:%G:%a' /run/bridgefu-qualification)" = 'root:root:700' ]
mkdir -m 0700 "$run"
phase=backup
cp --preserve=all "$config" "$run/bridgefu.yaml.original"
restore_owned() {{
  set +e
  if [ -f "$run/probe.pid" ]; then
    pid="$(cat "$run/probe.pid" 2>/dev/null)"
    case "$pid" in ''|*[!0-9]*) pid='' ;; esac
    if [ -n "$pid" ] && [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" = "$probe" ]; then
      kill "$pid" >/dev/null 2>&1
      for _ in $(seq 1 20); do kill -0 "$pid" >/dev/null 2>&1 || break; sleep 0.25; done
      kill -9 "$pid" >/dev/null 2>&1
    fi
    rm -f "$run/probe.pid"
  fi
  cp --preserve=all "$run/bridgefu.yaml.original" "$config" >/dev/null 2>&1
  cmp -s "$run/bridgefu.yaml.original" "$config" || return 1
  systemctl restart bridgefu.service >/dev/null 2>&1 || return 1
  for _ in $(seq 1 120); do
    systemctl is-active --quiet bridgefu.service && curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}}
on_exit() {{
  status=$?
  trap - EXIT INT TERM
  if [ "$status" -ne 0 ]; then
    printf 'direct_secure_phase=%s\\n' "$phase" >&2
    if [ -f "$run/probe-phase" ]; then
      detail="$(cat "$run/probe-phase" 2>/dev/null)"
      case "$detail" in
        load_credentials|reserve_route|reserve_unavailable|reserve_http_[1-5][0-9][0-9]|parse_reservation|validate_reservation|reservation_uri_missing|reservation_scheme_mismatch|reservation_target_mismatch|reservation_token_length_mismatch|reservation_token_charset_mismatch|start_probe|wait_probe|validate_probe_output|complete) printf 'direct_secure_detail=%s\\n' "$detail" >&2 ;;
        *)
          if [[ "$detail" =~ ^probe_failure_(setup|build|invite|answer|media_security|audio|marker|dtmf|hangup|wire|output)_(none|[1-6][0-9][0-9])_200_(yes|no)_ack_(yes|no)_contact_(absent|redacted|ipv4|dns)_sips_(unknown|yes|no)_tls_(unknown|yes|no)$ ]]; then
            printf 'direct_secure_detail=%s\\n' "$detail" >&2
          fi
          ;;
      esac
    fi
  fi
  restore_owned || status=1
  exit "$status"
}}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
imds_token="$(curl -fsS -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)"
private_ip="$(curl -fsS -H "X-aws-ec2-metadata-token: $imds_token" http://169.254.169.254/latest/meta-data/local-ipv4)"
case "$private_ip" in ''|*[!0-9.]*) exit 1 ;; esac
# shellcheck source=/dev/null
source /etc/bridgefu/runtime.conf
[ "$BRIDGEFU_DEPLOYMENT_ID" = "$execution" ]
[ "$AWS_REGION" = {shlex.quote(self.args.region)} ]
case "$BRIDGEFU_SIP_SECURITY" in sips_optional_srtp|sips_srtp) ;; *) exit 1 ;; esac
case "$BRIDGEFU_SIP_HOSTNAME" in ''|*[!A-Za-z0-9.-]*|.*|*.) exit 1 ;; esac
export BFQ_PRIVATE_IP="$private_ip" BFQ_PUBLIC_IP="$BRIDGEFU_PUBLIC_IP" BFQ_SIP_HOSTNAME="$BRIDGEFU_SIP_HOSTNAME" BFQ_EXPECTED_CIDRS="$VAPI_SIGNALING_CIDRS" BFQ_MARKER="$marker" BFQ_CONFIG="$config" BFQ_RUN="$run"
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
if not isinstance(private, ipaddress.IPv4Address) or not private.is_private:
    raise SystemExit(1)
if not isinstance(public, ipaddress.IPv4Address) or public.is_private:
    raise SystemExit(1)
hostname = os.environ["BFQ_SIP_HOSTNAME"].lower()
try:
    resolved = {{
        ipaddress.ip_address(item[4][0])
        for item in socket.getaddrinfo(
            hostname, 5061, socket.AF_INET, socket.SOCK_STREAM
        )
    }}
except (OSError, ValueError):
    raise SystemExit(1) from None
if resolved != {{private}}:
    raise SystemExit(1)
private_cidr = f"{{private}}/32"
expected = [
    str(ipaddress.ip_network(item, strict=True))
    for item in os.environ["BFQ_EXPECTED_CIDRS"].split(",")
]
if len(expected) != 2 or len(set(expected)) != 2:
    raise SystemExit(1)
if any(ipaddress.ip_network(item).version != 4 or not item.endswith("/32") for item in expected):
    raise SystemExit(1)

def bounded(path):
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise SystemExit(1)
    return path.read_text(encoding="utf-8")

config_text = bounded(config)
if marker in config_text or private_cidr in config_text:
    raise SystemExit(1)
lines = config_text.splitlines(keepends=True)
# Split-horizon Route53 keeps the production SIPS Contact DNS name private in
# this VPC. Only the SDP media address needs a guarded same-host rewrite.
media_public = f"  media_public_addr: {{public}}:0\\n"
if lines.count(media_public) != 1:
    raise SystemExit(1)
lines[lines.index(media_public)] = (
    f"  media_public_addr: {{private}}:0 # {{marker}}\\n"
)
anchors = [i for i, line in enumerate(lines) if line.rstrip("\\n") == "      vapi_signaling_cidrs:"]
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
lines.insert(index, f"        - {{private_cidr}} # {{marker}}\\n")
config_temp = config.parent / f".bridgefu.yaml.{{marker}}.tmp"
config_temp.write_text("".join(lines), encoding="utf-8")
os.chmod(config_temp, stat.S_IMODE(config.stat().st_mode))
os.chown(config_temp, config.stat().st_uid, config.stat().st_gid)
os.replace(config_temp, config)

PY
grep -Fq -- "$marker" "$config"
phase=restart_patched_runtime
systemctl restart bridgefu.service >/dev/null 2>&1
for _ in $(seq 1 120); do
  systemctl is-active --quiet bridgefu.service && curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && break
  sleep 0.5
done
systemctl is-active --quiet bridgefu.service
curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1
export BFQ_PROBE="$probe"
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
private_ip = os.environ["BFQ_PRIVATE_IP"]
hostname = os.environ["BFQ_SIP_HOSTNAME"].lower()
phase_path = run / "probe-phase"
def mark(value):
    allowed = {{"load_credentials", "reserve_route", "reserve_unavailable", "parse_reservation", "validate_reservation", "reservation_uri_missing", "reservation_scheme_mismatch", "reservation_target_mismatch", "reservation_token_length_mismatch", "reservation_token_charset_mismatch", "start_probe", "wait_probe", "validate_probe_output", "complete"}}
    failure = r"probe_failure_(setup|build|invite|answer|media_security|audio|marker|dtmf|hangup|wire|output)_(none|[1-6][0-9]{{2}})_200_(yes|no)_ack_(yes|no)_contact_(absent|redacted|ipv4|dns)_sips_(unknown|yes|no)_tls_(unknown|yes|no)"
    if value not in allowed and re.fullmatch(r"reserve_http_[1-5][0-9]{{2}}", value) is None and re.fullmatch(failure, value) is None:
        raise SystemExit(1)
    phase_path.write_text(value, encoding="ascii")
    os.chmod(phase_path, 0o600)
mark("load_credentials")
values = {{}}
for line in pathlib.Path("/run/bridgefu/runtime.env").read_text(encoding="utf-8").splitlines():
    key, separator, value = line.partition("=")
    if separator and key not in values:
        values[key] = value
bearer = values.get("BRIDGEFU_API_BEARER_TOKEN", "")
if not 32 <= len(bearer) <= 4096 or "\\n" in bearer or "\\r" in bearer:
    raise SystemExit(1)
correlation = "bf1_" + secrets.token_urlsafe(32)
idempotency = "bfq-direct-" + secrets.token_hex(16)
body = json.dumps(
    {{"ingress": "sip", "context": {{"correlation_id": correlation, "metadata": {{}}}}}},
    separators=(",", ":"),
).encode()
request = urllib.request.Request(
    "http://127.0.0.1:9090/v1/routes/support/calls",
    data=body,
    method="POST",
    headers={{
        "Authorization": "Bearer " + bearer,
        "Content-Type": "application/json",
        "Idempotency-Key": idempotency,
        "User-Agent": "bridgefu-direct-secure-orchestrator/1",
    }},
)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None
opener = urllib.request.build_opener(NoRedirect())
mark("reserve_route")
try:
    with opener.open(request, timeout=10) as response:
        if response.status != 201:
            mark(f"reserve_http_{{response.status}}")
            raise SystemExit(1)
        raw = response.read(16_385)
except urllib.error.HTTPError as error:
    mark(f"reserve_http_{{error.code}}")
    raise SystemExit(1) from None
except (urllib.error.URLError, TimeoutError, OSError):
    mark("reserve_unavailable")
    raise SystemExit(1) from None
if len(raw) > 16_384:
    raise SystemExit(1)
mark("parse_reservation")
reservation = json.loads(raw)
uri = reservation.get("attachment", {{}}).get("uri") if isinstance(reservation, dict) else None
mark("validate_reservation")
if not isinstance(uri, str):
    mark("reservation_uri_missing")
    raise SystemExit(1)
if not uri.startswith("sips:"):
    mark("reservation_scheme_mismatch")
    raise SystemExit(1)
suffix = f"@{{hostname}}:5061;transport=tls"
if not uri.endswith(suffix):
    mark("reservation_target_mismatch")
    raise SystemExit(1)
token = uri[len("sips:") : -len(suffix)]
if len(token) != 43:
    mark("reservation_token_length_mismatch")
    raise SystemExit(1)
if re.fullmatch(r"[A-Za-z0-9_-]{{43}}", token) is None:
    mark("reservation_token_charset_mismatch")
    raise SystemExit(1)
private_request = json.dumps(
    {{
        "schema_version": 1,
        "sip_uri": uri,
        "correlation_id": correlation,
        "media_advertised_ip": private_ip,
    }},
    separators=(",", ":"),
)
output = run / "probe.json"
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
    stderr=subprocess.PIPE,
    text=True,
)
pid_file = run / "probe.pid"
descriptor = os.open(pid_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as handle:
    handle.write(f"{{process.pid}}\\n")
try:
    mark("wait_probe")
    _, probe_stderr = process.communicate(private_request, timeout=120)
except subprocess.TimeoutExpired:
    process.kill()
    process.communicate()
    raise SystemExit(1)
finally:
    pid_file.unlink(missing_ok=True)
if process.returncode != 0:
    failure = re.fullmatch(
        r"Direct secure probe failed phase=(setup|build|invite|answer|media_security|audio|marker|dtmf|hangup|wire|output) status=(none|[1-6][0-9]{{2}}) inbound_200=(yes|no) outbound_ack=(yes|no) contact=(absent|redacted|ipv4|dns) contact_sips=(unknown|yes|no) contact_tls=(unknown|yes|no)\\n?",
        probe_stderr,
    )
    if failure is None:
        raise SystemExit(1)
    mark(
        f"probe_failure_{{failure.group(1)}}_{{failure.group(2)}}"
        f"_200_{{failure.group(3)}}_ack_{{failure.group(4)}}"
        f"_contact_{{failure.group(5)}}_sips_{{failure.group(6)}}"
        f"_tls_{{failure.group(7)}}"
    )
    raise SystemExit(1)
if probe_stderr or not output.is_file():
    raise SystemExit(1)
if output.stat().st_size > 16_384:
    raise SystemExit(1)
mark("validate_probe_output")
observed = json.loads(output.read_text(encoding="utf-8"))
expected = {{
    "schema_version": 1,
    "producer": "bridgefu-direct-secure-probe@1",
    "signaling": {{
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
    }},
    "media": {{
        "profile": "RTP/SAVP",
        "keying": "SDES-SRTP",
        "contexts_installed": True,
        "audio_opened": True,
        "marker_frames_sent": 120,
        "codec": "PCMU",
        "dtmf_requested": True,
        "in_band_dtmf_frames_sent": 15,
        "rfc4733_dtmf_sent": True,
    }},
    "hangup": {{"local_bye_completed": True, "cleanup_observed": True}},
    "redacted": True,
}}
if observed != expected:
    output.unlink(missing_ok=True)
    raise SystemExit(1)
mark("complete")
PY
phase=validate_result
[ -s "$run/probe.json" ]
cat "$run/probe.json"
"""
        return "\n".join(line for line in script.splitlines() if line)

    def parse_json(
        self, invocation: Mapping[str, Any], label: str
    ) -> Mapping[str, Any]:
        raw = invocation.get("StandardOutputContent")
        if not isinstance(raw, str) or not 2 <= len(raw.encode("utf-8")) <= MAX_OUTPUT:
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
            command_id = self.send_shell(target, self.remote_cleanup_script())
            invocation = self.invocation(target, command_id, 180)
            if invocation.get("Status") != "Success":
                raise DiagnosticError("direct secure remote cleanup failed")
            value = exact_object(
                self.parse_json(invocation, "direct secure cleanup"),
                {
                    "probe_process_absent",
                    "configuration_restored",
                    "private_dns_verified",
                    "run_artifacts_absent",
                    "bridgefu_active",
                },
                "direct secure remote cleanup",
            )
            if any(not isinstance(item, bool) for item in value.values()):
                raise DiagnosticError("direct secure cleanup checks are invalid")
            return dict(value)
        except (DiagnosticError, QualificationError):
            return {
                "probe_process_absent": False,
                "configuration_restored": False,
                "private_dns_verified": False,
                "run_artifacts_absent": False,
                "bridgefu_active": False,
            }

    def cleanup_direct(self) -> Mapping[str, Any]:
        command_terminal = False
        remote = {
            "probe_process_absent": False,
            "configuration_restored": False,
            "private_dns_verified": False,
            "run_artifacts_absent": False,
            "bridgefu_active": False,
        }
        if self.target is not None:
            command_terminal = self.cancel_command(self.target, self.command_id)
            remote = self.remote_cleanup(self.target)
        checks = [command_terminal, *remote.values()]
        return validate_cleanup_receipt(
            {
                "schema_version": 1,
                "producer": PRODUCER,
                "execution_id": self.args.execution,
                "observed_at": utc_now(),
                "ssm_command_terminal": command_terminal,
                **remote,
                "passed": all(checks),
                "redacted": True,
            }
        )

    def execute_direct(self) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        self.target = self.discover_target()
        primary: BaseException | None = None
        result: Mapping[str, Any] | None = None
        try:
            preflight = self.remote_cleanup(self.target)
            if not all(preflight.values()):
                raise DiagnosticError("direct secure preflight cleanup failed")
            self.command_id = self.send_shell(self.target, self.probe_script())
            invocation = self.invocation(self.target, self.command_id, 240)
            if invocation.get("Status") != "Success":
                raise DiagnosticError("direct secure probe command failed")
            result = validate_probe_result(
                self.parse_json(invocation, "direct secure probe")
            )
            self.result = result
        except BaseException as error:
            primary = error
        receipt = self.cleanup_direct()
        self.direct_cleanup_receipt = receipt
        if primary is not None:
            if isinstance(primary, (DiagnosticError, QualificationError)):
                raise DiagnosticError(
                    sanitize_diagnostic(str(primary), 512)
                ) from primary
            raise DiagnosticError(
                "direct secure diagnostic failed unexpectedly"
            ) from primary
        if result is None or receipt["passed"] is not True:
            raise DiagnosticError("direct secure diagnostic or cleanup did not pass")
        return result, receipt

    def run_direct(self) -> None:
        self.validate_inputs()
        self.args.output.mkdir(parents=True, mode=0o700)
        self.args.output.chmod(0o700)
        try:
            self.execute_direct()
        finally:
            if self.result is not None:
                private_json(self.args.output / "direct-secure-probe.json", self.result)
            if self.direct_cleanup_receipt is not None:
                private_json(
                    self.args.output / "direct-cleanup-receipt.json",
                    self.direct_cleanup_receipt,
                )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("run", nargs="?", choices=("run",))
    value.add_argument("--profile", required=True)
    value.add_argument("--region", required=True, choices=sorted(REGIONS))
    value.add_argument("--stack", required=True)
    value.add_argument("--execution", required=True)
    value.add_argument("--probe-path", required=True)
    value.add_argument("--output", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    args.output = args.output.resolve()
    try:
        DirectSecureProbe(args).run_direct()
    except (DiagnosticError, QualificationError):
        print("qualification direct secure diagnostic failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
