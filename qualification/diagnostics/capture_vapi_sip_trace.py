#!/usr/bin/env python3
"""Capture one redacted, bidirectional Vapi-to-Bridgefu SIP/SDP exchange."""

from __future__ import annotations

import argparse
import os
import re
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from capture_vapi_sdp import (
    DiagnosticError,
    QualificationError,
    SdpCapture,
    private_json,
    sanitize_diagnostic,
)

TRACE_PRODUCER = "bridgefu-vapi-sip-trace-proxy@1"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
NO_PRIVATE_VALUE = re.compile(
    r"(?i)(?:bf1_[A-Za-z0-9_-]{20,}|inline:[A-Za-z0-9+/=_-]{12,}|"
    r"(?:[0-9]{1,3}\.){3}[0-9]{1,3})"
)


def exact_object(value: Any, names: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != names:
        raise DiagnosticError(f"{label} has an invalid shape")
    return value


def validate_trace(value: Any) -> Mapping[str, Any]:
    root = exact_object(
        value,
        {
            "schema_version",
            "producer",
            "captured_at",
            "tls",
            "messages",
            "summary",
            "redaction",
            "redacted",
        },
        "SIP trace",
    )
    tls = exact_object(
        root["tls"],
        {
            "vapi_to_proxy",
            "proxy_to_bridgefu",
            "bridgefu_certificate_verified",
        },
        "TLS trace",
    )
    summary = exact_object(
        root["summary"],
        {
            "vapi_invite_observed",
            "media_profiles",
            "sdes_crypto_line_count",
            "dtls_fingerprint_line_count",
            "bridgefu_statuses",
            "vapi_ack_observed",
            "complete_frames_only",
        },
        "trace summary",
    )
    redaction = exact_object(
        root["redaction"],
        {
            "raw_sip_persisted",
            "credentials_redacted",
            "identifiers_redacted",
            "addresses_redacted",
            "sdp_key_material_redacted",
        },
        "trace redaction",
    )
    if (
        root["schema_version"] != 1
        or root["producer"] != TRACE_PRODUCER
        or not isinstance(root["captured_at"], str)
        or root["redacted"] is not True
        or tls["vapi_to_proxy"] not in {"TLSv1.2", "TLSv1.3"}
        or tls["proxy_to_bridgefu"] not in {"TLSv1.2", "TLSv1.3"}
        or tls["bridgefu_certificate_verified"] is not True
        or summary["vapi_invite_observed"] is not True
        or not isinstance(summary["media_profiles"], list)
        or any(
            item
            not in {
                "RTP/AVP",
                "RTP/AVPF",
                "RTP/SAVP",
                "RTP/SAVPF",
                "UDP/TLS/RTP/SAVP",
                "UDP/TLS/RTP/SAVPF",
            }
            for item in summary["media_profiles"]
        )
        or type(summary["sdes_crypto_line_count"]) is not int
        or type(summary["dtls_fingerprint_line_count"]) is not int
        or not isinstance(summary["bridgefu_statuses"], list)
        or not summary["bridgefu_statuses"]
        or any(
            type(item) is not int or not 100 <= item <= 699
            for item in summary["bridgefu_statuses"]
        )
        or not isinstance(summary["vapi_ack_observed"], bool)
        or not isinstance(summary["complete_frames_only"], bool)
        or redaction
        != {
            "raw_sip_persisted": False,
            "credentials_redacted": True,
            "identifiers_redacted": True,
            "addresses_redacted": True,
            "sdp_key_material_redacted": True,
        }
    ):
        raise DiagnosticError("SIP trace metadata is invalid")
    messages = root["messages"]
    if not isinstance(messages, list) or not 1 <= len(messages) <= 32:
        raise DiagnosticError("SIP trace message count is invalid")
    for index, value in enumerate(messages, 1):
        message = exact_object(
            value,
            {
                "sequence",
                "offset_ms",
                "direction",
                "transport",
                "wire_bytes",
                "wire_sha256",
                "start_line",
                "headers",
                "body_type",
                "body",
            },
            "SIP trace message",
        )
        strings = [message["start_line"], *message["headers"], *message["body"]]
        if (
            message["sequence"] != index
            or type(message["offset_ms"]) is not int
            or not 0 <= message["offset_ms"] <= 180_000
            or message["direction"] not in {"Vapi -> Bridgefu", "Bridgefu -> Vapi"}
            or message["transport"] != "TLS"
            or type(message["wire_bytes"]) is not int
            or not 1 <= message["wire_bytes"] <= 256 * 1024
            or not isinstance(message["wire_sha256"], str)
            or not HEX_64.fullmatch(message["wire_sha256"])
            or not isinstance(message["start_line"], str)
            or not isinstance(message["headers"], list)
            or not isinstance(message["body"], list)
            or any(not isinstance(item, str) for item in strings)
            or message["body_type"] not in {"none", "application/sdp", "other"}
            or NO_PRIVATE_VALUE.search("\n".join(strings))
        ):
            raise DiagnosticError("SIP trace message is invalid or insufficiently redacted")
    return root


class SipTraceCapture(SdpCapture):
    def __init__(self, args: argparse.Namespace) -> None:
        args.observer_path = args.proxy_path
        super().__init__(args)
        self.trace: Mapping[str, Any] | None = None

    def run_directory(self) -> str:
        return f"/run/bridgefu-qualification/trace-{self.args.execution}"

    def observer_script(self, target: Any) -> str:
        run = shlex.quote(self.run_directory())
        proxy = shlex.quote(self.args.proxy_path)
        rules = [self.rule(cidr) for cidr in target.signaling_cidrs]
        insert = "\n".join(
            f"iptables -t nat -I PREROUTING 1 {rule}" for rule in reversed(rules)
        )
        remove = "\n".join(
            f"while iptables -t nat -C PREROUTING {rule} >/dev/null 2>&1; do "
            f"iptables -t nat -D PREROUTING {rule} >/dev/null 2>&1 || break; done"
            for rule in rules
        )
        marker = f"bfq-full-trace-{self.args.execution}"
        script = f"""set -euo pipefail
umask 077
run={run}
proxy={proxy}
config=/etc/bridgefu/bridgefu.yaml
marker={shlex.quote(marker)}
phase=preflight
install -d -m 0700 -o root -g root /run/bridgefu-qualification
mkdir -m 0700 "$run"
cp --preserve=all "$config" "$run/bridgefu.yaml.original"
proxy_pid=''
restore_owned() {{
  status=$?
  set +e
  if [ "$status" -ne 0 ]; then printf 'sip_trace_phase=%s\n' "$phase" >&2; fi
  rm -f "$run/ready"
{remove}
  if [ -n "$proxy_pid" ] && kill -0 "$proxy_pid" >/dev/null 2>&1; then kill "$proxy_pid" >/dev/null 2>&1; wait "$proxy_pid" >/dev/null 2>&1; fi
  rm -f "$run/proxy.pid" "$run/trace.json"
  if [ -f "$run/bridgefu.yaml.original" ]; then
    cp --preserve=all "$run/bridgefu.yaml.original" "$config"
    cmp -s "$run/bridgefu.yaml.original" "$config" || status=1
    systemctl restart bridgefu.service >/dev/null 2>&1 || status=1
    ready=1
    for _ in $(seq 1 120); do
      systemctl is-active --quiet bridgefu.service && curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && ready=0 && break
      sleep 0.5
    done
    [ "$ready" -eq 0 ] || status=1
  fi
  rm -f "$run/bridgefu.yaml.original"
  rmdir "$run" >/dev/null 2>&1 || true
  exit "$status"
}}
trap restore_owned EXIT INT TERM
[ -x "$proxy" ]
[ -f "$config" ] && [ ! -L "$config" ]
source /etc/bridgefu/runtime.conf
[ "$BRIDGEFU_DEPLOYMENT_ID" = {shlex.quote(self.args.execution)} ]
case "$BRIDGEFU_SIP_SECURITY" in sips_optional_srtp|sips_srtp) ;; *) exit 1 ;; esac
case "$BRIDGEFU_SIP_HOSTNAME" in ''|*[!A-Za-z0-9.-]*|.*|*.) exit 1 ;; esac
export BFQ_CONFIG="$config" BFQ_MARKER="$marker" BFQ_EXPECTED_CIDRS="$VAPI_SIGNALING_CIDRS"
phase=patch_configuration
python3 - <<'PY' >/dev/null 2>&1
import ipaddress
import os
import pathlib
import stat

path = pathlib.Path(os.environ["BFQ_CONFIG"])
marker = os.environ["BFQ_MARKER"]
expected = [str(ipaddress.ip_network(item, strict=True)) for item in os.environ["BFQ_EXPECTED_CIDRS"].split(",")]
if len(expected) != 2 or len(set(expected)) != 2 or any(not item.endswith("/32") for item in expected):
    raise SystemExit(1)
info = path.stat()
if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
    raise SystemExit(1)
text = path.read_text(encoding="utf-8")
if marker in text or "127.0.0.1/32" in text:
    raise SystemExit(1)
lines = text.splitlines(keepends=True)
anchors = [index for index, line in enumerate(lines) if line.rstrip("\\n") == "      vapi_signaling_cidrs:"]
if len(anchors) != 1:
    raise SystemExit(1)
index = anchors[0] + 1
observed = []
while index < len(lines) and lines[index].startswith("        - "):
    observed.append(str(ipaddress.ip_network(lines[index].strip()[2:].split(" #", 1)[0], strict=True)))
    index += 1
if observed != expected:
    raise SystemExit(1)
lines.insert(index, f"        - 127.0.0.1/32 # {{marker}}\\n")
temporary = path.parent / f".bridgefu.yaml.{{marker}}.tmp"
temporary.write_text("".join(lines), encoding="utf-8")
os.chmod(temporary, stat.S_IMODE(info.st_mode))
os.chown(temporary, info.st_uid, info.st_gid)
os.replace(temporary, path)
PY
grep -Fq -- "$marker" "$config"
phase=restart_bridgefu
systemctl restart bridgefu.service >/dev/null 2>&1
for _ in $(seq 1 120); do
  systemctl is-active --quiet bridgefu.service && curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && break
  sleep 0.5
done
systemctl is-active --quiet bridgefu.service
curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1
phase=start_proxy
python3 "$proxy" --listen 0.0.0.0:15061 --upstream 127.0.0.1:5061 --server-name "$BRIDGEFU_SIP_HOSTNAME" --certificate /etc/bridgefu/tls/fullchain.pem --private-key /etc/bridgefu/tls/private-key.pem --output "$run/trace.json" --timeout-seconds 120 >/dev/null 2>/dev/null &
proxy_pid=$!
printf '%s\n' "$proxy_pid" > "$run/proxy.pid"
for _ in $(seq 1 120); do
  kill -0 "$proxy_pid" >/dev/null 2>&1 || exit 1
  ss -H -ltn 'sport = :15061' 2>/dev/null | grep -q . && break
  sleep 0.25
done
ss -H -ltn 'sport = :15061' 2>/dev/null | grep -q .
phase=install_redirect
{insert}
touch "$run/ready"
phase=wait_exchange
wait "$proxy_pid"
proxy_pid=''
phase=validate_trace
[ -s "$run/trace.json" ]
cat "$run/trace.json"
phase=complete
"""
        return "\n".join(line for line in script.splitlines() if line)

    def remote_cleanup_script(self, target: Any) -> str:
        run = shlex.quote(self.run_directory())
        source = shlex.quote(self.args.sip_client)
        marker = shlex.quote(f"bfq-full-trace-{self.args.execution}")
        rules = [self.rule(cidr) for cidr in target.signaling_cidrs]
        remove = "\n".join(
            f"while iptables -t nat -C PREROUTING {rule} >/dev/null 2>&1; do "
            f"iptables -t nat -D PREROUTING {rule} >/dev/null 2>&1 || break; done"
            for rule in rules
        )
        verify = " && ".join(
            f"! iptables -t nat -C PREROUTING {rule} >/dev/null 2>&1"
            for rule in rules
        )
        return f"""set +e
run={run}
config=/etc/bridgefu/bridgefu.yaml
marker={marker}
source={source}
source_absent=0
proxy_absent=0
config_restored=0
if [ -f "$run/source.pid" ]; then
  pid="$(cat "$run/source.pid" 2>/dev/null)"
  case "$pid" in ''|*[!0-9]*) source_absent=1 ;; *)
    if [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null)" = "$source" ]; then kill "$pid" >/dev/null 2>&1; sleep 1; kill -9 "$pid" >/dev/null 2>&1; fi
    ;;
  esac
fi
if [ -f "$run/proxy.pid" ]; then
  pid="$(cat "$run/proxy.pid" 2>/dev/null)"
  case "$pid" in ''|*[!0-9]*) proxy_absent=1 ;; *)
    command_line="$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null)"
    printf '%s\n' "$command_line" | grep -Fxq -- {shlex.quote(self.args.proxy_path)} && kill "$pid" >/dev/null 2>&1
    sleep 1
    kill -9 "$pid" >/dev/null 2>&1
    ;;
  esac
fi
{remove}
if [ -f "$run/bridgefu.yaml.original" ]; then
  cp --preserve=all "$run/bridgefu.yaml.original" "$config"
  cmp -s "$run/bridgefu.yaml.original" "$config" || config_restored=1
elif grep -Fq -- "$marker" "$config" 2>/dev/null; then
  config_restored=1
fi
if [ "$config_restored" -eq 0 ]; then
  systemctl restart bridgefu.service >/dev/null 2>&1 || config_restored=1
fi
rm -f "$run/ready" "$run/source.json" "$run/trace.json" "$run/source.pid" "$run/proxy.pid" "$run/bridgefu.yaml.original"
rmdir "$run" >/dev/null 2>&1
for entry in /proc/[0-9]*/exe; do [ "$(readlink -f "$entry" 2>/dev/null)" = "$source" ] && source_absent=1; done
ss -H -ltn 'sport = :15061' 2>/dev/null | grep -q . && proxy_absent=1
{verify} || rules_absent=1
: "${{rules_absent:=0}}"
bridgefu_active=1
for _ in $(seq 1 120); do
  systemctl is-active --quiet bridgefu.service && curl -fsS --max-time 2 http://127.0.0.1:9090/readyz >/dev/null 2>&1 && bridgefu_active=0 && break
  sleep 0.5
done
[ "$config_restored" -eq 0 ] || proxy_absent=1
[ "$rules_absent" -eq 0 ] && rules_json=true || rules_json=false
[ "$proxy_absent" -eq 0 ] && proxy_json=true || proxy_json=false
[ "$source_absent" -eq 0 ] && source_json=true || source_json=false
[ "$bridgefu_active" -eq 0 ] && bridgefu_json=true || bridgefu_json=false
printf '{{"redirect_rules_absent":%s,"observer_process_absent":%s,"source_process_absent":%s,"bridgefu_active":%s}}\n' "$rules_json" "$proxy_json" "$source_json" "$bridgefu_json"
exit 0"""

    def execute(self) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        self.target = self.discover_target()
        self.vapi = self.connect_vapi(self.target)
        primary: BaseException | None = None
        trace: Mapping[str, Any] | None = None
        try:
            authentication, _ = self.prepare_phone(self.target)
            self.upload_auth(self.target, authentication)
            preflight = self.remote_cleanup(self.target)
            if not all(preflight.values()):
                raise DiagnosticError("remote trace preflight cleanup failed")
            self.observer_command_id = self.send_shell(
                self.target, self.observer_script(self.target)
            )
            self.source_command_id = self.send_shell(
                self.target, self.source_script(self.target)
            )
            invocation = self.invocation(self.target, self.observer_command_id, 180)
            if invocation.get("Status") != "Success":
                raise DiagnosticError("SIP trace proxy command failed")
            trace = validate_trace(self.parse_ssm_json(invocation, "SIP trace"))
            self.trace = trace
        except BaseException as error:
            primary = error
        receipt = self.cleanup()
        self.cleanup_receipt = receipt
        if primary is not None:
            if isinstance(primary, (DiagnosticError, QualificationError)):
                raise DiagnosticError(sanitize_diagnostic(str(primary), 512)) from primary
            raise DiagnosticError("SIP trace capture failed unexpectedly") from primary
        if trace is None or receipt["passed"] is not True:
            raise DiagnosticError("SIP trace or cleanup did not pass")
        return trace, receipt

    def run(self) -> None:
        self.validate_inputs()
        self.args.output.mkdir(parents=True, mode=0o700)
        self.args.output.chmod(0o700)
        try:
            self.execute()
        finally:
            if self.trace is not None:
                private_json(self.args.output / "sip-trace.json", self.trace)
            if self.cleanup_receipt is not None:
                private_json(
                    self.args.output / "cleanup-receipt.json", self.cleanup_receipt
                )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("run", nargs="?", choices=("run",))
    value.add_argument("--profile", required=True)
    value.add_argument("--region", required=True, choices=("us-east-1", "us-west-2"))
    value.add_argument("--stack", required=True)
    value.add_argument("--execution", required=True)
    value.add_argument("--proxy-path", required=True)
    value.add_argument("--sip-client", required=True)
    value.add_argument("--prompt", required=True)
    value.add_argument("--vapi-secret-arn", required=True)
    value.add_argument("--output", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    args.output = args.output.resolve()
    try:
        SipTraceCapture(args).run()
    except (DiagnosticError, QualificationError):
        print("qualification SIP trace capture failed", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
