"""Secret-free runtime overlay for the retained Bridgefu Web SDK smoke.

The controller renders this complete configuration locally and validates it
with the exact pinned Bridgefu binary before it can upload or install it.  SIP
authentication remains an environment reference; no password is serialized in
the configuration, SSM command, browser attachment, or retained evidence.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from collections.abc import Mapping
from typing import Any

HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$"
)
IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
CONNECT_ARN = re.compile(
    r"^arn:aws[-a-z0-9]*:connect:(us-west-2|us-east-1):[0-9]{12}:"
    r"instance/[A-Za-z0-9-]+$"
)
REGIONS = {"us-west-2", "us-east-1"}
VAPI_CIDRS = ["44.229.228.186/32", "44.238.177.138/32"]
WEB_ROUTE_ID = "vapi-direct-assistant"
CONNECT_ROUTE_ID = "amazon-connect"
VAPI_PASSWORD_ENV = "BRIDGEFU_QUALIFICATION_VAPI_SIP_PASSWORD"  # noqa: S105
LOCAL_VALIDATION_SECRET = "bridgefu-local-validation-placeholder"  # noqa: S105
INSTALL_RESULT_KEYS = {
    "schema_version",
    "producer",
    "configuration_installed",
    "bridgefu_ready",
    "wss_listener_ready",
    "redacted",
}
CLEANUP_RESULT_KEYS = {
    "schema_version",
    "producer",
    "configuration_restored",
    "overlay_absent",
    "wrapper_absent",
    "dropin_absent",
    "bridgefu_ready",
    "redacted",
}
VAPI_TLS_RESULT_KEYS = {
    "schema_version",
    "producer",
    "dns",
    "tcp",
    "tls",
    "category",
    "redacted",
}


class WebRuntimeContractError(ValueError):
    """The qualification runtime overlay crossed a closed boundary."""


def validation_environment(base: Mapping[str, str]) -> dict[str, str]:
    """Supply non-secret placeholders only for local semantic validation."""
    result = dict(base)
    result.update(
        {
            "BRIDGEFU_API_BEARER_TOKEN": LOCAL_VALIDATION_SECRET,
            "BRIDGEFU_CONTROL_HMAC_KEY": LOCAL_VALIDATION_SECRET,
            VAPI_PASSWORD_ENV: LOCAL_VALIDATION_SECRET,
        }
    )
    return result


def vapi_tls_reachability_script() -> str:
    """Prove the retained EC2 can reach Vapi's US TLS listener.

    The remote program emits only closed booleans and a fixed category. It
    never prints resolved addresses, certificates, socket errors, or remote
    data, and it runs before any temporary Vapi resource is created.
    """
    return r"""set -euo pipefail
python3 - <<'PY'
import json
import socket
import ssl

result = {
    "schema_version": 1,
    "producer": "bridgefu-vapi-tls-reachability@1",
    "dns": False,
    "tcp": False,
    "tls": False,
    "category": "unknown",
    "redacted": True,
}
try:
    socket.getaddrinfo("sip.vapi.ai", 5061, type=socket.SOCK_STREAM)
    result["dns"] = True
    connection = socket.create_connection(("sip.vapi.ai", 5061), timeout=12)
    result["tcp"] = True
    context = ssl.create_default_context()
    with context.wrap_socket(connection, server_hostname="sip.vapi.ai"):
        result["tls"] = True
    result["category"] = "passed"
except socket.gaierror:
    result["category"] = "dns-error"
except socket.timeout:
    result["category"] = "timeout"
except ssl.SSLError:
    result["category"] = "tls-error"
except OSError:
    result["category"] = "socket-error"
print(json.dumps(result, separators=(",", ":"), sort_keys=True))
PY"""


def validate_vapi_tls_reachability(value: Any) -> Mapping[str, Any]:
    expected = {
        "schema_version": 1,
        "producer": "bridgefu-vapi-tls-reachability@1",
        "dns": True,
        "tcp": True,
        "tls": True,
        "category": "passed",
        "redacted": True,
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != VAPI_TLS_RESULT_KEYS
        or value != expected
    ):
        raise WebRuntimeContractError("Vapi TLS reachability preflight failed")
    return value


def build_runtime_config(
    *,
    region: str,
    deployment_id: str,
    sip_hostname: str,
    public_ip: str,
    connect_instance_arn: str,
    connect_flow_id: str,
    vapi_sip_username: str,
    signaling_port: int,
    max_concurrent_calls: int = 100,
) -> dict[str, Any]:
    """Build one complete, deterministic, secret-reference-only config."""
    if (
        region not in REGIONS
        or not IDENTIFIER.fullmatch(deployment_id)
        or not HOSTNAME.fullmatch(sip_hostname)
        or not CONNECT_ARN.fullmatch(connect_instance_arn)
        or not IDENTIFIER.fullmatch(connect_flow_id)
        or not IDENTIFIER.fullmatch(vapi_sip_username)
        or not 1024 <= signaling_port <= 65535
        or not 1 <= max_concurrent_calls <= 1000
    ):
        raise WebRuntimeContractError("Bridgefu Web runtime identity is invalid")
    try:
        address = str(ipaddress.IPv4Address(public_ip))
    except ipaddress.AddressValueError as error:
        raise WebRuntimeContractError(
            "Bridgefu Web runtime public address is invalid"
        ) from error

    # Vapi publishes its US TLS listener on 5061. Use SIP-over-TLS rather
    # than SIPS here because Vapi's response Contact is not guaranteed to
    # preserve the SIPS scheme. Transport security is proved independently
    # from the URI scheme by Bridgefu's redacted wire evidence.
    target = f"sip:{vapi_sip_username}@sip.vapi.ai:5061;transport=tls"
    signaling_origin = f"wss://{sip_hostname}:{signaling_port}"
    signing_uri = f"{signaling_origin}/webrtc"
    connect_destination = {
        "direction": "outbound",
        "signaling_initiator": "bridgefu",
        "media_flow": "send_receive",
        "endpoint": {
            "type": "amazon_connect",
            "config": {
                "instance_id": connect_instance_arn.rsplit("/", 1)[1],
                "contact_flow_id": connect_flow_id,
            },
        },
        "amazon_connect_start": {
            "profile": "support-connect",
            "instance_id": connect_instance_arn.rsplit("/", 1)[1],
            "contact_flow_id": connect_flow_id,
            "attributes": {
                "integration": "bridgefu",
                "handoff_route": "vapi-assistant",
            },
            "display_name": "Vapi caller",
            "description": "Bridgefu managed Vapi handoff",
        },
    }
    return {
        "config_version": 1,
        "aws": {"region": region},
        "edge": {
            "public_host": sip_hostname,
            "media_public_addr": f"{address}:0",
            "sip_tls": {
                "bind": "0.0.0.0:5061",
                "advertised_addr": f"{address}:5061",
                "certificate_chain": "/etc/bridgefu/tls/fullchain.pem",
                "private_key": "/etc/bridgefu/tls/private-key.pem",
            },
        },
        "api": {
            "enabled": True,
            "tls": {
                "certificate_chain": "/etc/bridgefu/tls/fullchain.pem",
                "private_key": "/etc/bridgefu/tls/private-key.pem",
            },
            "bearer_token": "env:BRIDGEFU_API_BEARER_TOKEN",
            "control_hmac_key": "env:BRIDGEFU_CONTROL_HMAC_KEY",
            "static_tenant": "support",
            "rate_limit": {
                "enabled": True,
                "control_requests_per_second": 20,
                "control_burst": 40,
                "diagnostics_requests_per_second": 5,
                "diagnostics_burst": 10,
                "webhook_requests_per_second": 5,
                "webhook_burst": 10,
                "max_tracked_identities": 1024,
                "identity_idle_ttl_secs": 300,
            },
            "route_attachments": {
                "webrtc": {"signaling_uri": signing_uri, "ice_servers": []}
            },
            "routes": {
                WEB_ROUTE_ID: {
                    "tenant_id": "support",
                    "ingress": ["webrtc"],
                    "webrtc_ingress_profile": "qualification-browser",
                    "destination_profile": {
                        "type": "sip",
                        "profile_id": "qualification-vapi-assistant",
                    },
                    "destination": {
                        "direction": "outbound",
                        "signaling_initiator": "bridgefu",
                        "media_flow": "send_receive",
                        "endpoint": {
                            "type": "sip",
                            "config": {"uri": target, "initial_context": "required"},
                        },
                    },
                },
                CONNECT_ROUTE_ID: {
                    "tenant_id": "support",
                    "ingress": ["webrtc"],
                    "webrtc_ingress_profile": "qualification-browser",
                    "destination_profile": {
                        "type": "amazon_connect",
                        "profile_id": "support-connect",
                    },
                    "destination": connect_destination,
                },
            },
        },
        "recipes": {
            "support": {
                "use": "builtin:vapi-amazon-connect-screen-pop@1",
                "with": {
                    "vapi_signaling_cidrs": VAPI_CIDRS,
                    "connect_instance_arn": connect_instance_arn,
                    "connect_entry_contact_flow_id": connect_flow_id,
                    "sip_security": "sips_optional_srtp",
                },
            }
        },
        "sip_profiles": {
            "qualification-vapi-assistant": {
                "allowed_targets": [target],
                "from_uri": f"sips:bridgefu@{sip_hostname}",
                "auth": {
                    "type": "digest",
                    "realm": "sip.vapi.ai",
                    "username": vapi_sip_username,
                    "password": f"env:{VAPI_PASSWORD_ENV}",
                },
                "tls_roots": ["/etc/pki/tls/certs/ca-bundle.crt"],
                "srtp": "preferred",
                "codecs": ["pcmu", "opus"],
                "metadata_keys": ["correlation_id", "handoff_token"],
            }
        },
        "webrtc_profiles": {
            "qualification-browser": {
                "allowed_signaling_origins": [signaling_origin],
                "ice_servers": [],
                "codecs": ["opus"],
                "data_channels": True,
            }
        },
        "context": {
            "allow_headers": {
                "X-Correlation-Id": "correlation_id",
                "X-Bridgefu_Handoff_Token": "handoff_token",
            }
        },
        "generic_bridge": {
            "enabled": True,
            "sip_bind": "127.0.0.1:5070",
            "webrtc_ws_bind": "127.0.0.1:8080",
            "webrtc_whip_bind": "127.0.0.1:8081",
            "sip": {"srtp": "preferred"},
            "webrtc": {
                "udp_port_range": {
                    # The public WebRTC media socket is bounded by the exact
                    # UDP range and the stack-owned gateway security group.
                    "bind_ip": "0.0.0.0",  # noqa: S104
                    "port_start": 20000,
                    "port_end": 20399,
                },
                "audio_codecs": ["opus"],
                "ice_servers": [],
                "nat_1to1_ips": [address],
                "nat_1to1_candidate_type": "host",
                "gather_timeout_secs": 10,
                "connection_timeout_secs": 30,
                "trickle_ice": True,
            },
        },
        "persistence": {
            "backend": "sqlite",
            "database_url": "sqlite:///var/lib/bridgefu/bridgefu.db",
            "deployment_id": deployment_id,
        },
        "observability": {
            "log_level": "info",
            "log_format": "json",
            "http_bind": "127.0.0.1:9090",
        },
        "runtime": {
            "mode": "all-in-one",
            "max_concurrent_calls": max_concurrent_calls,
            "setup_timeout_secs": 15,
            "media_idle_timeout_secs": 120,
            "drain_timeout_secs": 60,
        },
    }


def encode_runtime_config(value: Mapping[str, Any]) -> bytes:
    """Encode canonical JSON, which is also a valid Bridgefu YAML document."""
    if not isinstance(value, Mapping):
        raise WebRuntimeContractError("Bridgefu Web runtime config is invalid")
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    if len(encoded) > 64 * 1024:
        raise WebRuntimeContractError("Bridgefu Web runtime config exceeded its bound")
    try:
        password = value["sip_profiles"]["qualification-vapi-assistant"]["auth"][
            "password"
        ]
    except (KeyError, TypeError) as error:
        raise WebRuntimeContractError(
            "Bridgefu Web runtime secret reference is unavailable"
        ) from error
    if password != f"env:{VAPI_PASSWORD_ENV}" or b"api_key" in encoded.lower():
        raise WebRuntimeContractError("Bridgefu Web runtime config contains a secret")
    return encoded


def install_script(
    *,
    execution_id: str,
    region: str,
    bucket: str,
    object_key: str,
    config_sha256: str,
    auth_secret_arn: str,
) -> str:
    """Render one trap-restored, secret-free SSM install command."""
    if (
        not IDENTIFIER.fullmatch(execution_id)
        or region not in REGIONS
        or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
        or not re.fullmatch(r"qualification/[A-Za-z0-9_./-]{1,512}", object_key)
        or not re.fullmatch(r"[0-9a-f]{64}", config_sha256)
        or not re.fullmatch(
            r"arn:aws[-a-z0-9]*:secretsmanager:(us-west-2|us-east-1):"
            r"[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+",
            auth_secret_arn,
        )
    ):
        raise WebRuntimeContractError(
            "Bridgefu Web runtime install identity is invalid"
        )
    quoted = {
        "execution": shlex.quote(execution_id),
        "region": shlex.quote(region),
        "source": shlex.quote(f"s3://{bucket}/{object_key}"),
        "digest": shlex.quote(config_sha256),
        "secret": shlex.quote(auth_secret_arn),
    }
    return f"""set -euo pipefail
umask 077
execution={quoted["execution"]}
region={quoted["region"]}
source_uri={quoted["source"]}
expected_sha={quoted["digest"]}
auth_secret_arn={quoted["secret"]}
run=/var/lib/bridgefu/qualification/$execution-web-runtime
config=/etc/bridgefu/bridgefu.yaml
dropin=/etc/systemd/system/bridgefu.service.d/qualification-web-runtime.conf
wrapper=$run/bridgefu-qualification-web-run
restore() {{
  status=$?
  trap - EXIT
  if [ "$status" -ne 0 ]; then
    systemctl stop bridgefu.service >/dev/null 2>&1 || true
    if [ -f "$run/bridgefu.yaml.original" ]; then
      cp --preserve=all "$run/bridgefu.yaml.original" "$config" >/dev/null 2>&1 || true
    fi
    rm -f "$dropin"
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl start bridgefu.service >/dev/null 2>&1 || true
  fi
  exit "$status"
}}
trap restore EXIT
[ "$(id -u)" -eq 0 ]
[ -f "$config" ] && [ ! -L "$config" ]
[ ! -e "$run" ] && [ ! -L "$run" ]
[ ! -e "$dropin" ] && [ ! -L "$dropin" ]
install -d -o root -g bridgefu -m 0750 "$run"
cp --preserve=all "$config" "$run/bridgefu.yaml.original"
aws s3 cp "$source_uri" "$run/bridgefu.yaml.candidate" --region "$region" --only-show-errors
[ "$(sha256sum "$run/bridgefu.yaml.candidate" | awk '{{print $1}}')" = "$expected_sha" ]
cat > "$wrapper" <<'BRIDGEFU_QUALIFICATION_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
mode="${{1:-run}}"
config="${{2:-/etc/bridgefu/bridgefu.yaml}}"
if [[ "$mode" != run && "$mode" != validate ]]; then
  exit 64
fi
/usr/local/sbin/bridgefu-load-secrets
secret="$(aws secretsmanager get-secret-value --region "$BRIDGEFU_QUALIFICATION_REGION" --secret-id "$BRIDGEFU_QUALIFICATION_VAPI_SIP_AUTH_SECRET_ARN" --query SecretString --output text)"
python3 - /run/bridgefu/qualification-vapi.env 3<<<"$secret" <<'PY'
import json
import os
import re
import sys
path = sys.argv[1]
raw = os.read(3, 16385).decode("utf-8").rstrip("\\n")
if len(raw.encode("utf-8")) > 16384:
    raise SystemExit(1)
value = json.loads(raw)
if set(value) != {{"realm", "username", "password"}}:
    raise SystemExit(1)
if value["realm"] != "sip.vapi.ai":
    raise SystemExit(1)
if not re.fullmatch(r"[A-Za-z0-9_-]{{1,128}}", value["username"]):
    raise SystemExit(1)
if not isinstance(value["password"], str) or not 16 <= len(value["password"]) <= 256 or any(character.isspace() for character in value["password"]):
    raise SystemExit(1)
temporary = path + ".new"
with open(temporary, "x", encoding="utf-8") as output:
    output.write("BRIDGEFU_QUALIFICATION_VAPI_SIP_PASSWORD=" + value["password"] + "\\n")
os.chmod(temporary, 0o600)
os.replace(temporary, path)
PY
unset secret
set -a
source /run/bridgefu/runtime.env
source /run/bridgefu/qualification-vapi.env
set +a
exec /usr/local/bin/bridgefu --config "$config" "$mode"
BRIDGEFU_QUALIFICATION_WRAPPER
chown root:bridgefu "$wrapper"
chmod 0750 "$wrapper"
BRIDGEFU_QUALIFICATION_REGION="$region" BRIDGEFU_QUALIFICATION_VAPI_SIP_AUTH_SECRET_ARN="$auth_secret_arn" "$wrapper" validate "$run/bridgefu.yaml.candidate" >/dev/null
systemctl stop bridgefu.service
install -o root -g bridgefu -m 0640 "$run/bridgefu.yaml.candidate" "$config"
install -d -o root -g root -m 0755 "$(dirname "$dropin")"
cat > "$dropin" <<EOF
[Service]
Environment=BRIDGEFU_QUALIFICATION_REGION=$region
Environment=BRIDGEFU_QUALIFICATION_VAPI_SIP_AUTH_SECRET_ARN=$auth_secret_arn
ExecStart=
ExecStart=$wrapper run /etc/bridgefu/bridgefu.yaml
EOF
chmod 0644 "$dropin"
systemctl daemon-reload
systemctl start bridgefu.service
for _ in $(seq 1 90); do
  curl -fsS http://127.0.0.1:9090/readyz >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:9090/readyz >/dev/null
ss -ltnH | awk '{{print $4}}' | grep -Eq '^127\\.0\\.0\\.1:8080$'
trap - EXIT
printf '%s\\n' '{{"schema_version":1,"producer":"bridgefu-web-runtime@1","configuration_installed":true,"bridgefu_ready":true,"wss_listener_ready":true,"redacted":true}}'
"""


def cleanup_script(*, execution_id: str) -> str:
    if not IDENTIFIER.fullmatch(execution_id):
        raise WebRuntimeContractError(
            "Bridgefu Web runtime cleanup identity is invalid"
        )
    execution = shlex.quote(execution_id)
    return f"""set -euo pipefail
umask 077
execution={execution}
run=/var/lib/bridgefu/qualification/$execution-web-runtime
config=/etc/bridgefu/bridgefu.yaml
dropin=/etc/systemd/system/bridgefu.service.d/qualification-web-runtime.conf
wrapper=$run/bridgefu-qualification-web-run
[ "$(id -u)" -eq 0 ]
systemctl stop bridgefu.service
[ -f "$run/bridgefu.yaml.original" ] && [ ! -L "$run/bridgefu.yaml.original" ]
cp --preserve=all "$run/bridgefu.yaml.original" "$config"
cmp -s "$run/bridgefu.yaml.original" "$config"
rm -f "$dropin" /run/bridgefu/qualification-vapi.env
systemctl daemon-reload
systemctl start bridgefu.service
for _ in $(seq 1 90); do
  curl -fsS http://127.0.0.1:9090/readyz >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:9090/readyz >/dev/null
rm -f "$run/bridgefu.yaml.original" "$run/bridgefu.yaml.candidate" "$wrapper"
rmdir "$run"
[ ! -e "$run" ] && [ ! -L "$run" ]
[ ! -e "$dropin" ] && [ ! -L "$dropin" ]
[ ! -e "$wrapper" ] && [ ! -L "$wrapper" ]
printf '%s\\n' '{{"schema_version":1,"producer":"bridgefu-web-runtime@1","configuration_restored":true,"overlay_absent":true,"wrapper_absent":true,"dropin_absent":true,"bridgefu_ready":true,"redacted":true}}'
"""


def validate_install_result(value: Any) -> Mapping[str, Any]:
    expected = {
        "schema_version": 1,
        "producer": "bridgefu-web-runtime@1",
        "configuration_installed": True,
        "bridgefu_ready": True,
        "wss_listener_ready": True,
        "redacted": True,
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != INSTALL_RESULT_KEYS
        or value != expected
    ):
        raise WebRuntimeContractError("Bridgefu Web runtime install result is invalid")
    return value


def validate_cleanup_result(value: Any) -> Mapping[str, Any]:
    expected = {
        "schema_version": 1,
        "producer": "bridgefu-web-runtime@1",
        "configuration_restored": True,
        "overlay_absent": True,
        "wrapper_absent": True,
        "dropin_absent": True,
        "bridgefu_ready": True,
        "redacted": True,
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != CLEANUP_RESULT_KEYS
        or value != expected
    ):
        raise WebRuntimeContractError("Bridgefu Web runtime cleanup result is invalid")
    return value
