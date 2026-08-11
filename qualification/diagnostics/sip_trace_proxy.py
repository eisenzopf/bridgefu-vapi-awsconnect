#!/usr/bin/env python3
"""One-shot TLS SIP proxy that persists only a protocol-complete redacted trace.

This is a maintainer diagnostic, not a product component.  Raw SIP exists only
in bounded process memory while it is relayed byte-for-byte.  The output keeps
message ordering, SIP methods/statuses, header names, safe protocol values, and
SDP media/security attributes while replacing credentials, identifiers,
addresses, ports, tags, branches, keys, and customer-controlled text.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import select
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any

PRODUCER = "bridgefu-vapi-sip-trace-proxy@1"
MAX_DIRECTION_BYTES = 256 * 1024
MAX_MESSAGES = 32
MAX_OUTPUT_BYTES = 22 * 1024
SIP_METHODS = {
    "ACK",
    "BYE",
    "CANCEL",
    "INFO",
    "INVITE",
    "MESSAGE",
    "NOTIFY",
    "OPTIONS",
    "PRACK",
    "PUBLISH",
    "REFER",
    "REGISTER",
    "SUBSCRIBE",
    "UPDATE",
}
SAFE_HEADERS = {
    "accept",
    "accept-encoding",
    "allow",
    "allow-events",
    "content-disposition",
    "content-encoding",
    "content-length",
    "content-type",
    "cseq",
    "expires",
    "max-forwards",
    "min-expires",
    "min-se",
    "proxy-require",
    "require",
    "server",
    "session-expires",
    "supported",
    "timestamp",
    "unsupported",
    "user-agent",
}
URI_HEADERS = {
    "contact",
    "from",
    "record-route",
    "referred-by",
    "refer-to",
    "route",
    "to",
}
SECRET_HEADERS = {
    "authentication-info",
    "authorization",
    "identity",
    "p-asserted-identity",
    "p-preferred-identity",
    "proxy-authenticate",
    "proxy-authorization",
    "www-authenticate",
}
URI = re.compile(
    r"(?i)\b(sips?):([^@>;,'\"\s]+)@([^>;,'\"\s]+)"
)
IPV4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
TOKEN_PARAM = re.compile(r"(?i)(?P<name>branch|tag|received)=([^;>\s,]+)")
CORRELATION = re.compile(r"(?i)bf1_[A-Za-z0-9_-]{20,128}")


class TraceError(RuntimeError):
    """Closed diagnostic failure."""


def split_host_port(value: str) -> tuple[str, str]:
    if value.startswith("[") and "]" in value:
        _, remainder = value.split("]", 1)
        return "<redacted-host>", remainder if remainder.startswith(":") else ""
    host, separator, port = value.rpartition(":")
    if separator and host and port.isdigit():
        return "<redacted-host>", f":{port}"
    return "<redacted-host>", ""


def redact_uri_text(value: str) -> str:
    def replace_uri(match: re.Match[str]) -> str:
        host, port = split_host_port(match.group(3))
        return f"{match.group(1).lower()}:<redacted-user>@{host}{port}"

    value = URI.sub(replace_uri, value)
    value = CORRELATION.sub("<redacted-correlation-id>", value)
    value = TOKEN_PARAM.sub(
        lambda match: f"{match.group('name')}=<redacted>", value
    )
    return IPV4.sub("<redacted-ip>", value)


def redact_via(value: str) -> str:
    parts = value.strip().split(";", 1)
    first = parts[0].split()
    protocol = first[0] if first and re.fullmatch(r"SIP/2\.0/[A-Za-z]+", first[0]) else "SIP/2.0/<redacted>"
    parameters: list[str] = []
    if len(parts) == 2:
        for item in parts[1].split(";"):
            name, separator, _ = item.partition("=")
            if not re.fullmatch(r"[A-Za-z0-9_.!%*+`'~-]{1,64}", name):
                parameters.append("<redacted-param>")
            elif separator:
                parameters.append(f"{name}=<redacted>")
            else:
                parameters.append(name)
    suffix = ";" + ";".join(parameters) if parameters else ""
    return f"{protocol} <redacted-hop>{suffix}"


def redact_header(line: str) -> str:
    name, separator, value = line.partition(":")
    if not separator or not re.fullmatch(r"[A-Za-z0-9_.!%*+`'~-]{1,64}", name):
        return "<redacted-malformed-header>"
    lowered = name.lower()
    if lowered in {"via", "v"}:
        rendered = redact_via(value)
    elif lowered in {"call-id", "i"}:
        rendered = "<redacted-call-id>"
    elif lowered in {"x-correlation-id", "x-bridgefu-correlation-id"}:
        rendered = "<redacted-correlation-id>"
    elif lowered in SECRET_HEADERS:
        rendered = "<redacted-credential-or-identity>"
    elif lowered in URI_HEADERS or lowered in {"f", "m", "t"}:
        rendered = redact_uri_text(value.strip())
    elif lowered in SAFE_HEADERS or lowered in {"c", "l"}:
        rendered = redact_uri_text(value.strip())
    else:
        rendered = "<redacted-value>"
    return f"{name}: {rendered}"


def redact_start_line(line: str) -> str:
    if re.fullmatch(r"SIP/2\.0 [1-6][0-9]{2}(?: [\x20-\x7e]{0,80})?", line):
        return line
    parts = line.split(" ")
    if len(parts) == 3 and parts[0] in SIP_METHODS and parts[2] == "SIP/2.0":
        return f"{parts[0]} {redact_uri_text(parts[1])} SIP/2.0"
    return "<redacted-malformed-start-line>"


def redact_sdp_line(line: str) -> str:
    if line == "v=0":
        return line
    if line.startswith("o="):
        tokens = line[2:].split()
        if len(tokens) == 6 and tokens[3] == "IN" and tokens[4] in {"IP4", "IP6"}:
            return f"o=<redacted> <redacted> <redacted> IN {tokens[4]} <redacted-address>"
        return "o=<redacted>"
    if line.startswith("s="):
        return "s=-" if line == "s=-" else "s=<redacted-session-name>"
    if line.startswith("c="):
        tokens = line[2:].split()
        if len(tokens) >= 3 and tokens[0] == "IN" and tokens[1] in {"IP4", "IP6"}:
            return f"c=IN {tokens[1]} <redacted-address>"
        return "c=<redacted>"
    if line.startswith("m="):
        tokens = line[2:].split()
        if len(tokens) >= 4:
            return "m=" + " ".join(
                [tokens[0], "<redacted-port>", tokens[2], *tokens[3:]]
            )
        return "m=<redacted>"
    if re.fullmatch(r"t=[0-9]+ [0-9]+", line):
        return line
    if re.fullmatch(r"b=[A-Za-z0-9-]+:[0-9]+", line):
        return line
    if line.startswith("a=crypto:"):
        match = re.fullmatch(r"a=crypto:([0-9]+) ([A-Za-z0-9_]+)(?: .*)?", line)
        if match:
            return f"a=crypto:{match.group(1)} {match.group(2)} inline:<redacted-key>"
        return "a=crypto:<redacted>"
    if line.startswith("a=fingerprint:"):
        algorithm = line[len("a=fingerprint:") :].split(None, 1)[0]
        if re.fullmatch(r"[A-Za-z0-9-]{1,32}", algorithm):
            return f"a=fingerprint:{algorithm} <redacted-fingerprint>"
        return "a=fingerprint:<redacted>"
    safe_attribute = re.fullmatch(
        r"a=(?:rtpmap|fmtp|ptime|maxptime|setup|ice-options|extmap|rtcp-fb):[\x20-\x7e]{1,512}",
        line,
    )
    if safe_attribute:
        return line
    if line in {
        "a=inactive",
        "a=recvonly",
        "a=rtcp-mux",
        "a=rtcp-rsize",
        "a=sendonly",
        "a=sendrecv",
    }:
        return line
    if line.startswith("a="):
        name = line[2:].split(":", 1)[0]
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            return f"a={name}:<redacted>" if ":" in line else f"a={name}"
        return "a=<redacted>"
    if len(line) >= 2 and line[1] == "=":
        return f"{line[:2]}<redacted>"
    return "<redacted-sdp-line>"


def frame_messages(buffer: bytearray) -> list[bytes]:
    messages: list[bytes] = []
    while buffer.startswith(b"\r\n"):
        del buffer[:2]
    while True:
        end = buffer.find(b"\r\n\r\n")
        if end < 0:
            return messages
        header_end = end + 4
        try:
            header = buffer[:end].decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise TraceError("SIP header is not UTF-8") from error
        lengths: list[int] = []
        for line in header.split("\r\n")[1:]:
            name, separator, value = line.partition(":")
            if separator and name.lower() in {"content-length", "l"}:
                if not value.strip().isdigit():
                    raise TraceError("SIP Content-Length is invalid")
                lengths.append(int(value.strip()))
        if len(lengths) > 1 and len(set(lengths)) != 1:
            raise TraceError("SIP Content-Length is conflicting")
        body_bytes = lengths[0] if lengths else 0
        if body_bytes > 64 * 1024:
            raise TraceError("SIP body exceeds trace limit")
        total = header_end + body_bytes
        if len(buffer) < total:
            return messages
        messages.append(bytes(buffer[:total]))
        del buffer[:total]
        while buffer.startswith(b"\r\n"):
            del buffer[:2]


def redact_message(raw: bytes, *, sequence: int, direction: str, offset_ms: int) -> dict[str, Any]:
    end = raw.find(b"\r\n\r\n")
    if end < 0:
        raise TraceError("SIP frame is incomplete")
    try:
        header = raw[:end].decode("utf-8", "strict")
        body = raw[end + 4 :].decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise TraceError("SIP message is not UTF-8") from error
    lines = header.split("\r\n")
    start_line = redact_start_line(lines[0])
    headers = [redact_header(line) for line in lines[1:]]
    content_type = next(
        (
            line.partition(":")[2].strip().split(";", 1)[0].lower()
            for line in lines[1:]
            if line.partition(":")[0].lower() in {"content-type", "c"}
        ),
        "",
    )
    if body and content_type == "application/sdp":
        body_lines = [redact_sdp_line(line) for line in body.splitlines()]
        body_type = "application/sdp"
    elif body:
        body_lines = ["<redacted-non-sdp-body>"]
        body_type = "other"
    else:
        body_lines = []
        body_type = "none"
    return {
        "sequence": sequence,
        "offset_ms": offset_ms,
        "direction": direction,
        "transport": "TLS",
        "wire_bytes": len(raw),
        "wire_sha256": hashlib.sha256(raw).hexdigest(),
        "start_line": start_line,
        "headers": headers,
        "body_type": body_type,
        "body": body_lines,
    }


class Recorder:
    def __init__(self) -> None:
        self.started = time.monotonic()
        self.lock = threading.Lock()
        self.messages: list[dict[str, Any]] = []
        self.buffers = {
            "Vapi -> Bridgefu": bytearray(),
            "Bridgefu -> Vapi": bytearray(),
        }
        self.error = None

    def observe(self, direction: str, payload: bytes) -> None:
        with self.lock:
            buffer = self.buffers[direction]
            if len(buffer) + len(payload) > MAX_DIRECTION_BYTES:
                raise TraceError("direction capture exceeds trace limit")
            buffer.extend(payload)
            for raw in frame_messages(buffer):
                if len(self.messages) >= MAX_MESSAGES:
                    raise TraceError("message count exceeds trace limit")
                self.messages.append(
                    redact_message(
                        raw,
                        sequence=len(self.messages) + 1,
                        direction=direction,
                        offset_ms=round((time.monotonic() - self.started) * 1000),
                    )
                )

    def has_final_and_ack(self) -> bool:
        with self.lock:
            final = any(
                item["direction"] == "Bridgefu -> Vapi"
                and re.match(r"SIP/2\.0 [3-6][0-9]{2}", item["start_line"])
                for item in self.messages
            )
            ack = any(
                item["direction"] == "Vapi -> Bridgefu"
                and item["start_line"].startswith("ACK ")
                for item in self.messages
            )
            return final and ack


def relay(source: ssl.SSLSocket, destination: ssl.SSLSocket, direction: str, recorder: Recorder, stop: threading.Event) -> None:
    try:
        source.setblocking(False)
        while not stop.is_set():
            readable = [source] if source.pending() else select.select([source], [], [], 0.25)[0]
            if not readable:
                continue
            try:
                payload = source.recv(8192)
            except (ssl.SSLWantReadError, BlockingIOError):
                continue
            if not payload:
                stop.set()
                return
            recorder.observe(direction, payload)
            view = memoryview(payload)
            while view and not stop.is_set():
                try:
                    sent = destination.send(view)
                    view = view[sent:]
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                    select.select([], [destination], [], 0.25)
    except (OSError, ssl.SSLError, TraceError):
        recorder.error = "relay-failed"
        stop.set()


def exact_address(value: str) -> tuple[str, int]:
    host, separator, port = value.rpartition(":")
    if not separator or not host or not port.isdigit() or not 1024 <= int(port) <= 65535:
        raise TraceError("address is invalid")
    return host, int(port)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", required=True)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--server-name", required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    if (
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", args.server_name)
        or not args.certificate.is_absolute()
        or not args.private_key.is_absolute()
        or not args.output.is_absolute()
        or args.output.exists()
        or not args.certificate.is_file()
        or not args.private_key.is_file()
        or not args.output.parent.is_dir()
        or not 30 <= args.timeout_seconds <= 180
    ):
        raise TraceError("arguments are invalid")
    exact_address(args.listen)
    exact_address(args.upstream)
    return args


def write_private(path: Path, value: dict[str, Any]) -> None:
    encoded = (json.dumps(value, indent=2, sort_keys=False) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise TraceError("redacted trace exceeds output limit")
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def run(args: argparse.Namespace) -> None:
    listen = exact_address(args.listen)
    upstream = exact_address(args.upstream)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(args.certificate, args.private_key)
    client_context = ssl.create_default_context()
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    recorder = Recorder()
    stop = threading.Event()
    downstream = None
    upstream_tls = None
    downstream_version = "unknown"
    upstream_version = "unknown"
    with socket.create_server(listen, backlog=1) as listener:
        listener.settimeout(args.timeout_seconds)
        accepted, _ = listener.accept()
        with accepted:
            downstream = server_context.wrap_socket(accepted, server_side=True)
            downstream_version = downstream.version() or "unknown"
            raw_upstream = socket.create_connection(upstream, timeout=15)
            upstream_tls = client_context.wrap_socket(
                raw_upstream, server_hostname=args.server_name
            )
            upstream_version = upstream_tls.version() or "unknown"
            threads = [
                threading.Thread(
                    target=relay,
                    args=(downstream, upstream_tls, "Vapi -> Bridgefu", recorder, stop),
                    daemon=True,
                ),
                threading.Thread(
                    target=relay,
                    args=(upstream_tls, downstream, "Bridgefu -> Vapi", recorder, stop),
                    daemon=True,
                ),
            ]
            for thread in threads:
                thread.start()
            deadline = time.monotonic() + args.timeout_seconds
            final_ack_at = None
            while not stop.is_set() and time.monotonic() < deadline:
                if recorder.has_final_and_ack():
                    final_ack_at = final_ack_at or time.monotonic()
                    if time.monotonic() - final_ack_at >= 0.75:
                        stop.set()
                        break
                time.sleep(0.05)
            stop.set()
            for stream in (downstream, upstream_tls):
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            for thread in threads:
                thread.join(timeout=2)

    with recorder.lock:
        messages = list(recorder.messages)
        trailing = {name: len(value) for name, value in recorder.buffers.items()}
    final_statuses = [
        int(item["start_line"].split()[1])
        for item in messages
        if item["direction"] == "Bridgefu -> Vapi"
        and re.match(r"SIP/2\.0 [1-6][0-9]{2}", item["start_line"])
    ]
    invite = next(
        (
            item
            for item in messages
            if item["direction"] == "Vapi -> Bridgefu"
            and item["start_line"].startswith("INVITE ")
        ),
        None,
    )
    sdp = invite["body"] if invite and invite["body_type"] == "application/sdp" else []
    media_profiles = [line.split()[2] for line in sdp if line.startswith("m=") and len(line.split()) >= 3]
    output = {
        "schema_version": 1,
        "producer": PRODUCER,
        "captured_at": (
            dt.datetime.now(dt.timezone.utc)  # noqa: UP017 -- remote is Python 3.9
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        ),
        "tls": {
            "vapi_to_proxy": downstream_version,
            "proxy_to_bridgefu": upstream_version,
            "bridgefu_certificate_verified": True,
        },
        "messages": messages,
        "summary": {
            "vapi_invite_observed": invite is not None,
            "media_profiles": media_profiles,
            "sdes_crypto_line_count": sum(line.startswith("a=crypto:") for line in sdp),
            "dtls_fingerprint_line_count": sum(line.startswith("a=fingerprint:") for line in sdp),
            "bridgefu_statuses": final_statuses,
            "vapi_ack_observed": any(
                item["direction"] == "Vapi -> Bridgefu"
                and item["start_line"].startswith("ACK ")
                for item in messages
            ),
            "complete_frames_only": not any(trailing.values()),
        },
        "redaction": {
            "raw_sip_persisted": False,
            "credentials_redacted": True,
            "identifiers_redacted": True,
            "addresses_redacted": True,
            "sdp_key_material_redacted": True,
        },
        "redacted": True,
    }
    if recorder.error is not None or invite is None or not final_statuses:
        raise TraceError("trace exchange is incomplete")
    write_private(args.output, output)


def main() -> int:
    try:
        args = parse_args()
        run(args)
    except (OSError, ssl.SSLError, TraceError):
        print("SIP trace proxy failed", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
