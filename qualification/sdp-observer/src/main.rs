//! One-shot, qualification-only observer for an inbound Vapi SIP/SDP offer.
//!
//! A qualification controller may temporarily redirect one diagnostic INVITE
//! from Bridgefu's public TLS port to this observer's separate local listener;
//! Bridgefu and its control plane remain running. The observer terminates the
//! same TLS posture, frames and parses the decrypted message through exact
//! crates.io `rvoip-sip-core = 0.3.8`, emits a deliberately lossy summary, and
//! exits. It never logs or persists raw SIP, SDP, addresses, identifiers, or
//! key material.

use anyhow::{bail, Context};
use bytes::Bytes;
use rvoip_sip_core::framing::{
    inspect_sip_frame_with_policy, SipFrame, SipFrameStatus, SipFramingPolicy,
};
use rvoip_sip_core::sdp::parser::parse_sdp;
use rvoip_sip_core::types::{Method, Scheme};
use rvoip_sip_core::{parse_message, Message};
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_rustls::rustls::{
    self, pki_types::CertificateDer, pki_types::PrivateKeyDer, ServerConfig,
};
use tokio_rustls::TlsAcceptor;

const PRODUCER: &str = "bridgefu-sdp-observer@2";
const MAX_SDP_BYTES: usize = 64 * 1024;
const MAX_SDP_LINES: usize = 2_048;
const MAX_MEDIA_SECTIONS: usize = 16;
const MAX_CAPTURE_BYTES: usize = 256 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(30);

const HELP: &str = "\
Qualification-only, one-shot redacted SIP/SDP observer

Usage:
  bridgefu-sdp-observer \\
    --tls-bind 0.0.0.0:15061 \\
    --advertised PUBLIC_IP:5061 \\
    --certificate /etc/bridgefu/tls/fullchain.pem \\
    --private-key /etc/bridgefu/tls/private-key.pem \\
    --output /tmp/bridgefu-sdp-summary.json \\
    [--timeout-seconds 120]

The output never contains raw SIP/SDP, addresses, identifiers, header values,
ICE values, correlation data, SDES keys, or DTLS fingerprint values.
";

#[derive(Debug)]
struct Args {
    tls_bind: SocketAddr,
    advertised: SocketAddr,
    certificate: PathBuf,
    private_key: PathBuf,
    output: PathBuf,
    timeout: Duration,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Summary {
    schema_version: u8,
    producer: &'static str,
    wire: WireSummary,
    sdp_present: bool,
    media: Vec<MediaSummary>,
    sdes: SdesSummary,
    dtls: DtlsSummary,
    redacted: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct WireSummary {
    tls_handshake: &'static str,
    decrypted_payload_present: bool,
    framing: &'static str,
    rvoip_sip_parse: &'static str,
    message_kind: &'static str,
    method: &'static str,
    request_uri_scheme: &'static str,
    header_count: usize,
    via_count: usize,
    contact_count: usize,
    content_type_count: usize,
    content_length_count: usize,
    correlation_header_count: usize,
    content_type: &'static str,
    body_present: bool,
    rvoip_sdp_parse: &'static str,
}

#[derive(Debug)]
struct CapturedFrame {
    bytes: Vec<u8>,
    frame: Option<SipFrame>,
    framing: &'static str,
}

#[derive(Debug)]
struct HeaderFacts {
    header_count: usize,
    via_count: usize,
    contact_count: usize,
    content_type_count: usize,
    content_length_count: usize,
    correlation_header_count: usize,
    content_type: &'static str,
}

impl Default for HeaderFacts {
    fn default() -> Self {
        Self {
            header_count: 0,
            via_count: 0,
            contact_count: 0,
            content_type_count: 0,
            content_length_count: 0,
            correlation_header_count: 0,
            content_type: "absent",
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct MediaSummary {
    kind: &'static str,
    transport: &'static str,
    payload_types: Vec<u8>,
    codecs: Vec<CodecSummary>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct CodecSummary {
    payload_type: u8,
    name: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct SdesSummary {
    crypto_line_count: usize,
    suites: Vec<&'static str>,
    unrecognized_suite_count: usize,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct DtlsSummary {
    fingerprint_present: bool,
    fingerprint_line_count: usize,
    fingerprint_algorithms: Vec<&'static str>,
    unrecognized_fingerprint_algorithm_count: usize,
    setup_values: Vec<&'static str>,
    unrecognized_setup_value_count: usize,
}

#[derive(Debug)]
struct MediaWork {
    kind: &'static str,
    transport: &'static str,
    payload_types: Vec<u8>,
    codecs: HashMap<u8, &'static str>,
}

fn strip_prefix_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
}

fn media_kind(value: &str) -> &'static str {
    if value.eq_ignore_ascii_case("audio") {
        "audio"
    } else if value.eq_ignore_ascii_case("video") {
        "video"
    } else if value.eq_ignore_ascii_case("application") {
        "application"
    } else if value.eq_ignore_ascii_case("text") {
        "text"
    } else if value.eq_ignore_ascii_case("message") {
        "message"
    } else {
        "other"
    }
}

fn transport(value: &str) -> &'static str {
    if value.eq_ignore_ascii_case("RTP/AVP") {
        "RTP/AVP"
    } else if value.eq_ignore_ascii_case("RTP/AVPF") {
        "RTP/AVPF"
    } else if value.eq_ignore_ascii_case("RTP/SAVP") {
        "RTP/SAVP"
    } else if value.eq_ignore_ascii_case("RTP/SAVPF") {
        "RTP/SAVPF"
    } else if value.eq_ignore_ascii_case("UDP/TLS/RTP/SAVP") {
        "UDP/TLS/RTP/SAVP"
    } else if value.eq_ignore_ascii_case("UDP/TLS/RTP/SAVPF") {
        "UDP/TLS/RTP/SAVPF"
    } else if value.eq_ignore_ascii_case("TCP/TLS/RTP/SAVP") {
        "TCP/TLS/RTP/SAVP"
    } else if value.eq_ignore_ascii_case("TCP/TLS/RTP/SAVPF") {
        "TCP/TLS/RTP/SAVPF"
    } else if value.eq_ignore_ascii_case("UDP/DTLS/SCTP") {
        "UDP/DTLS/SCTP"
    } else if value.eq_ignore_ascii_case("TCP/DTLS/SCTP") {
        "TCP/DTLS/SCTP"
    } else if value.eq_ignore_ascii_case("DTLS/SCTP") {
        "DTLS/SCTP"
    } else if value.eq_ignore_ascii_case("TCP/MSRP") {
        "TCP/MSRP"
    } else if value.eq_ignore_ascii_case("TCP/TLS/MSRP") {
        "TCP/TLS/MSRP"
    } else {
        "other"
    }
}

fn codec(value: &str) -> &'static str {
    if value.eq_ignore_ascii_case("PCMU") {
        "PCMU"
    } else if value.eq_ignore_ascii_case("PCMA") {
        "PCMA"
    } else if value.eq_ignore_ascii_case("G722") {
        "G722"
    } else if value.eq_ignore_ascii_case("GSM") {
        "GSM"
    } else if value.eq_ignore_ascii_case("opus") {
        "opus"
    } else if value.eq_ignore_ascii_case("CN") {
        "CN"
    } else if value.eq_ignore_ascii_case("telephone-event") {
        "telephone-event"
    } else if value.eq_ignore_ascii_case("red") {
        "red"
    } else if value.eq_ignore_ascii_case("ulpfec") {
        "ulpfec"
    } else if value.eq_ignore_ascii_case("rtx") {
        "rtx"
    } else if value.eq_ignore_ascii_case("VP8") {
        "VP8"
    } else if value.eq_ignore_ascii_case("VP9") {
        "VP9"
    } else if value.eq_ignore_ascii_case("H264") {
        "H264"
    } else if value.eq_ignore_ascii_case("AV1") {
        "AV1"
    } else {
        "other"
    }
}

fn static_codec(payload_type: u8) -> &'static str {
    match payload_type {
        0 => "PCMU",
        3 => "GSM",
        8 => "PCMA",
        9 => "G722",
        13 => "CN",
        _ => "other",
    }
}

fn crypto_suite(value: &str) -> Option<&'static str> {
    if value.eq_ignore_ascii_case("AES_CM_128_HMAC_SHA1_80") {
        Some("AES_CM_128_HMAC_SHA1_80")
    } else if value.eq_ignore_ascii_case("AES_CM_128_HMAC_SHA1_32") {
        Some("AES_CM_128_HMAC_SHA1_32")
    } else if value.eq_ignore_ascii_case("AES_192_CM_HMAC_SHA1_80") {
        Some("AES_192_CM_HMAC_SHA1_80")
    } else if value.eq_ignore_ascii_case("AES_192_CM_HMAC_SHA1_32") {
        Some("AES_192_CM_HMAC_SHA1_32")
    } else if value.eq_ignore_ascii_case("AES_256_CM_HMAC_SHA1_80") {
        Some("AES_256_CM_HMAC_SHA1_80")
    } else if value.eq_ignore_ascii_case("AES_256_CM_HMAC_SHA1_32") {
        Some("AES_256_CM_HMAC_SHA1_32")
    } else if value.eq_ignore_ascii_case("F8_128_HMAC_SHA1_80") {
        Some("F8_128_HMAC_SHA1_80")
    } else if value.eq_ignore_ascii_case("F8_192_HMAC_SHA1_80") {
        Some("F8_192_HMAC_SHA1_80")
    } else if value.eq_ignore_ascii_case("F8_256_HMAC_SHA1_80") {
        Some("F8_256_HMAC_SHA1_80")
    } else if value.eq_ignore_ascii_case("AEAD_AES_128_GCM") {
        Some("AEAD_AES_128_GCM")
    } else if value.eq_ignore_ascii_case("AEAD_AES_256_GCM") {
        Some("AEAD_AES_256_GCM")
    } else {
        None
    }
}

fn fingerprint_algorithm(value: &str) -> Option<&'static str> {
    if value.eq_ignore_ascii_case("sha-1") {
        Some("sha-1")
    } else if value.eq_ignore_ascii_case("sha-224") {
        Some("sha-224")
    } else if value.eq_ignore_ascii_case("sha-256") {
        Some("sha-256")
    } else if value.eq_ignore_ascii_case("sha-384") {
        Some("sha-384")
    } else if value.eq_ignore_ascii_case("sha-512") {
        Some("sha-512")
    } else {
        None
    }
}

fn setup_value(value: &str) -> Option<&'static str> {
    if value.eq_ignore_ascii_case("active") {
        Some("active")
    } else if value.eq_ignore_ascii_case("passive") {
        Some("passive")
    } else if value.eq_ignore_ascii_case("actpass") {
        Some("actpass")
    } else if value.eq_ignore_ascii_case("holdconn") {
        Some("holdconn")
    } else {
        None
    }
}

fn remember(values: &mut Vec<&'static str>, value: &'static str) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn payload_type(value: &str) -> Option<u8> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u8>().ok().filter(|value| *value <= 127)
}

fn summarize_sdp(sdp: Option<&str>, wire: WireSummary) -> anyhow::Result<Summary> {
    let Some(sdp) = sdp else {
        return Ok(Summary {
            schema_version: 2,
            producer: PRODUCER,
            wire,
            sdp_present: false,
            media: Vec::new(),
            sdes: SdesSummary {
                crypto_line_count: 0,
                suites: Vec::new(),
                unrecognized_suite_count: 0,
            },
            dtls: DtlsSummary {
                fingerprint_present: false,
                fingerprint_line_count: 0,
                fingerprint_algorithms: Vec::new(),
                unrecognized_fingerprint_algorithm_count: 0,
                setup_values: Vec::new(),
                unrecognized_setup_value_count: 0,
            },
            redacted: true,
        });
    };
    if sdp.len() > MAX_SDP_BYTES || sdp.lines().count() > MAX_SDP_LINES {
        bail!("SDP exceeds diagnostic limits")
    }

    let mut media = Vec::<MediaWork>::new();
    let mut current_media = None::<usize>;
    let mut crypto_line_count = 0;
    let mut suites = Vec::new();
    let mut unrecognized_suite_count = 0;
    let mut fingerprint_line_count = 0;
    let mut fingerprint_algorithms = Vec::new();
    let mut unrecognized_fingerprint_algorithm_count = 0;
    let mut setup_values = Vec::new();
    let mut unrecognized_setup_value_count = 0;

    for line in sdp.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if let Some(body) = strip_prefix_ascii_case(line, "m=") {
            if media.len() >= MAX_MEDIA_SECTIONS {
                bail!("SDP exceeds diagnostic limits")
            }
            let tokens = body.split_whitespace().collect::<Vec<_>>();
            if tokens.len() < 4 {
                current_media = None;
                continue;
            }
            let mut payload_types = Vec::new();
            for token in &tokens[3..] {
                if let Some(payload_type) = payload_type(token) {
                    if !payload_types.contains(&payload_type) {
                        payload_types.push(payload_type);
                    }
                }
            }
            media.push(MediaWork {
                kind: media_kind(tokens[0]),
                transport: transport(tokens[2]),
                payload_types,
                codecs: HashMap::new(),
            });
            current_media = Some(media.len() - 1);
            continue;
        }

        if let (Some(body), Some(index)) =
            (strip_prefix_ascii_case(line, "a=rtpmap:"), current_media)
        {
            let mut tokens = body.split_whitespace();
            if let (Some(payload), Some(encoding)) = (tokens.next(), tokens.next()) {
                if let Some(payload) = payload_type(payload) {
                    let encoding = encoding.split('/').next().unwrap_or_default();
                    media[index].codecs.insert(payload, codec(encoding));
                }
            }
            continue;
        }

        if let Some(body) = strip_prefix_ascii_case(line, "a=crypto:") {
            crypto_line_count += 1;
            let mut tokens = body.split_whitespace();
            let _tag = tokens.next();
            match tokens.next().and_then(crypto_suite) {
                Some(suite) => remember(&mut suites, suite),
                None => unrecognized_suite_count += 1,
            }
            continue;
        }

        if let Some(body) = strip_prefix_ascii_case(line, "a=fingerprint:") {
            fingerprint_line_count += 1;
            match body
                .split_whitespace()
                .next()
                .and_then(fingerprint_algorithm)
            {
                Some(algorithm) => remember(&mut fingerprint_algorithms, algorithm),
                None => unrecognized_fingerprint_algorithm_count += 1,
            }
            continue;
        }

        if let Some(body) = strip_prefix_ascii_case(line, "a=setup:") {
            match setup_value(body.trim()) {
                Some(value) => remember(&mut setup_values, value),
                None => unrecognized_setup_value_count += 1,
            }
        }
    }

    let media = media
        .into_iter()
        .map(|section| {
            let codecs = section
                .payload_types
                .iter()
                .copied()
                .map(|payload_type| CodecSummary {
                    payload_type,
                    name: section
                        .codecs
                        .get(&payload_type)
                        .copied()
                        .unwrap_or_else(|| static_codec(payload_type)),
                })
                .collect();
            MediaSummary {
                kind: section.kind,
                transport: section.transport,
                payload_types: section.payload_types,
                codecs,
            }
        })
        .collect();

    Ok(Summary {
        schema_version: 2,
        producer: PRODUCER,
        wire,
        sdp_present: true,
        media,
        sdes: SdesSummary {
            crypto_line_count,
            suites,
            unrecognized_suite_count,
        },
        dtls: DtlsSummary {
            fingerprint_present: fingerprint_line_count > 0,
            fingerprint_line_count,
            fingerprint_algorithms,
            unrecognized_fingerprint_algorithm_count,
            setup_values,
            unrecognized_setup_value_count,
        },
        redacted: true,
    })
}

fn take_option(values: &mut HashMap<String, String>, name: &str) -> anyhow::Result<String> {
    values
        .remove(name)
        .with_context(|| format!("missing required {name}"))
}

fn parse_args(arguments: impl IntoIterator<Item = String>) -> anyhow::Result<Args> {
    let mut arguments = arguments.into_iter();
    let mut values = HashMap::new();
    while let Some(name) = arguments.next() {
        if !matches!(
            name.as_str(),
            "--tls-bind"
                | "--advertised"
                | "--certificate"
                | "--private-key"
                | "--output"
                | "--timeout-seconds"
        ) || values.contains_key(&name)
        {
            bail!("invalid SDP observer arguments")
        }
        let value = arguments
            .next()
            .context("missing SDP observer argument value")?;
        values.insert(name, value);
    }

    let tls_bind = take_option(&mut values, "--tls-bind")?
        .parse::<SocketAddr>()
        .context("invalid TLS bind address")?;
    let advertised = take_option(&mut values, "--advertised")?
        .parse::<SocketAddr>()
        .context("invalid advertised address")?;
    let certificate = PathBuf::from(take_option(&mut values, "--certificate")?);
    let private_key = PathBuf::from(take_option(&mut values, "--private-key")?);
    let output = PathBuf::from(take_option(&mut values, "--output")?);
    let timeout_seconds = values
        .remove("--timeout-seconds")
        .unwrap_or_else(|| "120".to_owned())
        .parse::<u64>()
        .context("invalid timeout")?;

    if !values.is_empty()
        || tls_bind.port() < 1024
        || tls_bind.ip() != IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        || advertised.port() == 0
        || !matches!(advertised.ip(), IpAddr::V4(ip) if !ip.is_unspecified() && !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !ip.is_broadcast() && !ip.is_documentation() && !ip.is_multicast())
        || !certificate.is_absolute()
        || !private_key.is_absolute()
        || !output.is_absolute()
        || certificate == private_key
        || output.exists()
        || !(10..=180).contains(&timeout_seconds)
    {
        bail!("invalid SDP observer arguments")
    }
    let parent = output.parent().context("output has no parent")?;
    if !parent.is_dir() || !certificate.is_file() || !private_key.is_file() {
        bail!("invalid SDP observer files")
    }

    Ok(Args {
        tls_bind,
        advertised,
        certificate,
        private_key,
        output,
        timeout: Duration::from_secs(timeout_seconds),
    })
}

fn write_summary(path: &Path, summary: &Summary) -> anyhow::Result<()> {
    let temporary = path.with_extension("json.tmp");
    if temporary.exists() {
        bail!("temporary observation already exists")
    }
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .context("creating redacted SDP summary")?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, summary)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    drop(writer);
    fs::rename(&temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn method_class(method: &Method) -> &'static str {
    match method {
        Method::Invite => "INVITE",
        Method::Ack => "ACK",
        Method::Bye => "BYE",
        Method::Cancel => "CANCEL",
        Method::Register => "REGISTER",
        Method::Options => "OPTIONS",
        Method::Subscribe => "SUBSCRIBE",
        Method::Notify => "NOTIFY",
        Method::Update => "UPDATE",
        Method::Refer => "REFER",
        Method::Info => "INFO",
        Method::Message => "MESSAGE",
        Method::Prack => "PRACK",
        Method::Publish => "PUBLISH",
        Method::Extension(_) => "other",
    }
}

fn scheme_class(scheme: &Scheme) -> &'static str {
    match scheme {
        Scheme::Sip => "sip",
        Scheme::Sips => "sips",
        _ => "other",
    }
}

fn raw_start_line_facts(bytes: &[u8]) -> (&'static str, &'static str, &'static str) {
    let Some(line_end) = bytes.windows(2).position(|window| window == b"\r\n") else {
        return ("unknown", "none", "unknown");
    };
    let Ok(line) = std::str::from_utf8(&bytes[..line_end]) else {
        return ("unknown", "none", "unknown");
    };
    if line.starts_with("SIP/2.0 ") {
        return ("response", "none", "none");
    }
    let mut tokens = line.split_ascii_whitespace();
    let (Some(method), Some(target), Some(version), None) =
        (tokens.next(), tokens.next(), tokens.next(), tokens.next())
    else {
        return ("unknown", "none", "unknown");
    };
    if version != "SIP/2.0" {
        return ("unknown", "none", "unknown");
    }
    let method = match method {
        "INVITE" => "INVITE",
        "ACK" => "ACK",
        "BYE" => "BYE",
        "CANCEL" => "CANCEL",
        "REGISTER" => "REGISTER",
        "OPTIONS" => "OPTIONS",
        "SUBSCRIBE" => "SUBSCRIBE",
        "NOTIFY" => "NOTIFY",
        "UPDATE" => "UPDATE",
        "REFER" => "REFER",
        "INFO" => "INFO",
        "MESSAGE" => "MESSAGE",
        "PRACK" => "PRACK",
        "PUBLISH" => "PUBLISH",
        _ => "other",
    };
    let scheme = if target
        .get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sips:"))
    {
        "sips"
    } else if target
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sip:"))
    {
        "sip"
    } else {
        "other"
    };
    ("request", method, scheme)
}

fn header_facts(bytes: &[u8], header_bytes: usize) -> HeaderFacts {
    let Some(header) = bytes.get(..header_bytes) else {
        return HeaderFacts::default();
    };
    let Ok(header) = std::str::from_utf8(header) else {
        return HeaderFacts::default();
    };
    let mut facts = HeaderFacts::default();
    for line in header.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        facts.header_count += 1;
        if name.eq_ignore_ascii_case("Via") || name.eq_ignore_ascii_case("v") {
            facts.via_count += 1;
        } else if name.eq_ignore_ascii_case("Contact") || name.eq_ignore_ascii_case("m") {
            facts.contact_count += 1;
        } else if name.eq_ignore_ascii_case("Content-Type") || name.eq_ignore_ascii_case("c") {
            facts.content_type_count += 1;
            let media_type = value.split(';').next().unwrap_or_default().trim();
            let observed = if media_type.eq_ignore_ascii_case("application/sdp") {
                "application/sdp"
            } else {
                "other"
            };
            facts.content_type = match (facts.content_type, observed) {
                ("absent", value) => value,
                (value, observed) if value == observed => value,
                _ => "conflicting",
            };
        } else if name.eq_ignore_ascii_case("Content-Length") || name.eq_ignore_ascii_case("l") {
            facts.content_length_count += 1;
        } else if name.eq_ignore_ascii_case("X-Correlation-Id") {
            facts.correlation_header_count += 1;
        }
    }
    facts
}

fn load_certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).context("opening TLS certificate")?;
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .context("parsing TLS certificate")
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = File::open(path).context("opening TLS private key")?;
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .context("parsing TLS private key")?
        .context("TLS private key is absent")
}

async fn capture_frame(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> anyhow::Result<CapturedFrame> {
    let mut bytes = Vec::new();
    loop {
        if !bytes.is_empty() {
            match inspect_sip_frame_with_policy(&bytes, SipFramingPolicy::Stream) {
                Ok(SipFrameStatus::Complete(frame)) => {
                    bytes.truncate(frame.total_bytes);
                    return Ok(CapturedFrame {
                        bytes,
                        frame: Some(frame),
                        framing: "complete",
                    });
                }
                Ok(SipFrameStatus::Incomplete { .. }) => {}
                Err(error) => {
                    return Ok(CapturedFrame {
                        bytes,
                        frame: None,
                        framing: error.class(),
                    });
                }
            }
        }
        if bytes.len() >= MAX_CAPTURE_BYTES {
            return Ok(CapturedFrame {
                bytes,
                frame: None,
                framing: "diagnostic-limit",
            });
        }
        let mut chunk = [0_u8; 8192];
        match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                let framing = if bytes.is_empty() {
                    "eof-empty"
                } else {
                    "eof-incomplete"
                };
                return Ok(CapturedFrame {
                    bytes,
                    frame: None,
                    framing,
                });
            }
            Ok(Ok(read)) => bytes.extend_from_slice(&chunk[..read]),
            Ok(Err(_)) => {
                return Ok(CapturedFrame {
                    bytes,
                    frame: None,
                    framing: "read-failed",
                });
            }
            Err(_) => {
                return Ok(CapturedFrame {
                    bytes,
                    frame: None,
                    framing: "read-timeout",
                });
            }
        }
    }
}

fn summarize_capture(capture: CapturedFrame) -> anyhow::Result<Summary> {
    let (mut message_kind, mut method, mut request_uri_scheme) =
        raw_start_line_facts(&capture.bytes);
    let facts = capture
        .frame
        .map(|frame| header_facts(&capture.bytes, frame.header_bytes))
        .unwrap_or_default();
    let mut rvoip_sip_parse = "not-attempted";
    let mut body = None;
    let mut rvoip_sdp_parse = "not-attempted";

    if let Some(frame) = capture.frame {
        let message_bytes = &capture.bytes[..frame.total_bytes];
        match parse_message(message_bytes) {
            Ok(Message::Request(request)) => {
                rvoip_sip_parse = "accepted";
                message_kind = "request";
                method = method_class(&request.method());
                request_uri_scheme = scheme_class(request.uri().scheme());
            }
            Ok(Message::Response(_)) => {
                rvoip_sip_parse = "accepted";
                message_kind = "response";
                method = "none";
                request_uri_scheme = "none";
            }
            Err(_) => rvoip_sip_parse = "rejected",
        }
        if facts.content_type == "application/sdp" && frame.body_bytes > 0 {
            let body_bytes = &capture.bytes[frame.header_bytes..frame.total_bytes];
            rvoip_sdp_parse = if parse_sdp(&Bytes::copy_from_slice(body_bytes)).is_ok() {
                "accepted"
            } else {
                "rejected"
            };
            body = std::str::from_utf8(body_bytes).ok();
        }
    }

    let wire = WireSummary {
        tls_handshake: "accepted",
        decrypted_payload_present: !capture.bytes.is_empty(),
        framing: capture.framing,
        rvoip_sip_parse,
        message_kind,
        method,
        request_uri_scheme,
        header_count: facts.header_count,
        via_count: facts.via_count,
        contact_count: facts.contact_count,
        content_type_count: facts.content_type_count,
        content_length_count: facts.content_length_count,
        correlation_header_count: facts.correlation_header_count,
        content_type: facts.content_type,
        body_present: capture.frame.is_some_and(|frame| frame.body_bytes > 0),
        rvoip_sdp_parse,
    };
    summarize_sdp(body, wire)
}

async fn run(args: Args) -> anyhow::Result<()> {
    let _ = args.advertised;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certificates = load_certificates(&args.certificate)?;
    let private_key = load_private_key(&args.private_key)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .context("building TLS server")?;
    let listener = TcpListener::bind(args.tls_bind)
        .await
        .context("binding TLS observer")?;
    let (stream, _) = tokio::time::timeout(args.timeout, listener.accept())
        .await
        .context("SIP connection observation timed out")?
        .context("accepting SIP connection")?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let mut stream = tokio::time::timeout(Duration::from_secs(20), acceptor.accept(stream))
        .await
        .context("TLS handshake observation timed out")?
        .context("accepting TLS handshake")?;
    let summary = summarize_capture(capture_frame(&mut stream).await?)?;
    write_summary(&args.output, &summary)
}

#[tokio::main]
async fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .iter()
        .any(|value| value == "--help" || value == "-h")
    {
        print!("{HELP}");
        return;
    }
    let result = match parse_args(arguments) {
        Ok(args) => run(args).await,
        Err(error) => Err(error),
    };
    if result.is_err() {
        // Errors are deliberately constant so paths or future parser details
        // can never leak into retained qualification evidence.
        eprintln!("SDP observer failed");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire() -> WireSummary {
        WireSummary {
            tls_handshake: "accepted",
            decrypted_payload_present: true,
            framing: "complete",
            rvoip_sip_parse: "accepted",
            message_kind: "request",
            method: "INVITE",
            request_uri_scheme: "sips",
            header_count: 8,
            via_count: 1,
            contact_count: 1,
            content_type_count: 1,
            content_length_count: 1,
            correlation_header_count: 1,
            content_type: "application/sdp",
            body_present: true,
            rvoip_sdp_parse: "accepted",
        }
    }

    fn encoded(summary: &Summary) -> String {
        serde_json::to_string(summary).expect("serialize")
    }

    fn captured(message: Vec<u8>) -> CapturedFrame {
        let SipFrameStatus::Complete(frame) =
            inspect_sip_frame_with_policy(&message, SipFramingPolicy::Stream).expect("frame")
        else {
            panic!("complete frame expected")
        };
        CapturedFrame {
            bytes: message,
            frame: Some(frame),
            framing: "complete",
        }
    }

    fn invite(target: &str, sdp: &str) -> Vec<u8> {
        format!(
            "INVITE {target} SIP/2.0\r\n\
Via: SIP/2.0/TLS client.invalid;branch=z9hG4bK-wire-test\r\n\
Max-Forwards: 70\r\n\
From: <sip:caller@client.invalid>;tag=wire-test\r\n\
To: <{target}>\r\n\
Call-ID: private-call-id-canary\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sips:caller@client.invalid;transport=tls>\r\n\
X-Correlation-Id: bf1_private-correlation-canary\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n{}",
            sdp.len(),
            sdp
        )
        .into_bytes()
    }

    #[test]
    fn sdes_summary_keeps_only_closed_vocabulary_posture() {
        let sdp = "v=0\r\n\
o=caller 123 456 IN IP4 203.0.113.99\r\n\
s=customer-name-canary\r\n\
c=IN IP4 198.51.100.77\r\n\
m=audio 49170 RTP/SAVP 0 8 111 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=rtpmap:101 telephone-event/8000\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:private-key-canary\r\n\
a=x-correlation-id:bf1_private-correlation-canary\r\n";
        let summary = summarize_sdp(Some(sdp), wire()).expect("summary");

        assert_eq!(summary.media[0].transport, "RTP/SAVP");
        assert_eq!(summary.media[0].payload_types, vec![0, 8, 111, 101]);
        assert_eq!(summary.media[0].codecs[0].name, "PCMU");
        assert_eq!(summary.media[0].codecs[2].name, "opus");
        assert_eq!(summary.media[0].codecs[3].name, "telephone-event");
        assert_eq!(summary.sdes.crypto_line_count, 1);
        assert_eq!(summary.sdes.suites, vec!["AES_CM_128_HMAC_SHA1_80"]);
        let encoded = encoded(&summary);
        for private in [
            "private-key-canary",
            "bf1_private-correlation-canary",
            "203.0.113.99",
            "198.51.100.77",
            "customer-name-canary",
        ] {
            assert!(!encoded.contains(private));
        }
    }

    #[test]
    fn dtls_summary_never_repeats_fingerprint_or_ice_values() {
        let sdp = "v=0\n\
a=ice-ufrag:private-ice-user\n\
a=ice-pwd:private-ice-password\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111 0\n\
a=rtpmap:111 opus/48000/2\n\
a=rtpmap:0 PCMU/8000\n\
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11\n\
a=setup:actpass\n\
a=candidate:private-candidate-value\n";
        let summary = summarize_sdp(Some(sdp), wire()).expect("summary");

        assert_eq!(summary.media[0].transport, "UDP/TLS/RTP/SAVPF");
        assert!(summary.dtls.fingerprint_present);
        assert_eq!(summary.dtls.fingerprint_algorithms, vec!["sha-256"]);
        assert_eq!(summary.dtls.setup_values, vec!["actpass"]);
        let encoded = encoded(&summary);
        for private in [
            "AA:BB:CC:DD:EE:FF:00:11",
            "private-ice-user",
            "private-ice-password",
            "private-candidate-value",
        ] {
            assert!(!encoded.contains(private));
        }
    }

    #[test]
    fn unknown_sender_tokens_are_counted_not_reflected() {
        let sdp = "v=0\n\
m=private-media-canary 9 PRIVATE/TRANSPORT/CANARY 126\n\
a=rtpmap:126 private-codec-canary/8000\n\
a=crypto:9 PRIVATE_SUITE_CANARY inline:private-key-canary\n\
a=fingerprint:private-hash-canary PRIVATE:FINGERPRINT:CANARY\n\
a=setup:private-setup-canary\n";
        let summary = summarize_sdp(Some(sdp), wire()).expect("summary");

        assert_eq!(summary.media[0].kind, "other");
        assert_eq!(summary.media[0].transport, "other");
        assert_eq!(summary.media[0].codecs[0].name, "other");
        assert_eq!(summary.sdes.unrecognized_suite_count, 1);
        assert_eq!(summary.dtls.unrecognized_fingerprint_algorithm_count, 1);
        assert_eq!(summary.dtls.unrecognized_setup_value_count, 1);
        assert!(!encoded(&summary).to_ascii_lowercase().contains("canary"));
    }

    #[test]
    fn missing_sdp_is_explicit_and_still_redacted() {
        let summary = summarize_sdp(None, wire()).expect("summary");
        assert!(!summary.sdp_present);
        assert!(summary.media.is_empty());
        assert!(summary.redacted);
    }

    #[test]
    fn excessive_sdp_fails_without_reflecting_input() {
        let canary = "private-oversized-canary".repeat(MAX_SDP_BYTES);
        let error = summarize_sdp(Some(&canary), wire()).expect_err("limit");
        assert!(error.to_string().contains("diagnostic limits"));
        assert!(!error.to_string().contains("private-oversized-canary"));
    }

    #[test]
    fn exact_rvoip_parser_acceptance_and_plain_media_are_distinct_facts() {
        let sdp = "v=0\r\n\
o=caller 1 1 IN IP4 203.0.113.50\r\n\
s=private-session-canary\r\n\
c=IN IP4 203.0.113.51\r\n\
t=0 0\r\n\
m=audio 40000 RTP/AVP 0 101\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:101 telephone-event/8000\r\n";
        let summary = summarize_capture(captured(invite(
            "sips:private-route-canary@example.invalid:5061;transport=tls",
            sdp,
        )))
        .expect("summary");

        assert_eq!(summary.wire.tls_handshake, "accepted");
        assert_eq!(summary.wire.framing, "complete");
        assert_eq!(summary.wire.rvoip_sip_parse, "accepted");
        assert_eq!(summary.wire.method, "INVITE");
        assert_eq!(summary.wire.request_uri_scheme, "sips");
        assert_eq!(summary.wire.correlation_header_count, 1);
        assert_eq!(summary.wire.rvoip_sdp_parse, "accepted");
        assert_eq!(summary.media[0].transport, "RTP/AVP");
        assert_eq!(summary.sdes.crypto_line_count, 0);
        assert!(!summary.dtls.fingerprint_present);
        let output = encoded(&summary);
        for private in [
            "private-route-canary",
            "private-call-id-canary",
            "private-correlation-canary",
            "private-session-canary",
            "203.0.113.50",
            "203.0.113.51",
        ] {
            assert!(!output.contains(private));
        }
    }

    #[test]
    fn sip_syntax_rejection_does_not_hide_a_bounded_sdp_posture() {
        let sdp = "v=0\r\no=x 1 1 IN IP4 203.0.113.60\r\ns=x\r\nc=IN IP4 203.0.113.61\r\nt=0 0\r\n\
m=audio 40000 RTP/SAVP 0\r\n\
a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZWNyZXRfa2V5X3RoaXJ0ZV9ieXRlcw==\r\n";
        let mut message = invite("sips:route@example.invalid:5061;transport=tls", sdp);
        message.splice(
            ..message.iter().position(|byte| *byte == b'\r').unwrap(),
            b"INVITE invalid target SIP/2.0".iter().copied(),
        );
        let summary = summarize_capture(captured(message)).expect("summary");

        assert_eq!(summary.wire.rvoip_sip_parse, "rejected");
        assert_eq!(summary.wire.rvoip_sdp_parse, "accepted");
        assert_eq!(summary.media[0].transport, "RTP/SAVP");
        assert_eq!(summary.sdes.crypto_line_count, 1);
        assert!(!encoded(&summary).contains("WVNfX19zZWNyZXRfa2V5X3RoaXJ0ZV9ieXRlcw"));
    }
}
