//! Qualification-only direct SIPS/SDES-SRTP probe for Bridgefu.
//!
//! The destination URI, one-use route token, correlation value, SDP, and
//! addresses arrive only through a bounded private stdin document and never
//! appear in arguments, application output, or errors. The successful artifact
//! contains only fixed classifications, booleans, and bounded counts.

use anyhow::{bail, Context};
use rvoip_sip::api::headers::SipRequestOptions;
use rvoip_sip::{
    AudioFrame, CallHandlerDecision, CallId, CallbackPeer, Config, HeaderName,
    MediaSecurityProfile, RedactionDecision, SipTlsMode, SipTrace, SipTraceConfig,
    SipTraceDirection, TraceRedactor,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const PRODUCER: &str = "bridgefu-direct-secure-probe@1";
const CORRELATION_HEADER: &str = "X-Correlation-Id";
const MAX_REQUEST_BYTES: usize = 4 * 1024;
const FRAME_SAMPLES: usize = 160;
const FRAME_DURATION: Duration = Duration::from_millis(20);
const MARKER_FREQUENCY: f32 = 997.0;
// Keep the deterministic marker on the wire long enough for Amazon Connect to
// route the contact, for the agent to accept it, and for Chromium to sample the
// established WebRTC media. The first live qualification showed that twelve
// seconds ended roughly one second after agent acceptance, which made the
// observer race the BYE even though TLS/SRTP and Connect delivery succeeded.
const MARKER_BURSTS: usize = 32;
const MARKER_FRAMES_PER_BURST: usize = 10;
const MARKER_SILENCE_FRAMES_PER_BURST: usize = 40;
const MARKER_FRAMES: usize = MARKER_BURSTS * MARKER_FRAMES_PER_BURST;
const MARKER_TOTAL_FRAMES: usize =
    MARKER_BURSTS * (MARKER_FRAMES_PER_BURST + MARKER_SILENCE_FRAMES_PER_BURST);
const DTMF_FRAMES: usize = 15;
const DTMF_TRAILING_SILENCE_FRAMES: usize = 5;
const DTMF_LOW_FREQUENCY: f32 = 770.0;
const DTMF_HIGH_FREQUENCY: f32 = 1_336.0;

const HELP: &str = "\
Qualification-only direct secure Bridgefu probe

Usage:
  bridgefu-direct-secure-probe \\
    --request-stdin \\
    --output /tmp/bridgefu-direct-secure-probe.json \\
    [--sip-port 5077] \\
    [--media-port-start 41000] \\
    [--timeout-seconds 90] \\
    [--send-dtmf]

Standard input must contain one bounded private JSON request. Sensitive call
values are deliberately unavailable as command-line options.
";

#[derive(Debug)]
struct Args {
    output: PathBuf,
    sip_port: u16,
    media_port_start: u16,
    timeout: Duration,
    send_dtmf: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateRequest {
    schema_version: u8,
    sip_uri: String,
    correlation_id: String,
    media_advertised_ip: Option<IpAddr>,
}

#[derive(Debug)]
struct ValidatedRequest {
    sip_uri: String,
    correlation_id: String,
    destination_host: String,
    media_advertised_ip: Option<IpAddr>,
}

#[derive(Debug, Default)]
struct WireEvidence {
    invite_count: usize,
    correlation_header_count: Option<usize>,
    header_contract_failed: bool,
    outbound_invite_tls: bool,
    safe_trace: bool,
    inbound_200: bool,
    inbound_200_tls: bool,
    outbound_ack: bool,
    outbound_ack_tls: bool,
    dialog_session: Option<CallId>,
    dialog_session_conflict: bool,
    contact_observed: bool,
    contact: ContactEvidence,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ContactHost {
    #[default]
    Absent,
    Redacted,
    Ipv4,
    Dns,
}

impl ContactHost {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Redacted => "redacted",
            Self::Ipv4 => "ipv4",
            Self::Dns => "dns",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "absent" => Some(Self::Absent),
            "redacted" => Some(Self::Redacted),
            "ipv4" => Some(Self::Ipv4),
            "dns" => Some(Self::Dns),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum FixedState {
    #[default]
    Unknown,
    No,
    Yes,
}

impl FixedState {
    const fn from_bool(value: bool) -> Self {
        if value {
            Self::Yes
        } else {
            Self::No
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::No => "no",
            Self::Yes => "yes",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "unknown" => Some(Self::Unknown),
            "no" => Some(Self::No),
            "yes" => Some(Self::Yes),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum CSeqMethod {
    #[default]
    Unknown,
    Invite,
    Ack,
    Bye,
    Other,
}

impl CSeqMethod {
    const fn marker(self) -> &'static str {
        match self {
            Self::Unknown => "<bridgefu-probe-cseq;method=unknown>",
            Self::Invite => "<bridgefu-probe-cseq;method=invite>",
            Self::Ack => "<bridgefu-probe-cseq;method=ack>",
            Self::Bye => "<bridgefu-probe-cseq;method=bye>",
            Self::Other => "<bridgefu-probe-cseq;method=other>",
        }
    }

    fn parse_marker(value: &str) -> Option<Self> {
        match value.trim() {
            "<bridgefu-probe-cseq;method=unknown>" => Some(Self::Unknown),
            "<bridgefu-probe-cseq;method=invite>" => Some(Self::Invite),
            "<bridgefu-probe-cseq;method=ack>" => Some(Self::Ack),
            "<bridgefu-probe-cseq;method=bye>" => Some(Self::Bye),
            "<bridgefu-probe-cseq;method=other>" => Some(Self::Other),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ContactEvidence {
    host: ContactHost,
    sips: FixedState,
    tls: FixedState,
}

impl ContactEvidence {
    const fn redacted() -> Self {
        Self {
            host: ContactHost::Redacted,
            sips: FixedState::Unknown,
            tls: FixedState::Unknown,
        }
    }

    fn marker(self) -> String {
        format!(
            "<bridgefu-probe-contact;host={};sips={};tls={}>",
            self.host.as_str(),
            self.sips.as_str(),
            self.tls.as_str()
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FailureWireSummary {
    inbound_200: bool,
    outbound_ack: bool,
    contact: ContactEvidence,
}

impl std::fmt::Display for FailureWireSummary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "inbound_200={} outbound_ack={} contact={} contact_sips={} contact_tls={}",
            yes_no(self.inbound_200),
            yes_no(self.outbound_ack),
            self.contact.host.as_str(),
            self.contact.sips.as_str(),
            self.contact.tls.as_str()
        )
    }
}

impl std::error::Error for FailureWireSummary {}

#[derive(Debug)]
struct ProbeTraceRedactor;

impl TraceRedactor for ProbeTraceRedactor {
    fn redact(&self, header: &HeaderName, value: &str) -> RedactionDecision {
        let marker = match header {
            HeaderName::Contact => classify_contact(value).marker(),
            HeaderName::CSeq => classify_cseq_method(value).marker().to_owned(),
            _ => "<bridgefu-probe-redacted>".to_owned(),
        };
        RedactionDecision::Redact(marker)
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Observation {
    schema_version: u8,
    producer: &'static str,
    signaling: SignalingObservation,
    media: MediaObservation,
    hangup: HangupObservation,
    redacted: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct SignalingObservation {
    scheme: &'static str,
    transport: &'static str,
    invite_count: usize,
    correlation_header_count: usize,
    answered: bool,
    inbound_200: bool,
    outbound_ack: bool,
    contact_host: &'static str,
    contact_sips: bool,
    contact_tls: bool,
    trace_redacted: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct MediaObservation {
    profile: &'static str,
    keying: &'static str,
    contexts_installed: bool,
    audio_opened: bool,
    marker_frames_sent: usize,
    codec: &'static str,
    dtmf_requested: bool,
    in_band_dtmf_frames_sent: usize,
    rfc4733_dtmf_sent: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct HangupObservation {
    local_bye_completed: bool,
    cleanup_observed: bool,
}

fn take_option(values: &mut HashMap<String, String>, name: &str) -> anyhow::Result<String> {
    values
        .remove(name)
        .with_context(|| format!("missing required {name}"))
}

fn parse_args(arguments: impl IntoIterator<Item = String>) -> anyhow::Result<Args> {
    let mut arguments = arguments.into_iter();
    let mut values = HashMap::new();
    let mut request_stdin = false;
    let mut send_dtmf = false;

    while let Some(name) = arguments.next() {
        match name.as_str() {
            "--request-stdin" if !request_stdin => request_stdin = true,
            "--send-dtmf" if !send_dtmf => send_dtmf = true,
            "--output" | "--sip-port" | "--media-port-start" | "--timeout-seconds"
                if !values.contains_key(&name) =>
            {
                let value = arguments
                    .next()
                    .context("missing secure probe argument value")?;
                values.insert(name, value);
            }
            _ => bail!("invalid secure probe arguments"),
        }
    }
    if !request_stdin {
        bail!("private request must arrive on standard input")
    }

    let output = PathBuf::from(take_option(&mut values, "--output")?);
    let sip_port = values
        .remove("--sip-port")
        .unwrap_or_else(|| "5077".to_owned())
        .parse::<u16>()
        .context("invalid SIP port")?;
    let media_port_start = values
        .remove("--media-port-start")
        .unwrap_or_else(|| "41000".to_owned())
        .parse::<u16>()
        .context("invalid media port")?;
    let timeout_seconds = values
        .remove("--timeout-seconds")
        .unwrap_or_else(|| "90".to_owned())
        .parse::<u64>()
        .context("invalid timeout")?;
    if !values.is_empty()
        || !output.is_absolute()
        || output.exists()
        || output.parent().is_none_or(|parent| !parent.is_dir())
        || sip_port < 1024
        || !(1024..=u16::MAX - 31).contains(&media_port_start)
        || !(30..=180).contains(&timeout_seconds)
    {
        bail!("invalid secure probe arguments")
    }

    Ok(Args {
        output,
        sip_port,
        media_port_start,
        timeout: Duration::from_secs(timeout_seconds),
        send_dtmf,
    })
}

fn read_request() -> anyhow::Result<PrivateRequest> {
    let mut encoded = Vec::new();
    std::io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .context("reading private secure probe request")?;
    if encoded.is_empty() || encoded.len() > MAX_REQUEST_BYTES {
        bail!("private secure probe request exceeds its boundary")
    }
    serde_json::from_slice(&encoded).context("private secure probe request is invalid")
}

fn valid_hostname(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

const fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn strip_ascii_case_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let candidate = value.get(..prefix.len())?;
    candidate
        .eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
}

fn classify_contact(value: &str) -> ContactEvidence {
    let value = value.trim();
    let uri = match value.find('<') {
        Some(start) => value
            .get(start + 1..)
            .and_then(|remainder| remainder.split_once('>').map(|(uri, _)| uri.trim())),
        None => value.split(',').next().map(str::trim),
    };
    let Some(uri) = uri else {
        return ContactEvidence::redacted();
    };
    let (sips, remainder) = if let Some(remainder) = strip_ascii_case_prefix(uri, "sips:") {
        (FixedState::Yes, remainder)
    } else if let Some(remainder) = strip_ascii_case_prefix(uri, "sip:") {
        (FixedState::No, remainder)
    } else {
        return ContactEvidence::redacted();
    };

    let authority_end = remainder.find([';', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let parameters = &remainder[authority_end..];
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if host_and_port.starts_with('[') {
        return ContactEvidence {
            host: ContactHost::Redacted,
            sips,
            tls: classify_tls_parameter(parameters),
        };
    } else if let Some((host, port)) = host_and_port.rsplit_once(':') {
        if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
            host
        } else {
            host_and_port
        }
    } else {
        host_and_port
    };
    let host = if host.parse::<Ipv4Addr>().is_ok() {
        ContactHost::Ipv4
    } else if valid_hostname(host) {
        ContactHost::Dns
    } else {
        ContactHost::Redacted
    };
    ContactEvidence {
        host,
        sips,
        tls: classify_tls_parameter(parameters),
    }
}

fn classify_tls_parameter(parameters: &str) -> FixedState {
    FixedState::from_bool(parameters.split(';').skip(1).any(|parameter| {
        parameter
            .split_once('?')
            .map_or(parameter, |(before_query, _)| before_query)
            .eq_ignore_ascii_case("transport=tls")
    }))
}

fn parse_contact_marker(value: &str) -> Option<ContactEvidence> {
    let value = value
        .trim()
        .strip_prefix("<bridgefu-probe-contact;host=")?
        .strip_suffix('>')?;
    let (host, value) = value.split_once(";sips=")?;
    let (sips, tls) = value.split_once(";tls=")?;
    Some(ContactEvidence {
        host: ContactHost::parse(host)?,
        sips: FixedState::parse(sips)?,
        tls: FixedState::parse(tls)?,
    })
}

fn classify_cseq_method(value: &str) -> CSeqMethod {
    let mut fields = value.split_ascii_whitespace();
    let (Some(sequence), Some(method), None) = (fields.next(), fields.next(), fields.next()) else {
        return CSeqMethod::Unknown;
    };
    if sequence.is_empty() || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return CSeqMethod::Unknown;
    }
    if method.eq_ignore_ascii_case("INVITE") {
        CSeqMethod::Invite
    } else if method.eq_ignore_ascii_case("ACK") {
        CSeqMethod::Ack
    } else if method.eq_ignore_ascii_case("BYE") {
        CSeqMethod::Bye
    } else if !method.is_empty()
        && method.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
                )
        })
    {
        CSeqMethod::Other
    } else {
        CSeqMethod::Unknown
    }
}

fn redacted_cseq_method(raw_message: &str) -> CSeqMethod {
    let mut values = raw_message
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("CSeq"))
        .map(|(_, value)| value);
    match (values.next(), values.next()) {
        (Some(value), None) => CSeqMethod::parse_marker(value).unwrap_or_default(),
        _ => CSeqMethod::Unknown,
    }
}

fn validate_request(request: PrivateRequest) -> anyhow::Result<ValidatedRequest> {
    let uri = &request.sip_uri;
    if request.schema_version != 1
        || !(1..=2048).contains(&uri.len())
        || !uri.bytes().all(|byte| byte.is_ascii_graphic())
        || uri.contains(['?', '#', '\r', '\n'])
    {
        bail!("private secure probe request violates its contract")
    }
    let authority = uri
        .strip_prefix("sips:")
        .and_then(|value| value.strip_suffix(";transport=tls"))
        .context("private secure probe destination is not exact SIPS/TLS")?;
    let (token, host_and_port) = authority
        .split_once('@')
        .context("private secure probe destination has no route token")?;
    if authority.matches('@').count() != 1
        || token.len() != 43
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("private secure probe destination token is invalid")
    }
    let host = host_and_port
        .strip_suffix(":5061")
        .context("private secure probe destination port is invalid")?;
    if !valid_hostname(host)
        || request.correlation_id.len() != 47
        || !request.correlation_id.starts_with("bf1_")
        || !request.correlation_id[4..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || request.media_advertised_ip.is_some_and(|ip| match ip {
            IpAddr::V4(ip) => {
                ip.is_unspecified()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || ip.is_multicast()
            }
            IpAddr::V6(ip) => ip.is_unspecified() || ip.is_loopback() || ip.is_multicast(),
        })
    {
        bail!("private secure probe request violates its contract")
    }

    let destination_host = host.to_owned();
    Ok(ValidatedRequest {
        sip_uri: request.sip_uri,
        correlation_id: request.correlation_id,
        destination_host,
        media_advertised_ip: request.media_advertised_ip,
    })
}

fn routed_media_ip(host: &str) -> anyhow::Result<IpAddr> {
    let destinations = (host, 5061_u16)
        .to_socket_addrs()
        .context("resolving secure probe destination")?;
    for destination in destinations {
        let bind = match destination {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind).context("opening secure probe route")?;
        if socket.connect(destination).is_err() {
            continue;
        }
        let local_ip = socket
            .local_addr()
            .context("reading secure probe route")?
            .ip();
        if !local_ip.is_unspecified() {
            return Ok(local_ip);
        }
    }
    bail!("secure probe destination has no route")
}

impl WireEvidence {
    fn failure_summary(&self) -> FailureWireSummary {
        FailureWireSummary {
            inbound_200: self.inbound_200,
            outbound_ack: self.outbound_ack,
            contact: self.contact,
        }
    }

    fn observe_contact(&mut self, observed: ContactEvidence) {
        if self.contact_observed && self.contact != observed {
            self.contact = ContactEvidence::redacted();
        } else {
            self.contact = observed;
        }
        self.contact_observed = true;
    }

    fn observe_dialog_session(&mut self, observed: Option<&CallId>) -> bool {
        let Some(observed) = observed else {
            return true;
        };
        match &self.dialog_session {
            None => {
                self.dialog_session = Some(observed.clone());
                true
            }
            Some(expected) if expected == observed => true,
            Some(_) => {
                self.dialog_session_conflict = true;
                false
            }
        }
    }

    fn success_contract_satisfied(&self) -> bool {
        self.invite_count == 1
            && self.correlation_header_count == Some(1)
            && !self.header_contract_failed
            && self.outbound_invite_tls
            && self.safe_trace
            && self.inbound_200
            && self.inbound_200_tls
            && self.outbound_ack
            && self.outbound_ack_tls
            && !self.dialog_session_conflict
            && self.contact.host == ContactHost::Dns
            && self.contact.sips == FixedState::Yes
            && self.contact.tls == FixedState::Yes
    }
}

fn observe_wire(trace: &SipTrace, evidence: &mut WireEvidence) {
    if trace.direction == SipTraceDirection::Outbound && trace.start_line.starts_with("INVITE ") {
        let same_dialog = evidence.observe_dialog_session(trace.session_id.as_ref());
        evidence.invite_count += 1;
        evidence.header_contract_failed |= !same_dialog;
        let count = trace
            .raw_message
            .lines()
            .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
            .filter(|name| name.eq_ignore_ascii_case(CORRELATION_HEADER))
            .count();
        evidence.header_contract_failed |= count != 1;
        evidence.correlation_header_count.get_or_insert(count);
        if evidence.correlation_header_count != Some(count) {
            evidence.header_contract_failed = true;
        }
        evidence.outbound_invite_tls = trace.transport.eq_ignore_ascii_case("tls");
        evidence.safe_trace |= trace.redacted;
        return;
    }
    if trace.direction == SipTraceDirection::Inbound
        && trace.start_line.starts_with("SIP/2.0 200 ")
        && redacted_cseq_method(&trace.raw_message) == CSeqMethod::Invite
    {
        if !evidence.observe_dialog_session(trace.session_id.as_ref()) {
            return;
        }
        let tls = trace.transport.eq_ignore_ascii_case("tls");
        evidence.inbound_200_tls = if evidence.inbound_200 {
            evidence.inbound_200_tls && tls
        } else {
            tls
        };
        evidence.inbound_200 = true;
        let contacts = trace
            .raw_message
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(name, _)| name.trim().eq_ignore_ascii_case("Contact"))
            .map(|(_, value)| parse_contact_marker(value).unwrap_or_else(ContactEvidence::redacted))
            .collect::<Vec<_>>();
        let contact = match contacts.as_slice() {
            [] => ContactEvidence::default(),
            [contact] => *contact,
            _ => ContactEvidence::redacted(),
        };
        evidence.observe_contact(contact);
        return;
    }
    if trace.direction == SipTraceDirection::Outbound && trace.start_line.starts_with("ACK ") {
        if !evidence.observe_dialog_session(trace.session_id.as_ref()) {
            return;
        }
        let tls = trace.transport.eq_ignore_ascii_case("tls");
        evidence.outbound_ack_tls = if evidence.outbound_ack {
            evidence.outbound_ack_tls && tls
        } else {
            tls
        };
        evidence.outbound_ack = true;
    }
}

fn tone_frame(frequency: f32, phase: &mut f32) -> Vec<i16> {
    let step = 2.0 * std::f32::consts::PI * frequency / 8_000.0;
    (0..FRAME_SAMPLES)
        .map(|_| {
            let sample = phase.sin() * 0.25 * f32::from(i16::MAX);
            *phase = (*phase + step) % (2.0 * std::f32::consts::PI);
            sample as i16
        })
        .collect()
}

fn dual_tone_frame(
    low_frequency: f32,
    high_frequency: f32,
    low_phase: &mut f32,
    high_phase: &mut f32,
) -> Vec<i16> {
    let low_step = 2.0 * std::f32::consts::PI * low_frequency / 8_000.0;
    let high_step = 2.0 * std::f32::consts::PI * high_frequency / 8_000.0;
    (0..FRAME_SAMPLES)
        .map(|_| {
            let sample = (low_phase.sin() + high_phase.sin()) * 0.125 * f32::from(i16::MAX);
            *low_phase = (*low_phase + low_step) % (2.0 * std::f32::consts::PI);
            *high_phase = (*high_phase + high_step) % (2.0 * std::f32::consts::PI);
            sample as i16
        })
        .collect()
}

async fn send_marker(sender: &rvoip_sip::AudioSender) -> anyhow::Result<usize> {
    let mut phase = 0.0;
    let mut timestamp = 0_u32;
    for _ in 0..MARKER_BURSTS {
        for _ in 0..MARKER_FRAMES_PER_BURST {
            sender
                .send(AudioFrame::new(
                    tone_frame(MARKER_FREQUENCY, &mut phase),
                    8_000,
                    1,
                    timestamp,
                ))
                .await
                .context("sending secure probe marker")?;
            timestamp = timestamp.wrapping_add(FRAME_SAMPLES as u32);
            tokio::time::sleep(FRAME_DURATION).await;
        }
        for _ in 0..MARKER_SILENCE_FRAMES_PER_BURST {
            sender
                .send(AudioFrame::new(vec![0; FRAME_SAMPLES], 8_000, 1, timestamp))
                .await
                .context("sending secure probe marker spacing")?;
            timestamp = timestamp.wrapping_add(FRAME_SAMPLES as u32);
            tokio::time::sleep(FRAME_DURATION).await;
        }
    }
    Ok(MARKER_FRAMES)
}

async fn send_in_band_dtmf(sender: &rvoip_sip::AudioSender) -> anyhow::Result<usize> {
    let mut low_phase = 0.0;
    let mut high_phase = 0.0;
    let mut timestamp = (MARKER_TOTAL_FRAMES * FRAME_SAMPLES) as u32;
    for _ in 0..DTMF_FRAMES {
        sender
            .send(AudioFrame::new(
                dual_tone_frame(
                    DTMF_LOW_FREQUENCY,
                    DTMF_HIGH_FREQUENCY,
                    &mut low_phase,
                    &mut high_phase,
                ),
                8_000,
                1,
                timestamp,
            ))
            .await
            .context("sending secure probe in-band DTMF")?;
        timestamp = timestamp.wrapping_add(FRAME_SAMPLES as u32);
        tokio::time::sleep(FRAME_DURATION).await;
    }
    for _ in 0..DTMF_TRAILING_SILENCE_FRAMES {
        sender
            .send(AudioFrame::new(vec![0; FRAME_SAMPLES], 8_000, 1, timestamp))
            .await
            .context("sending secure probe DTMF spacing")?;
        timestamp = timestamp.wrapping_add(FRAME_SAMPLES as u32);
        tokio::time::sleep(FRAME_DURATION).await;
    }
    Ok(DTMF_FRAMES)
}

fn success_observation(send_dtmf: bool, marker_frames: usize, wire: &WireEvidence) -> Observation {
    Observation {
        schema_version: 1,
        producer: PRODUCER,
        signaling: SignalingObservation {
            scheme: "sips",
            transport: "tls",
            invite_count: 1,
            correlation_header_count: 1,
            answered: true,
            inbound_200: wire.inbound_200,
            outbound_ack: wire.outbound_ack,
            contact_host: wire.contact.host.as_str(),
            contact_sips: wire.contact.sips == FixedState::Yes,
            contact_tls: wire.contact.tls == FixedState::Yes,
            trace_redacted: true,
        },
        media: MediaObservation {
            profile: "RTP/SAVP",
            keying: "SDES-SRTP",
            contexts_installed: true,
            audio_opened: true,
            marker_frames_sent: marker_frames,
            codec: "PCMU",
            dtmf_requested: send_dtmf,
            in_band_dtmf_frames_sent: if send_dtmf { DTMF_FRAMES } else { 0 },
            rfc4733_dtmf_sent: send_dtmf,
        },
        hangup: HangupObservation {
            local_bye_completed: true,
            cleanup_observed: true,
        },
        redacted: true,
    }
}

fn write_observation(path: &Path, observation: &Observation) -> anyhow::Result<()> {
    let temporary = path.with_extension("json.tmp");
    if temporary.exists() {
        bail!("secure probe temporary output already exists")
    }
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .context("creating secure probe output")?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, observation)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    drop(writer);
    fs::rename(&temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn secure_config(args: &Args, media_ip: IpAddr) -> Config {
    let mut config = Config::on(
        "bridgefu-direct-secure-probe",
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        args.sip_port,
    )
    .with_server_capacity(1)
    .with_media_port_capacity(args.media_port_start, 32);
    config.offered_codecs = vec![0, 101];
    config.strict_codec_matching = true;
    config.offer_srtp = true;
    config.srtp_required = true;
    config.sip_tls_mode = SipTlsMode::ClientOnly;
    // rvoip's reachable-contact posture deliberately refuses ClientOnly TLS
    // without an explicit external Contact. The peer reuses the established
    // TLS dialog flow, but the initial INVITE still needs a concrete SIPS
    // Contact rather than the unspecified bind address.
    config.contact_uri = Some(format!(
        "sips:bridgefu-direct-secure-probe@{media_ip}:{};transport=tls",
        args.sip_port
    ));
    config.media_public_addr = Some(SocketAddr::new(media_ip, 0));
    config.active_call_no_media_timeout_secs = args.timeout.as_secs();
    config.active_call_media_idle_timeout_secs = args.timeout.as_secs();
    config.setup_teardown_timeout_secs = args.timeout.as_secs();
    config.sip_trace = SipTraceConfig::enabled();
    config.trace_redaction = Some(Arc::new(ProbeTraceRedactor));
    config
}

async fn run(args: Args, request: ValidatedRequest) -> anyhow::Result<()> {
    let media_ip = match request.media_advertised_ip {
        Some(ip) => ip,
        None => routed_media_ip(&request.destination_host)?,
    };
    let config = secure_config(&args, media_ip);
    config.validate().map_err(anyhow::Error::msg)?;

    let wire = Arc::new(Mutex::new(WireEvidence::default()));
    let peer = CallbackPeer::builder(config)
        .on_incoming(|_| async move {
            CallHandlerDecision::Reject {
                status: 486,
                reason: "Secure probe does not accept inbound calls".into(),
            }
        })
        .on_sip_trace({
            let wire = Arc::clone(&wire);
            move |trace| {
                let wire = Arc::clone(&wire);
                async move {
                    let mut evidence = wire.lock().await;
                    observe_wire(&trace, &mut evidence);
                    Ok(())
                }
            }
        })
        .build()
        .await
        .context("building secure probe")?;
    let control = peer.control();
    let shutdown = peer.shutdown_handle();
    let peer_task = tokio::spawn(peer.run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    let call_result = async {
        let call_id = control
            .invite(request.sip_uri)
            .with_raw_header(
                HeaderName::Other(CORRELATION_HEADER.to_owned()),
                request.correlation_id,
            )
            .context("staging secure probe correlation")?
            .send()
            .await
            .context("sending secure probe INVITE")?;
        let handle = control.coordinator().session(&call_id);
        let handle = handle
            .wait_for_answered(Some(args.timeout))
            .await
            .context("secure probe was not answered")?;
        let security = handle
            .wait_for_media_security(Some(Duration::from_secs(10)))
            .await
            .context("secure media did not converge")?;
        if security.profile != MediaSecurityProfile::RtpSavp || !security.contexts_installed {
            bail!("secure media contexts were not installed")
        }
        let audio = handle.audio().await.context("opening secure probe audio")?;
        let (sender, _receiver) = audio.split();
        let marker_frames = send_marker(&sender).await?;
        if args.send_dtmf {
            let frames = send_in_band_dtmf(&sender).await?;
            if frames != DTMF_FRAMES {
                bail!("secure probe DTMF frame count is invalid")
            }
            handle
                .send_dtmf('5')
                .await
                .context("sending secure probe RFC4733 DTMF")?;
        }
        handle
            .hangup_and_wait(Some(Duration::from_secs(10)))
            .await
            .context("secure probe BYE did not complete")?;
        Ok::<usize, anyhow::Error>(marker_frames)
    }
    .await;

    let marker_frames = match call_result {
        Ok(marker_frames) => marker_frames,
        Err(error) => {
            // Trace hooks are dispatched asynchronously. Give an
            // already-received final response or attempted ACK one bounded
            // turn to reach the fixed evidence accumulator before shutting
            // down the peer.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let summary = wire.lock().await.failure_summary();
            shutdown.shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(5), peer_task).await;
            return Err(error.context(summary));
        }
    };

    let wire = wire.lock().await;
    let summary = wire.failure_summary();
    if !wire.success_contract_satisfied() {
        drop(wire);
        shutdown.shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(5), peer_task).await;
        return Err(anyhow::anyhow!("secure probe wire contract failed").context(summary));
    }
    let observation = success_observation(args.send_dtmf, marker_frames, &wire);
    drop(wire);
    shutdown.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(5), peer_task).await;
    write_observation(&args.output, &observation).map_err(|error| error.context(summary))
}

fn failure_phase(error: &anyhow::Error) -> (&'static str, Option<u16>) {
    let messages = error.chain().map(ToString::to_string).collect::<Vec<_>>();
    let contains = |needle: &str| messages.iter().any(|message| message.contains(needle));
    let phase = if contains("building secure probe") {
        "build"
    } else if contains("staging secure probe correlation")
        || contains("sending secure probe INVITE")
    {
        "invite"
    } else if contains("secure probe was not answered") {
        "answer"
    } else if contains("secure media did not converge")
        || contains("secure media contexts were not installed")
    {
        "media_security"
    } else if contains("opening secure probe audio") {
        "audio"
    } else if contains("secure probe marker") {
        "marker"
    } else if contains("secure probe in-band DTMF")
        || contains("secure probe RFC4733 DTMF")
        || contains("secure probe DTMF frame count")
    {
        "dtmf"
    } else if contains("secure probe BYE") {
        "hangup"
    } else if contains("secure probe wire contract") {
        "wire"
    } else if contains("secure probe output") || contains("secure probe temporary output") {
        "output"
    } else {
        "setup"
    };
    let status = messages.iter().find_map(|message| {
        let suffix = message.split("call failed before answer: ").nth(1)?;
        let encoded = suffix.as_bytes().get(..3)?;
        if encoded.iter().all(u8::is_ascii_digit) {
            let status = suffix[..3].parse::<u16>().ok()?;
            (100..=699).contains(&status).then_some(status)
        } else {
            None
        }
    });
    (phase, status)
}

fn failure_wire_summary(error: &anyhow::Error) -> FailureWireSummary {
    error
        .downcast_ref::<FailureWireSummary>()
        .copied()
        .unwrap_or_default()
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
        Ok(args) => match read_request().and_then(validate_request) {
            Ok(request) => run(args, request).await,
            Err(error) => Err(error),
        },
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        let (phase, status) = failure_phase(&error);
        let status = status.map_or_else(|| "none".to_owned(), |status| status.to_string());
        let wire = failure_wire_summary(&error);
        eprintln!("Direct secure probe failed phase={phase} status={status} {wire}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str, correlation: &str) -> PrivateRequest {
        PrivateRequest {
            schema_version: 1,
            sip_uri: uri.to_owned(),
            correlation_id: correlation.to_owned(),
            media_advertised_ip: Some("10.0.0.7".parse().expect("IP")),
        }
    }

    fn valid_uri() -> String {
        format!(
            "sips:{}@bridgefu.example.test:5061;transport=tls",
            "a".repeat(43)
        )
    }

    fn wire_trace(
        direction: SipTraceDirection,
        transport: &str,
        start_line: &str,
        raw_message: &str,
        session_id: Option<&str>,
    ) -> SipTrace {
        SipTrace {
            direction,
            transport: transport.to_owned(),
            local_addr: "private-local-ip-canary".into(),
            remote_addr: "private-remote-ip-canary".into(),
            timestamp_unix_millis: 1,
            start_line: start_line.to_owned(),
            sip_call_id: None,
            session_id: session_id.map(CallId::from),
            raw_message: raw_message.to_owned(),
            original_len: raw_message.len(),
            truncated: false,
            redacted: true,
        }
    }

    fn observe_dialog_with_transports(
        evidence: &mut WireEvidence,
        invite_transport: &str,
        response_transport: &str,
        ack_transport: &str,
    ) {
        let session = Some("private-session-canary");
        observe_wire(
            &wire_trace(
                SipTraceDirection::Outbound,
                invite_transport,
                "INVITE <redacted-request-uri> SIP/2.0",
                "INVITE <redacted-request-uri> SIP/2.0\r\nX-Correlation-Id: <redacted>\r\n\r\n",
                session,
            ),
            evidence,
        );
        observe_wire(
            &wire_trace(
                SipTraceDirection::Inbound,
                response_transport,
                "SIP/2.0 200 <redacted-reason>",
                concat!(
                    "SIP/2.0 200 <redacted-reason>\r\n",
                    "CSeq: <bridgefu-probe-cseq;method=invite>\r\n",
                    "Contact: <bridgefu-probe-contact;host=dns;sips=yes;tls=yes>\r\n",
                    "\r\n<redacted body>"
                ),
                session,
            ),
            evidence,
        );
        observe_wire(
            &wire_trace(
                SipTraceDirection::Outbound,
                ack_transport,
                "ACK <redacted-request-uri> SIP/2.0",
                concat!(
                    "ACK <redacted-request-uri> SIP/2.0\r\n",
                    "CSeq: <bridgefu-probe-cseq;method=ack>\r\n\r\n"
                ),
                session,
            ),
            evidence,
        );
    }

    #[test]
    fn failure_summary_is_closed_and_retains_only_a_sip_status() {
        let error = anyhow::anyhow!(
            "call failed before answer: 488 reason-with-private-value bf1_{}",
            "x".repeat(43)
        )
        .context("secure probe was not answered");
        assert_eq!(failure_phase(&error), ("answer", Some(488)));
        let setup = anyhow::anyhow!("private-value").context("building secure probe");
        assert_eq!(failure_phase(&setup), ("build", None));
        assert_eq!(failure_wire_summary(&setup), FailureWireSummary::default());

        let evidence = FailureWireSummary {
            inbound_200: true,
            outbound_ack: false,
            contact: ContactEvidence {
                host: ContactHost::Ipv4,
                sips: FixedState::Yes,
                tls: FixedState::Yes,
            },
        };
        let evidenced = anyhow::anyhow!("private-value").context(evidence);
        assert_eq!(failure_wire_summary(&evidenced), evidence);
        assert_eq!(
            evidence.to_string(),
            "inbound_200=yes outbound_ack=no contact=ipv4 contact_sips=yes contact_tls=yes"
        );
    }

    fn valid_correlation() -> String {
        format!("bf1_{}", "b".repeat(43))
    }

    #[test]
    fn private_request_accepts_only_exact_secure_shape() {
        assert!(validate_request(request(&valid_uri(), &valid_correlation())).is_ok());
        for invalid in [
            valid_uri().replacen("sips:", "sip:", 1),
            valid_uri().replace(":5061", ":5060"),
            format!("{}?X-Extra=private", valid_uri()),
            valid_uri().replace(";transport=tls", ";transport=udp"),
            "sips:short@bridgefu.example.test:5061;transport=tls".to_owned(),
            format!("sips:{}@192.0.2.8:5061;transport=tls", "a".repeat(43)),
        ] {
            assert!(validate_request(request(&invalid, &valid_correlation())).is_err());
        }
    }

    #[test]
    fn client_only_tls_config_has_an_explicit_secure_contact() {
        let args = Args {
            output: PathBuf::from("/tmp/bridgefu-direct-secure-probe-test.json"),
            sip_port: 5077,
            media_port_start: 41_000,
            timeout: Duration::from_secs(90),
            send_dtmf: true,
        };
        let config = secure_config(&args, "10.0.0.7".parse().expect("IP"));

        assert_eq!(
            config.contact_uri.as_deref(),
            Some("sips:bridgefu-direct-secure-probe@10.0.0.7:5077;transport=tls")
        );
        assert!(config.trace_redaction.is_some());
        config.validate().expect("secure client configuration");
    }

    #[test]
    fn private_request_rejects_header_and_correlation_injection() {
        for invalid in [
            "bf1_short".to_owned(),
            format!("bf1_{}\r\nX-Injected:private", "b".repeat(43)),
            format!("bf1_{}", "/".repeat(43)),
        ] {
            assert!(validate_request(request(&valid_uri(), &invalid)).is_err());
        }
    }

    #[test]
    fn sensitive_values_are_unavailable_as_process_arguments() {
        let output = env::temp_dir().join("bridgefu-direct-probe-argument-test.json");
        let base = vec![
            "--request-stdin".to_owned(),
            "--output".to_owned(),
            output.display().to_string(),
        ];
        assert!(parse_args(base.clone()).is_ok());
        for option in ["--sip-uri", "--correlation-id", "--header", "--public-ip"] {
            let mut invalid = base.clone();
            invalid.push(option.to_owned());
            invalid.push("private-canary".to_owned());
            let error = parse_args(invalid).expect_err("sensitive argument rejected");
            assert!(!error.to_string().contains("private-canary"));
        }
    }

    #[test]
    fn success_artifact_cannot_contain_private_inputs() {
        let uri_canary = "private-uri-canary";
        let token_canary = "private-token-canary";
        let correlation_canary = "private-correlation-canary";
        let header_canary = "private-header-canary";
        let ip_canary = "198.51.100.77";
        let wire = WireEvidence {
            inbound_200: true,
            outbound_ack: true,
            contact_observed: true,
            contact: ContactEvidence {
                host: ContactHost::Dns,
                sips: FixedState::Yes,
                tls: FixedState::Yes,
            },
            ..WireEvidence::default()
        };
        let encoded = serde_json::to_string(&success_observation(true, MARKER_FRAMES, &wire))
            .expect("serialize");
        for private in [
            uri_canary,
            token_canary,
            correlation_canary,
            header_canary,
            ip_canary,
        ] {
            assert!(!encoded.contains(private));
        }
        assert!(!encoded.contains(CORRELATION_HEADER));
        assert!(encoded.contains("SDES-SRTP"));
        assert!(encoded.contains("RTP/SAVP"));
        assert!(encoded.contains("\"inbound_200\":true"));
        assert!(encoded.contains("\"outbound_ack\":true"));
        assert!(encoded.contains("\"contact_host\":\"dns\""));
        assert!(encoded.contains("\"contact_sips\":true"));
        assert!(encoded.contains("\"contact_tls\":true"));
    }

    #[test]
    fn wire_observer_retains_only_counts_and_fixed_classifications() {
        let mut evidence = WireEvidence::default();
        observe_wire(
            &SipTrace {
                direction: SipTraceDirection::Outbound,
                transport: "TLS".into(),
                local_addr: "private-local-ip-canary".into(),
                remote_addr: "private-remote-ip-canary".into(),
                timestamp_unix_millis: 1,
                start_line: "INVITE <redacted-request-uri> SIP/2.0".into(),
                sip_call_id: None,
                session_id: None,
                raw_message:
                    "INVITE <redacted-request-uri> SIP/2.0\r\nX-Correlation-Id: <redacted>\r\n\r\n"
                        .into(),
                original_len: 200,
                truncated: false,
                redacted: true,
            },
            &mut evidence,
        );
        assert_eq!(evidence.invite_count, 1);
        assert_eq!(evidence.correlation_header_count, Some(1));
        assert!(evidence.outbound_invite_tls);
        assert!(evidence.safe_trace);
        assert!(!format!("{evidence:?}").contains("private"));

        observe_wire(
            &SipTrace {
                direction: SipTraceDirection::Inbound,
                transport: "TLS".into(),
                local_addr: "private-local-ip-canary".into(),
                remote_addr: "private-remote-ip-canary".into(),
                timestamp_unix_millis: 2,
                start_line: "SIP/2.0 200 <redacted-reason>".into(),
                sip_call_id: None,
                session_id: None,
                raw_message: concat!(
                    "SIP/2.0 200 <redacted-reason>\r\n",
                    "CSeq: <bridgefu-probe-cseq;method=invite>\r\n",
                    "Contact: <bridgefu-probe-contact;host=ipv4;sips=yes;tls=yes>\r\n",
                    "\r\n<redacted body>"
                )
                .into(),
                original_len: 400,
                truncated: false,
                redacted: true,
            },
            &mut evidence,
        );
        observe_wire(
            &SipTrace {
                direction: SipTraceDirection::Outbound,
                transport: "TLS".into(),
                local_addr: "private-local-ip-canary".into(),
                remote_addr: "private-remote-ip-canary".into(),
                timestamp_unix_millis: 3,
                start_line: "ACK <redacted-request-uri> SIP/2.0".into(),
                sip_call_id: None,
                session_id: None,
                raw_message: "ACK <redacted-request-uri> SIP/2.0\r\n\r\n".into(),
                original_len: 200,
                truncated: false,
                redacted: true,
            },
            &mut evidence,
        );
        assert_eq!(
            evidence.failure_summary(),
            FailureWireSummary {
                inbound_200: true,
                outbound_ack: true,
                contact: ContactEvidence {
                    host: ContactHost::Ipv4,
                    sips: FixedState::Yes,
                    tls: FixedState::Yes,
                },
            }
        );
        assert!(evidence.inbound_200_tls);
        assert!(evidence.outbound_ack_tls);
        assert!(!format!("{evidence:?}").contains("private"));
    }

    #[test]
    fn bye_200_cannot_replace_the_invite_200_contact() {
        let mut evidence = WireEvidence::default();
        observe_dialog_with_transports(&mut evidence, "TLS", "TLS", "TLS");
        assert!(evidence.success_contract_satisfied());
        let contact = evidence.contact;

        observe_wire(
            &wire_trace(
                SipTraceDirection::Inbound,
                "TLS",
                "SIP/2.0 200 <redacted-reason>",
                concat!(
                    "SIP/2.0 200 <redacted-reason>\r\n",
                    "CSeq: <bridgefu-probe-cseq;method=bye>\r\n\r\n"
                ),
                Some("private-session-canary"),
            ),
            &mut evidence,
        );

        assert_eq!(evidence.contact, contact);
        assert!(evidence.inbound_200_tls);
        assert!(evidence.success_contract_satisfied());
    }

    #[test]
    fn wire_success_requires_tls_on_each_dialog_message() {
        for transports in [
            ("TCP", "TLS", "TLS"),
            ("TLS", "TCP", "TLS"),
            ("TLS", "TLS", "TCP"),
        ] {
            let mut evidence = WireEvidence::default();
            observe_dialog_with_transports(&mut evidence, transports.0, transports.1, transports.2);
            assert!(!evidence.success_contract_satisfied(), "{transports:?}");
        }
    }

    #[test]
    fn wire_success_rejects_mixed_sessions_without_exposing_them() {
        let mut evidence = WireEvidence::default();
        observe_dialog_with_transports(&mut evidence, "TLS", "TLS", "TLS");
        assert!(evidence.success_contract_satisfied());

        observe_wire(
            &wire_trace(
                SipTraceDirection::Outbound,
                "TLS",
                "ACK <redacted-request-uri> SIP/2.0",
                "ACK <redacted-request-uri> SIP/2.0\r\n\r\n",
                Some("private-conflicting-session-canary"),
            ),
            &mut evidence,
        );

        assert!(evidence.dialog_session_conflict);
        assert!(!evidence.success_contract_satisfied());
        let debug = format!("{evidence:?}");
        assert!(!debug.contains("private-session-canary"));
        assert!(!debug.contains("private-conflicting-session-canary"));
    }

    #[test]
    fn wire_success_requires_200_ack_and_secure_dns_contact() {
        let passing = || WireEvidence {
            invite_count: 1,
            correlation_header_count: Some(1),
            outbound_invite_tls: true,
            safe_trace: true,
            inbound_200: true,
            inbound_200_tls: true,
            outbound_ack: true,
            outbound_ack_tls: true,
            contact_observed: true,
            contact: ContactEvidence {
                host: ContactHost::Dns,
                sips: FixedState::Yes,
                tls: FixedState::Yes,
            },
            ..WireEvidence::default()
        };
        assert!(passing().success_contract_satisfied());

        let mut missing_200 = passing();
        missing_200.inbound_200 = false;
        assert!(!missing_200.success_contract_satisfied());
        let mut missing_ack = passing();
        missing_ack.outbound_ack = false;
        assert!(!missing_ack.success_contract_satisfied());
        let mut ip_contact = passing();
        ip_contact.contact.host = ContactHost::Ipv4;
        assert!(!ip_contact.success_contract_satisfied());
        let mut sip_contact = passing();
        sip_contact.contact.sips = FixedState::No;
        assert!(!sip_contact.success_contract_satisfied());
        let mut non_tls_contact = passing();
        non_tls_contact.contact.tls = FixedState::No;
        assert!(!non_tls_contact.success_contract_satisfied());
        let mut clear_200 = passing();
        clear_200.inbound_200_tls = false;
        assert!(!clear_200.success_contract_satisfied());
        let mut clear_ack = passing();
        clear_ack.outbound_ack_tls = false;
        assert!(!clear_ack.success_contract_satisfied());
    }

    #[test]
    fn cseq_trace_policy_emits_only_closed_method_classifications() {
        for (private, expected, classification) in [
            (
                "918273645 INVITE",
                "<bridgefu-probe-cseq;method=invite>",
                CSeqMethod::Invite,
            ),
            (
                "918273646 BYE",
                "<bridgefu-probe-cseq;method=bye>",
                CSeqMethod::Bye,
            ),
            (
                "918273647 INFO",
                "<bridgefu-probe-cseq;method=other>",
                CSeqMethod::Other,
            ),
            (
                "private-malformed-cseq-canary",
                "<bridgefu-probe-cseq;method=unknown>",
                CSeqMethod::Unknown,
            ),
        ] {
            let marker = match ProbeTraceRedactor.redact(&HeaderName::CSeq, private) {
                RedactionDecision::Redact(marker) => marker,
                decision => panic!("unexpected CSeq trace decision: {decision:?}"),
            };
            assert_eq!(marker, expected);
            assert_eq!(CSeqMethod::parse_marker(&marker), Some(classification));
            assert!(!marker.contains(private));
        }
    }

    #[test]
    fn contact_trace_policy_emits_only_fixed_classifications() {
        let private =
            "\"private-display-canary\" <sips:private-user@203.0.113.9:5061;transport=tls>";
        let marker = match ProbeTraceRedactor.redact(&HeaderName::Contact, private) {
            RedactionDecision::Redact(marker) => marker,
            decision => panic!("unexpected contact trace decision: {decision:?}"),
        };
        assert_eq!(
            marker,
            "<bridgefu-probe-contact;host=ipv4;sips=yes;tls=yes>"
        );
        assert!(!marker.contains("private"));
        assert!(!marker.contains("203.0.113.9"));
        assert_eq!(
            parse_contact_marker(&marker),
            Some(ContactEvidence {
                host: ContactHost::Ipv4,
                sips: FixedState::Yes,
                tls: FixedState::Yes,
            })
        );

        let dns = classify_contact("<sip:route@bridgefu.example.test:5060;transport=udp>");
        assert_eq!(dns.host, ContactHost::Dns);
        assert_eq!(dns.sips, FixedState::No);
        assert_eq!(dns.tls, FixedState::No);
        assert_eq!(
            ProbeTraceRedactor.redact(
                &HeaderName::Other("X-Private".to_owned()),
                "private-header-value-canary"
            ),
            RedactionDecision::Redact("<bridgefu-probe-redacted>".to_owned())
        );
    }

    #[test]
    fn deterministic_dtmf_frame_contains_both_frequencies() {
        let mut low_phase = 0.0;
        let mut high_phase = 0.0;
        let first = dual_tone_frame(
            DTMF_LOW_FREQUENCY,
            DTMF_HIGH_FREQUENCY,
            &mut low_phase,
            &mut high_phase,
        );
        assert_eq!(first.len(), FRAME_SAMPLES);
        assert!(first.iter().any(|sample| *sample != 0));
        let mut repeated_low = 0.0;
        let mut repeated_high = 0.0;
        assert_eq!(
            first,
            dual_tone_frame(
                DTMF_LOW_FREQUENCY,
                DTMF_HIGH_FREQUENCY,
                &mut repeated_low,
                &mut repeated_high,
            )
        );
    }

    #[test]
    fn marker_window_allows_connect_flow_and_agent_acceptance() {
        let duration = FRAME_DURATION * MARKER_TOTAL_FRAMES as u32;
        assert_eq!(MARKER_FRAMES, 320);
        assert!(duration >= Duration::from_secs(32));
        assert!(duration < Duration::from_secs(40));
    }

    #[test]
    fn manifest_and_lock_pin_exact_crates_io_rvoip_038() {
        let manifest = include_str!("../Cargo.toml");
        assert!(manifest.contains("rvoip-sip = { version = \"=0.3.8\", default-features = false }"));
        assert!(!manifest.contains("path ="));
        assert!(!manifest.contains("git ="));
        let lock = include_str!("../Cargo.lock");
        let package = lock
            .split_once("name = \"rvoip-sip\"")
            .expect("rvoip package")
            .1
            .split_once("[[package]]")
            .expect("next package")
            .0;
        assert!(package.contains("version = \"0.3.8\""));
        assert!(
            package.contains("source = \"registry+https://github.com/rust-lang/crates.io-index\"")
        );
    }
}
