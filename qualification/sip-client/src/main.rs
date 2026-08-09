//! A controlled SIP user agent for the Vapi -> Bridgefu -> Amazon Connect smoke.
//!
//! This binary calls Vapi's SIP ingress directly. It never asks Vapi's HTTP API
//! to originate a call. A separate controller creates the temporary Vapi SIP
//! phone-number resource and passes its public URI here.

use anyhow::{bail, Context};
use clap::Parser;
use rvoip_sip::api::headers::SipRequestOptions;
use rvoip_sip::{
    AudioFrame, CallHandlerDecision, CallbackPeer, Config, HeaderName, SipTrace, SipTraceConfig,
    SipTraceDirection,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const PRODUCER: &str = "bridgefu-vapi-sip-smoke@1";
const SAMPLE_RATE: u32 = 8_000;
const FRAME_SAMPLES: usize = 160;
const FRAME_DURATION: Duration = Duration::from_millis(20);
const SOURCE_MARKER_HZ: f32 = 997.0;
const AGENT_MARKER_HZ: f64 = 880.0;
const REQUIRED_AGENT_MARKERS: usize = 5;
const MAX_PROMPT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Parser)]
#[command(about = "Call Vapi over SIP and observe the Bridgefu Connect transfer")]
struct Args {
    #[arg(long)]
    sip_uri: String,
    /// Signed little-endian 16-bit, mono, 8 kHz PCM containing synthetic speech.
    #[arg(long)]
    prompt_pcm: PathBuf,
    /// Public IPv4 address advertised in SDP by the disposable Bridgefu host.
    #[arg(long)]
    public_ip: Ipv4Addr,
    #[arg(long)]
    execution_id: String,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 5076)]
    sip_port: u16,
    #[arg(long, default_value_t = 40_000)]
    media_port_start: u16,
    #[arg(long, default_value_t = 120)]
    timeout_seconds: u64,
}

#[derive(Default)]
struct WireEvidence {
    invite_count: usize,
    request_host_is_vapi: bool,
    transport: Option<String>,
}

#[derive(Default)]
struct ToneEdges {
    active: bool,
    last_edge_ms: Option<u64>,
    timestamps: Vec<u64>,
    frames: usize,
}

#[derive(Clone, Default)]
struct SendStats {
    prompt_frames: usize,
    marker_timestamps: Vec<u64>,
    marker_frames: usize,
}

#[derive(Serialize)]
struct Observation {
    schema_version: u8,
    producer: &'static str,
    producer_revision_sha256: String,
    execution_id: String,
    scenario_id: &'static str,
    observed_at: String,
    signaling: SignalingObservation,
    media: MediaObservation,
    hangup: HangupObservation,
    redacted: bool,
}

#[derive(Serialize)]
struct SignalingObservation {
    source: &'static str,
    target: &'static str,
    invite_sent: bool,
    answered: bool,
    transport: String,
}

#[derive(Serialize)]
struct MediaObservation {
    codec: &'static str,
    prompt_frames_sent: usize,
    source_marker_sent_at_ms: Vec<u64>,
    source_to_agent_marker_frames_sent: usize,
    agent_marker_observed_at_ms: Vec<u64>,
    agent_to_source_marker_frames: usize,
}

#[derive(Serialize)]
struct HangupObservation {
    local_bye_completed: bool,
    cleanup_observed: bool,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_vapi_sip_uri(value: &str) -> anyhow::Result<()> {
    let Some(remainder) = value.strip_prefix("sip:") else {
        bail!("qualification URI must use plain SIP into Vapi")
    };
    let Some((user, authority)) = remainder.split_once('@') else {
        bail!("qualification URI must contain a Vapi SIP user")
    };
    if !(8..=128).contains(&user.len())
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || authority != "sip.vapi.ai"
    {
        bail!("qualification URI must be an exact US Vapi SIP URI")
    }
    Ok(())
}

fn validate_args(args: &Args) -> anyhow::Result<()> {
    validate_vapi_sip_uri(&args.sip_uri)?;
    if !args.execution_id.starts_with("bfq-")
        || !(8..=32).contains(&args.execution_id.len())
        || !args
            .execution_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("execution ID is invalid")
    }
    if args.sip_port == 0
        || args.media_port_start < 1024
        || args.media_port_start > u16::MAX - 31
        || !(60..=300).contains(&args.timeout_seconds)
    {
        bail!("SIP client port or timeout is invalid")
    }
    if args.public_ip.is_private()
        || args.public_ip.is_loopback()
        || args.public_ip.is_link_local()
        || args.public_ip.is_unspecified()
        || args.public_ip.is_broadcast()
        || args.public_ip.is_documentation()
    {
        bail!("public media address must be a routable IPv4 address")
    }
    if args.output.exists() {
        bail!("observation output already exists")
    }
    Ok(())
}

fn read_prompt(path: &Path) -> anyhow::Result<Vec<i16>> {
    let metadata = fs::symlink_metadata(path).context("synthetic prompt is unavailable")?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() < 320
        || metadata.len() > MAX_PROMPT_BYTES
        || metadata.len() % 2 != 0
    {
        bail!("synthetic prompt must be bounded 16-bit PCM")
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    fs::File::open(path)
        .context("opening synthetic prompt")?
        .read_to_end(&mut bytes)
        .context("reading synthetic prompt")?;
    Ok(bytes
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect())
}

fn vapi_route_ip() -> anyhow::Result<IpAddr> {
    for destination in ("sip.vapi.ai", 5060)
        .to_socket_addrs()
        .context("resolving Vapi SIP ingress")?
    {
        let socket =
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("opening media route probe")?;
        if socket.connect(destination).is_ok() {
            let address = socket.local_addr().context("reading media route")?.ip();
            if !address.is_unspecified() {
                return Ok(address);
            }
        }
    }
    bail!("Vapi SIP ingress has no routable address")
}

fn tone_power(samples: &[i16], sample_rate: u32, frequency: f64) -> f64 {
    let coefficient = 2.0 * (2.0 * std::f64::consts::PI * frequency / f64::from(sample_rate)).cos();
    let mut previous = 0.0;
    let mut before_previous = 0.0;
    for sample in samples {
        let current =
            f64::from(*sample) / f64::from(i16::MAX) + coefficient * previous - before_previous;
        before_previous = previous;
        previous = current;
    }
    (previous * previous + before_previous * before_previous
        - coefficient * previous * before_previous)
        / (samples.len() as f64 * samples.len() as f64)
}

fn rms(samples: &[i16]) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    (samples
        .iter()
        .map(|sample| (f64::from(*sample) / f64::from(i16::MAX)).powi(2))
        .sum::<f64>()
        / samples.len() as f64)
        .sqrt()
}

impl ToneEdges {
    fn observe(&mut self, frame: &AudioFrame) {
        let agent = tone_power(&frame.samples, frame.sample_rate, AGENT_MARKER_HZ);
        let source = tone_power(
            &frame.samples,
            frame.sample_rate,
            f64::from(SOURCE_MARKER_HZ),
        );
        let present = frame.channels == 1
            && rms(&frame.samples) >= 0.01
            && agent >= 0.001
            && agent >= source * 8.0;
        if present {
            self.frames += 1;
            let current = now_ms();
            if !self.active
                && self
                    .last_edge_ms
                    .is_none_or(|previous| current.saturating_sub(previous) >= 500)
                && self.timestamps.len() < REQUIRED_AGENT_MARKERS
            {
                self.timestamps.push(current);
                self.last_edge_ms = Some(current);
            }
        }
        self.active = present;
    }
}

fn tone_frame(phase: &mut f32) -> Vec<i16> {
    let step = 2.0 * std::f32::consts::PI * SOURCE_MARKER_HZ / SAMPLE_RATE as f32;
    (0..FRAME_SAMPLES)
        .map(|_| {
            let sample = phase.sin() * 0.25 * f32::from(i16::MAX);
            *phase = (*phase + step) % (2.0 * std::f32::consts::PI);
            sample as i16
        })
        .collect()
}

async fn send_frame(
    sender: &rvoip_sip::AudioSender,
    samples: Vec<i16>,
    timestamp: &mut u32,
) -> anyhow::Result<()> {
    sender
        .send(AudioFrame::new(samples, SAMPLE_RATE, 1, *timestamp))
        .await
        .context("sending SIP smoke audio")?;
    *timestamp = timestamp.wrapping_add(FRAME_SAMPLES as u32);
    tokio::time::sleep(FRAME_DURATION).await;
    Ok(())
}

async fn send_media(
    sender: rvoip_sip::AudioSender,
    prompt: Vec<i16>,
    stats: Arc<Mutex<SendStats>>,
) -> anyhow::Result<()> {
    let mut timestamp = 0_u32;
    for _ in 0..150 {
        send_frame(&sender, vec![0; FRAME_SAMPLES], &mut timestamp).await?;
    }
    let mut prompt_frames = 0;
    for chunk in prompt.chunks(FRAME_SAMPLES) {
        let mut frame = vec![0; FRAME_SAMPLES];
        frame[..chunk.len()].copy_from_slice(chunk);
        send_frame(&sender, frame, &mut timestamp).await?;
        prompt_frames += 1;
    }
    stats.lock().await.prompt_frames = prompt_frames;
    let mut phase = 0.0;
    for _ in 0..90 {
        let marker_timestamp = now_ms();
        for _ in 0..5 {
            send_frame(&sender, tone_frame(&mut phase), &mut timestamp).await?;
        }
        {
            let mut current = stats.lock().await;
            current.marker_timestamps.push(marker_timestamp);
            current.marker_frames += 5;
        }
        for _ in 0..45 {
            send_frame(&sender, vec![0; FRAME_SAMPLES], &mut timestamp).await?;
        }
    }
    Ok(())
}

fn observe_wire(trace: &SipTrace, evidence: &mut WireEvidence) {
    if trace.direction != SipTraceDirection::Outbound || !trace.start_line.starts_with("INVITE ") {
        return;
    }
    evidence.invite_count += 1;
    evidence.request_host_is_vapi &= trace.start_line.contains("@sip.vapi.ai");
    if evidence.invite_count == 1 {
        evidence.request_host_is_vapi = trace.start_line.contains("@sip.vapi.ai");
    }
    evidence.transport = Some(trace.transport.to_ascii_lowercase());
}

fn write_observation(path: &Path, value: &Observation) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .context("observation requires a parent directory")?;
    fs::create_dir_all(parent).context("creating observation directory")?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let temporary = path.with_extension("json.tmp");
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .context("creating observation")?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    drop(writer);
    fs::rename(temporary, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

async fn run(args: Args) -> anyhow::Result<()> {
    validate_args(&args)?;
    let prompt = read_prompt(&args.prompt_pcm)?;
    let mut config = Config::on(
        "bridgefu-vapi-sip-smoke",
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        args.sip_port,
    )
    .with_server_capacity(1)
    .with_media_port_capacity(args.media_port_start, 32);
    config.offered_codecs = vec![0, 8, 101];
    config.strict_codec_matching = false;
    // Confirm the host has an outbound route to Vapi, then advertise its stack
    // Elastic IP so Vapi can return RTP through the stateful security group.
    let _ = vapi_route_ip()?;
    config.sip_advertised_addr = Some(SocketAddr::new(IpAddr::V4(args.public_ip), args.sip_port));
    config.media_public_addr = Some(SocketAddr::new(IpAddr::V4(args.public_ip), 0));
    config.active_call_no_media_timeout_secs = args.timeout_seconds;
    config.active_call_media_idle_timeout_secs = args.timeout_seconds;
    config.setup_teardown_timeout_secs = args.timeout_seconds;
    config.sip_trace = SipTraceConfig::enabled();
    config.validate().map_err(anyhow::Error::msg)?;

    let wire = Arc::new(Mutex::new(WireEvidence::default()));
    let peer = CallbackPeer::builder(config)
        .on_incoming(|_| async move {
            CallHandlerDecision::Reject {
                status: 486,
                reason: "SIP smoke source does not accept calls".into(),
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
        .context("building rvoip SIP client")?;
    let control = peer.control();
    let shutdown = peer.shutdown_handle();
    let peer_task = tokio::spawn(peer.run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    let call_id = control
        .invite(args.sip_uri.clone())
        .with_raw_header(
            HeaderName::Other("X-Bridgefu-Qualification".to_owned()),
            "vapi-sip-transfer".to_owned(),
        )
        .context("adding bounded qualification header")?
        .send()
        .await
        .context("sending SIP INVITE to Vapi")?;
    let handle = control
        .coordinator()
        .session(&call_id)
        .wait_for_answered(Some(Duration::from_secs(args.timeout_seconds)))
        .await
        .context("Vapi did not answer the SIP call")?;
    let audio = handle.audio().await.context("opening Vapi SIP audio")?;
    let (sender, mut receiver) = audio.split();

    let send_stats = Arc::new(Mutex::new(SendStats::default()));
    let send_task = tokio::spawn(send_media(sender, prompt, Arc::clone(&send_stats)));
    let receive_deadline = tokio::time::Instant::now() + Duration::from_secs(args.timeout_seconds);
    let mut agent_markers = ToneEdges::default();
    while tokio::time::Instant::now() < receive_deadline
        && agent_markers.timestamps.len() < REQUIRED_AGENT_MARKERS
    {
        let remaining = receive_deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining.min(Duration::from_secs(2)), receiver.recv()).await {
            Ok(Some(frame)) => agent_markers.observe(&frame),
            Ok(None) => break,
            Err(_) => {}
        }
    }
    if agent_markers.timestamps.len() < REQUIRED_AGENT_MARKERS
        || agent_markers.frames < REQUIRED_AGENT_MARKERS
    {
        send_task.abort();
        bail!("Connect agent audio marker was not received through Vapi and Bridgefu")
    }
    send_task.abort();
    match send_task.await {
        Ok(result) => result?,
        Err(error) if error.is_cancelled() => {}
        Err(error) => return Err(error).context("SIP media sender failed"),
    }
    let send_stats = send_stats.lock().await.clone();
    if send_stats.prompt_frames == 0 || send_stats.marker_frames < 5 {
        bail!("source audio was not sent before the return marker arrived")
    }
    handle
        .hangup_and_wait(Some(Duration::from_secs(10)))
        .await
        .context("SIP smoke BYE did not complete")?;
    let wire = wire.lock().await;
    if wire.invite_count != 1 || !wire.request_host_is_vapi {
        bail!("wire trace did not prove exactly one INVITE to Vapi")
    }
    let transport = wire.transport.clone().unwrap_or_else(|| "unknown".into());
    drop(wire);

    shutdown.shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(5), peer_task).await;
    write_observation(
        &args.output,
        &Observation {
            schema_version: 1,
            producer: PRODUCER,
            producer_revision_sha256: digest(include_bytes!("main.rs")),
            execution_id: args.execution_id,
            scenario_id: "vapi-sip-transfer",
            observed_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            signaling: SignalingObservation {
                source: "rvoip-sip-0.3.7",
                target: "sip.vapi.ai",
                invite_sent: true,
                answered: true,
                transport,
            },
            media: MediaObservation {
                codec: "pcmu-or-pcma",
                prompt_frames_sent: send_stats.prompt_frames,
                source_marker_sent_at_ms: send_stats.marker_timestamps,
                source_to_agent_marker_frames_sent: send_stats.marker_frames,
                agent_marker_observed_at_ms: agent_markers.timestamps,
                agent_to_source_marker_frames: agent_markers.frames,
            },
            hangup: HangupObservation {
                local_bye_completed: true,
                cleanup_observed: true,
            },
            redacted: true,
        },
    )?;
    println!("{}", args.output.display());
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Args::parse()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_us_vapi_sip_host() {
        assert!(validate_vapi_sip_uri("sip:bfq_12345678@sip.vapi.ai").is_ok());
        assert!(validate_vapi_sip_uri("sip:bfq_12345678@example.com").is_err());
        assert!(validate_vapi_sip_uri("https://sip.vapi.ai").is_err());
    }

    #[test]
    fn marker_detector_rejects_the_source_frequency() {
        let mut phase = 0.0;
        let frame = AudioFrame::new(tone_frame(&mut phase), SAMPLE_RATE, 1, 0);
        let mut detector = ToneEdges::default();
        detector.observe(&frame);
        assert!(detector.timestamps.is_empty());
    }
}
