#!/usr/bin/env node
/**
 * Controlled Bridgefu WebRTC SDK source for the Bridgefu AWS Connect release.
 *
 * The exact immutable demo-site bundle is served either by the deployed
 * CloudFront distribution or, for a non-deployed qualification, on 127.0.0.1.
 * A one-use Bridgefu route attachment is exchanged through a mode-0600 input.
 * The browser never receives a Vapi key, Bridgefu control bearer, or handoff
 * authority. Retained output contains only hashes, counts, timestamps, and
 * fixed labels.
 */

import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const PRODUCER = "bridgefu-webrtc-browser-playwright@1";
const SDK_NAME = "@bridgefu/webrtc-browser";
const SDK_VERSION = "0.1.0";
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");
const require = createRequire(join(ROOT, "qualification/package.json"));
process.env.PLAYWRIGHT_BROWSERS_PATH ??= "0";
const { chromium } = require("playwright");

const MAX_JSON_BYTES = 1024 * 1024;
const MAX_SITE_FILE_BYTES = 2 * 1024 * 1024;
const ROUTE_INPUT_KEYS = new Set(["schema_version", "route_attachment", "route_binding"]);
const SESSION_KEYS = new Set([
  "schema_version",
  "execution_id",
  "recipe",
  "release_id",
  "source_tree_sha256",
  "image",
  "session_id",
  "scenario_id",
  "hangup_origin",
  "security",
  "codec",
  "network_profile",
  "network_contract",
  "started_at",
  "started_epoch_ms",
  "correlation_id",
  "correlation_fingerprint",
  "source_call_id",
  "vapi_call_id",
  "source_org_id",
  "source_call_fingerprint",
  "sip_uri",
  "sip_header",
  "expected_context",
  "session_hmac",
]);
const SAMPLE_RATE = 48_000;
const PROBE_SECONDS = 120;
const SOURCE_MARKER_HZ = 997;
const AGENT_MARKER_HZ = 880;
const PROBE_INITIAL_SILENCE_MS = 10_000;
const PROBE_CYCLE_MS = 10_000;
const PROBE_PULSES_PER_CYCLE = 5;
const PROBE_PULSE_MS = 100;
const DTMF_START_MS = 6_000;
const DTMF_DURATION_MS = 350;
// The fake microphone starts when Bridgefu opens the browser capture device.
// Give its spoken trigger an exact five-second silence prefix, while keeping it
// well inside Vapi's 30-second silence window. Media probes begin afterward.
const PROMPT_START_MS = 5_000;
const PROMPT_SAMPLE_RATE = 8_000;
const STARTUP_ERROR_TYPES = new Set([
  "invalid-attachment",
  "invalid-credential",
  "invalid-state",
  "media-unavailable",
  "signaling-failed",
  "protocol-error",
  "timeout",
  "data-channel-unavailable",
  "dtmf-unavailable",
  "unknown",
]);
const PEER_CONNECTION_STATES = new Set([
  "new", "connecting", "connected", "disconnected", "failed", "closed",
]);
const ICE_CONNECTION_STATES = new Set([
  "new", "checking", "connected", "completed", "disconnected", "failed", "closed",
]);
const ICE_GATHERING_STATES = new Set(["new", "gathering", "complete"]);
const SIGNALING_STATES = new Set([
  "stable", "have-local-offer", "have-remote-offer", "have-local-pranswer",
  "have-remote-pranswer", "closed",
]);
const QUALIFICATION_STUN_URLS = new Set([
  "stun:stun.kinesisvideo.us-west-2.amazonaws.com:443",
  "stun:stun.kinesisvideo.us-east-1.amazonaws.com:443",
]);

class HarnessError extends Error {}

function fail(message) {
  throw new HarnessError(message);
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function sha256File(path) {
  return sha256Bytes(readFileSync(path));
}

function exactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === expected.size &&
    Object.keys(value).every((key) => expected.has(key))
  );
}

function validNetworkContract(profile, contract) {
  if (!contract || typeof contract !== "object" || Array.isArray(contract)) return false;
  if (
    Object.keys(contract).sort().join(",") !==
    "delay_ms,jitter_ms,loss_percent,reorder_percent"
  ) return false;
  const expected =
    profile === "baseline"
      ? [0, 0, 0, 0]
      : profile === "moderate-wan"
        ? [80, 20, 1, 0.1]
        : null;
  return (
    expected !== null &&
    [
      contract.delay_ms,
      contract.jitter_ms,
      contract.loss_percent,
      contract.reorder_percent,
    ].every((value, index) => value === expected[index])
  );
}

function privateRegularFile(path, maximum = MAX_JSON_BYTES) {
  const details = lstatSync(path);
  if (!details.isFile() || details.isSymbolicLink()) fail("private input is not a regular file");
  if (details.size <= 0 || details.size > maximum) fail("private input exceeds its boundary");
  if ((details.mode & 0o077) !== 0) fail("private input permissions must be mode 0600");
}

function boundedPublicFile(path) {
  const details = lstatSync(path);
  if (!details.isFile() || details.isSymbolicLink()) fail("site input is not a regular file");
  if (details.size <= 0 || details.size > MAX_SITE_FILE_BYTES) fail("site input exceeds its boundary");
  return readFileSync(path);
}

function privateJson(path) {
  privateRegularFile(path);
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    fail("private input is not valid UTF-8 JSON");
  }
}

function exclusiveJson(path, value) {
  if (existsSync(path)) fail("private output already exists");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  chmodSync(dirname(path), 0o700);
  const temporary = `${path}.tmp`;
  const descriptor = openSync(temporary, "wx", 0o600);
  try {
    writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  } finally {
    closeSync(descriptor);
  }
  renameSync(temporary, path);
  chmodSync(path, 0o600);
}

function parseOptions(values) {
  const options = new Map();
  for (let index = 0; index < values.length; index += 1) {
    const name = values[index];
    if (!name.startsWith("--")) fail("unexpected positional argument");
    if (name === "--headed") {
      options.set(name, true);
      continue;
    }
    const value = values[index + 1];
    if (!value || value.startsWith("--")) fail(`missing value for ${name}`);
    if (options.has(name)) fail(`duplicate option ${name}`);
    options.set(name, value);
    index += 1;
  }
  return options;
}

function required(options, name) {
  const value = options.get(name);
  if (typeof value !== "string" || value.length === 0) fail(`${name} is required`);
  return value;
}

function timeoutMilliseconds(options) {
  const raw = options.get("--timeout-seconds") ?? "180";
  if (!/^[0-9]+$/.test(raw)) fail("timeout seconds must be an integer");
  const seconds = Number(raw);
  if (seconds < 30 || seconds > 600) fail("timeout seconds must be between 30 and 600");
  return seconds * 1000;
}

function validateSha256(value, label) {
  if (!/^[0-9a-f]{64}$/.test(value)) fail(`${label} digest is invalid`);
  return value;
}

function validateRouteInput(path) {
  const value = privateJson(path);
  if (!exactKeys(value, ROUTE_INPUT_KEYS) || value.schema_version !== 1) {
    fail("private route attachment shape changed");
  }
  const attachment = value.route_attachment;
  const binding = value.route_binding;
  const attachmentKeys = new Set([
    "type",
    "signaling_uri",
    "token",
    "signaling_credential",
    "subprotocols",
    "ice_servers",
    "expires_at",
  ]);
  const bindingKeys = new Set(["tenantId", "callId", "legId"]);
  if (
    !exactKeys(attachment, attachmentKeys)
    || !exactKeys(binding, bindingKeys)
    || attachment.type !== "webrtc"
    || !/^[A-Za-z0-9_-]{43}$/.test(attachment.token)
    || attachment.signaling_credential?.usage !== "bridgefu-webrtc-signaling"
    || !/^bfs1\.[A-Za-z0-9_.-]{1,4091}$/.test(
      attachment.signaling_credential?.token ?? "",
    )
    || !Array.isArray(attachment.subprotocols)
    || attachment.subprotocols.length !== 3
    || attachment.subprotocols[0] !== "rvoip.webrtc.v1"
    || attachment.subprotocols[1] !== `token.${attachment.signaling_credential.token}`
    || attachment.subprotocols[2] !== `bridgefu.attach.${attachment.token}`
    || !Array.isArray(attachment.ice_servers)
    || attachment.ice_servers.length !== 1
    || !exactKeys(attachment.ice_servers[0], new Set(["urls"]))
    || !Array.isArray(attachment.ice_servers[0].urls)
    || attachment.ice_servers[0].urls.length !== 1
    || !QUALIFICATION_STUN_URLS.has(attachment.ice_servers[0].urls[0])
    || ![binding.tenantId, binding.callId, binding.legId].every(
      (field) => typeof field === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(field),
    )
  ) {
    fail("private route attachment violates the Bridgefu SDK contract");
  }
  let signaling;
  try {
    signaling = new URL(attachment.signaling_uri);
  } catch {
    fail("private route signaling URI is invalid");
  }
  if (
    signaling.protocol !== "wss:"
    || signaling.username
    || signaling.password
    || signaling.search
    || signaling.hash
    || !signaling.hostname
  ) {
    fail("private route signaling URI must use exact WSS");
  }
  const expiresAt = Date.parse(attachment.expires_at);
  const credentialExpiry = Date.parse(attachment.signaling_credential.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt !== credentialExpiry || expiresAt <= Date.now()) {
    fail("private route attachment expiry is invalid");
  }
  return value;
}

function validateSiteUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail("deployed demo-site URL is invalid");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.port ||
    !/^d[a-z0-9]+\.cloudfront\.net$/.test(parsed.hostname) ||
    !["", "/"].includes(parsed.pathname) ||
    parsed.search ||
    parsed.hash
  ) {
    fail("deployed demo-site URL must be an exact CloudFront HTTPS origin");
  }
  return `${parsed.origin}/`;
}

function readPromptPcm(path) {
  privateRegularFile(path, 8 * 1024 * 1024);
  const value = readFileSync(path);
  if (value.length < 2 || value.length % 2 !== 0) {
    fail("spoken handoff prompt is not signed 16-bit PCM");
  }
  if (value.length / 2 > PROMPT_SAMPLE_RATE * 60) {
    fail("spoken handoff prompt exceeds its duration boundary");
  }
  const samples = new Int16Array(value.length / 2);
  for (let index = 0; index < samples.length; index += 1) {
    samples[index] = value.readInt16LE(index * 2);
  }
  return samples;
}

function writeProbeWav(path, promptPcmPath) {
  if (existsSync(path)) fail("fake microphone path already exists");
  const promptSamples = readPromptPcm(promptPcmPath);
  const sampleCount = PROBE_SECONDS * SAMPLE_RATE;
  const bodyBytes = sampleCount * 2;
  const buffer = Buffer.alloc(44 + bodyBytes);
  buffer.write("RIFF", 0);
  buffer.writeUInt32LE(36 + bodyBytes, 4);
  buffer.write("WAVEfmt ", 8);
  buffer.writeUInt32LE(16, 16);
  buffer.writeUInt16LE(1, 20);
  buffer.writeUInt16LE(1, 22);
  buffer.writeUInt32LE(SAMPLE_RATE, 24);
  buffer.writeUInt32LE(SAMPLE_RATE * 2, 28);
  buffer.writeUInt16LE(2, 32);
  buffer.writeUInt16LE(16, 34);
  buffer.write("data", 36);
  buffer.writeUInt32LE(bodyBytes, 40);
  for (let sample = 0; sample < sampleCount; sample += 1) {
    const elapsedMs = (sample * 1000) / SAMPLE_RATE;
    const afterSilence = elapsedMs - PROBE_INITIAL_SILENCE_MS;
    const cycle = ((afterSilence % PROBE_CYCLE_MS) + PROBE_CYCLE_MS) % PROBE_CYCLE_MS;
    const pulse = Math.floor(cycle / 1000);
    const marker =
      afterSilence >= 0 &&
      pulse < PROBE_PULSES_PER_CYCLE &&
      cycle - pulse * 1000 < PROBE_PULSE_MS;
    const dtmf =
      afterSilence >= 0 &&
      cycle >= DTMF_START_MS &&
      cycle < DTMF_START_MS + DTMF_DURATION_MS;
    let value = 0;
    const promptSample = Math.floor(
      ((elapsedMs - PROMPT_START_MS) * PROMPT_SAMPLE_RATE) / 1000,
    );
    if (promptSample >= 0 && promptSample < promptSamples.length) {
      value += (promptSamples[promptSample] / 32768) * 0.8;
    }
    if (marker) value += Math.sin((2 * Math.PI * SOURCE_MARKER_HZ * sample) / SAMPLE_RATE);
    if (dtmf) {
      value += 0.55 * Math.sin((2 * Math.PI * 770 * sample) / SAMPLE_RATE);
      value += 0.55 * Math.sin((2 * Math.PI * 1336 * sample) / SAMPLE_RATE);
    }
    buffer.writeInt16LE(Math.round(Math.max(-1, Math.min(1, value)) * 8191), 44 + sample * 2);
  }
  const descriptor = openSync(path, "wx", 0o600);
  try {
    writeFileSync(descriptor, buffer);
  } finally {
    closeSync(descriptor);
  }
}

async function waitUntil(operation, timeoutMs, message, intervalMs = 250) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const result = await operation();
      if (result) return result;
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, intervalMs));
  }
  if (lastError) fail(`${message}: ${lastError.message}`);
  fail(message);
}

async function waitForPrivateFile(path, timeoutMs) {
  return waitUntil(
    () => {
      if (!existsSync(path)) return false;
      privateRegularFile(path);
      return true;
    },
    timeoutMs,
    "private orchestration file did not arrive",
  );
}

function validateSession(path, bridgefuCallId, hangupOrigin) {
  const session = privateJson(path);
  if (!exactKeys(session, SESSION_KEYS)) fail("private session shape changed");
  const callFingerprint = sha256Bytes(bridgefuCallId).slice(0, 12);
  if (
    session.schema_version !== 1 ||
    session.recipe !== "vapi-amazon-connect-screen-pop@1" ||
    session.scenario_id !== "bridgefu-web-sdk-handoff" ||
    session.hangup_origin !== hangupOrigin ||
    !["sips_optional_srtp", "sips_srtp", "sip_rtp"].includes(session.security) ||
    session.codec !== "negotiated" ||
    !validNetworkContract(session.network_profile, session.network_contract) ||
    session.sip_uri !== null ||
    session.source_call_id !== bridgefuCallId ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(session.vapi_call_id) ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(session.source_org_id) ||
    session.source_call_fingerprint !== callFingerprint ||
    !/^bf1_[A-Za-z0-9_-]{43}$/.test(session.correlation_id) ||
    sha256Bytes(session.correlation_id).slice(0, 12) !== session.correlation_fingerprint ||
    session.sip_header?.name !== "X-Correlation-Id" ||
    session.sip_header?.value !== session.correlation_id ||
    session.expected_context?.customer_name !== "Bridgefu Synthetic Caller" ||
    session.expected_context?.issue_summary !==
      `Qualification Bridgefu Web SDK ${hangupOrigin} hangup.` ||
    session.expected_context?.intent !== "qualification" ||
    session.expected_context?.verification_status !== "synthetic"
  ) {
    fail("private session violates the Bridgefu browser source contract");
  }
  return session;
}

function installProbe() {
  if (globalThis.__bridgefuVapiProbe) return;
  const newCandidateSummary = () => ({
    udpIpv4Srflx: 0,
    udpIpv4Host: 0,
    udpIpv6: 0,
    tcp: 0,
    other: 0,
  });
  const newCandidatePairSummary = () => ({
    waiting: 0,
    inProgress: 0,
    succeeded: 0,
    failed: 0,
    frozen: 0,
    other: 0,
    selected: 0,
  });
  const newDescriptionSummary = () => ({
    present: 0,
    audioMedia: 0,
    applicationMedia: 0,
    rejectedMedia: 0,
    mids: 0,
    iceUfrag: 0,
    icePwd: 0,
    fingerprint: 0,
    inlineCandidates: 0,
    endOfCandidates: 0,
    iceLite: 0,
    setupActive: 0,
    setupPassive: 0,
    setupActpass: 0,
    bundleGroups: 0,
    bundleMids: 0,
    uniqueIceUfrag: 0,
    uniqueIcePwd: 0,
    uniqueFingerprint: 0,
    sendrecv: 0,
    recvonly: 0,
    sendonly: 0,
    inactive: 0,
  });
  const classifyDescription = (description) => {
    const summary = newDescriptionSummary();
    const sdp = String(description?.sdp ?? "");
    if (!sdp || sdp.length > 1024 * 1024) return summary;
    summary.present = 1;
    const ufrags = new Set();
    const passwords = new Set();
    const fingerprints = new Set();
    for (const line of sdp.split(/\r?\n/).slice(0, 4096)) {
      if (line.startsWith("m=audio ")) summary.audioMedia += 1;
      if (line.startsWith("m=application ")) summary.applicationMedia += 1;
      if (/^m=[^ ]+ 0(?: |$)/.test(line)) summary.rejectedMedia += 1;
      if (line.startsWith("a=mid:")) summary.mids += 1;
      if (line.startsWith("a=ice-ufrag:")) {
        summary.iceUfrag += 1;
        ufrags.add(line.slice("a=ice-ufrag:".length));
      }
      if (line.startsWith("a=ice-pwd:")) {
        summary.icePwd += 1;
        passwords.add(line.slice("a=ice-pwd:".length));
      }
      if (line.startsWith("a=fingerprint:")) {
        summary.fingerprint += 1;
        fingerprints.add(line.slice("a=fingerprint:".length));
      }
      if (line.startsWith("a=candidate:")) summary.inlineCandidates += 1;
      if (line === "a=end-of-candidates") summary.endOfCandidates += 1;
      if (line === "a=ice-lite") summary.iceLite += 1;
      if (line === "a=setup:active") summary.setupActive += 1;
      if (line === "a=setup:passive") summary.setupPassive += 1;
      if (line === "a=setup:actpass") summary.setupActpass += 1;
      if (line.startsWith("a=group:BUNDLE")) {
        summary.bundleGroups += 1;
        summary.bundleMids += Math.max(0, line.trim().split(/\s+/).length - 1);
      }
      if (line === "a=sendrecv") summary.sendrecv += 1;
      if (line === "a=recvonly") summary.recvonly += 1;
      if (line === "a=sendonly") summary.sendonly += 1;
      if (line === "a=inactive") summary.inactive += 1;
    }
    summary.uniqueIceUfrag = ufrags.size;
    summary.uniqueIcePwd = passwords.size;
    summary.uniqueFingerprint = fingerprints.size;
    return summary;
  };
  const newTransceiverSummary = () => ({
    count: 0,
    midPresent: 0,
    currentNull: 0,
    sendrecv: 0,
    recvonly: 0,
    sendonly: 0,
    inactive: 0,
    other: 0,
  });
  const newCandidateAssociationSummary = () => ({
    sdpMidEmpty: 0,
    sdpMidAbsent: 0,
    sdpMidNonempty: 0,
    mLineZero: 0,
    mLineOther: 0,
    mLineAbsent: 0,
    usernameFragmentPresent: 0,
    addSucceeded: 0,
    addFailed: 0,
  });
  const mergeMaximums = (destination, source) => {
    for (const [key, value] of Object.entries(source)) {
      destination[key] = Math.max(destination[key], value);
    }
  };
  const classifyCandidate = (candidate, summary) => {
    const raw = String(candidate?.candidate ?? "");
    const tokens = raw.trim().split(/\s+/);
    const typeIndex = tokens.findIndex((token) => token.toLowerCase() === "typ");
    const protocol = String(candidate?.protocol ?? tokens[2] ?? "").toLowerCase();
    const type = String(candidate?.type ?? (typeIndex >= 0 ? tokens[typeIndex + 1] : ""))
      .toLowerCase();
    const address = String(candidate?.address ?? tokens[4] ?? "");
    if (protocol === "tcp") summary.tcp += 1;
    else if (
      protocol === "udp" && type === "srflx"
      && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)
    ) summary.udpIpv4Srflx += 1;
    else if (
      protocol === "udp" && type === "host"
      && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)
    ) summary.udpIpv4Host += 1;
    else if (protocol === "udp" && address.includes(":")) summary.udpIpv6 += 1;
    else summary.other += 1;
  };
  const state = {
    captureRequestedAtMs: null,
    captureResolvedAtMs: null,
    agentMarkerObservedAtMs: [],
    agentMarkerFrames: 0,
    agentMarkerActive: false,
    agentMarkerLastEdgeMs: 0,
    dtmfAgentToSourceObserved: false,
    dtmfActive: false,
    remoteAudioTracks: 0,
    remoteAudioActiveFrames: 0,
    remoteAudioMaxRms: 0,
    iceCandidateSummary: newCandidateSummary(),
    remoteIceCandidateSummary: newCandidateSummary(),
    remoteIceComplete: 0,
    statsRemoteCandidateSummary: newCandidateSummary(),
    candidatePairSummary: newCandidatePairSummary(),
    localDescriptionSummary: newDescriptionSummary(),
    remoteDescriptionSummary: newDescriptionSummary(),
    remoteCandidateAssociationSummary: newCandidateAssociationSummary(),
    transceiverSummary: newTransceiverSummary(),
    statsSamples: 0,
  };
  globalThis.__bridgefuVapiProbe = state;
  globalThis.__bridgefuVapiPeers = [];
  const mediaDevices = navigator.mediaDevices;
  if (mediaDevices?.getUserMedia) {
    const original = mediaDevices.getUserMedia.bind(mediaDevices);
    mediaDevices.getUserMedia = async (...argumentsList) => {
      state.captureRequestedAtMs ??= Date.now();
      const stream = await original(...argumentsList);
      state.captureResolvedAtMs ??= Date.now();
      return stream;
    };
  }
  const power = (samples, sampleRate, frequency) => {
    const coefficient = 2 * Math.cos((2 * Math.PI * frequency) / sampleRate);
    let previous = 0;
    let beforePrevious = 0;
    for (const sample of samples) {
      const current = sample + coefficient * previous - beforePrevious;
      beforePrevious = previous;
      previous = current;
    }
    return (
      (previous * previous + beforePrevious * beforePrevious - coefficient * previous * beforePrevious) /
      (samples.length * samples.length)
    );
  };
  const observeTrack = (track) => {
    state.remoteAudioTracks += 1;
    const AudioContextClass = globalThis.AudioContext ?? globalThis.webkitAudioContext;
    if (!AudioContextClass) return;
    const context = new AudioContextClass();
    const source = context.createMediaStreamSource(new MediaStream([track]));
    const analyser = context.createAnalyser();
    analyser.fftSize = 2048;
    source.connect(analyser);
    const samples = new Float32Array(analyser.fftSize);
    const timer = setInterval(async () => {
      if (track.readyState === "ended") {
        clearInterval(timer);
        await context.close().catch(() => {});
        return;
      }
      await context.resume().catch(() => {});
      analyser.getFloatTimeDomainData(samples);
      let energy = 0;
      for (const sample of samples) energy += sample * sample;
      const rms = Math.sqrt(energy / samples.length);
      state.remoteAudioMaxRms = Math.max(state.remoteAudioMaxRms, rms);
      if (rms > 0.01) state.remoteAudioActiveFrames += 1;
      const marker = rms > 0.01 && power(samples, context.sampleRate, AGENT_MARKER_HZ) > 0.0003;
      if (marker) {
        state.agentMarkerFrames += 1;
        const now = Date.now();
        if (
          !state.agentMarkerActive &&
          now - state.agentMarkerLastEdgeMs >= 500 &&
          state.agentMarkerObservedAtMs.length < 16
        ) {
          state.agentMarkerObservedAtMs.push(now);
          state.agentMarkerLastEdgeMs = now;
        }
      }
      state.agentMarkerActive = marker;
      const low = power(samples, context.sampleRate, 770);
      const high = power(samples, context.sampleRate, 1477);
      const dtmf = rms > 0.01 && low > 0.00015 && high > 0.00015;
      if (dtmf && !state.dtmfActive) state.dtmfAgentToSourceObserved = true;
      state.dtmfActive = dtmf;
    }, 20);
  };
  const NativePeerConnection = globalThis.RTCPeerConnection;
  if (NativePeerConnection) {
    globalThis.RTCPeerConnection = new Proxy(NativePeerConnection, {
      construct(Target, argumentsList, NewTarget) {
        const peer = Reflect.construct(Target, argumentsList, NewTarget);
        globalThis.__bridgefuVapiPeers.push(peer);
        const nativeAddIceCandidate = peer.addIceCandidate.bind(peer);
        peer.addIceCandidate = async (candidate) => {
          if (candidate === null) state.remoteIceComplete += 1;
          else {
            classifyCandidate(candidate, state.remoteIceCandidateSummary);
            if (candidate.sdpMid === "") {
              state.remoteCandidateAssociationSummary.sdpMidEmpty += 1;
            } else if (candidate.sdpMid === null || candidate.sdpMid === undefined) {
              state.remoteCandidateAssociationSummary.sdpMidAbsent += 1;
            } else state.remoteCandidateAssociationSummary.sdpMidNonempty += 1;
            if (candidate.sdpMLineIndex === 0) {
              state.remoteCandidateAssociationSummary.mLineZero += 1;
            } else if (
              candidate.sdpMLineIndex === null || candidate.sdpMLineIndex === undefined
            ) state.remoteCandidateAssociationSummary.mLineAbsent += 1;
            else state.remoteCandidateAssociationSummary.mLineOther += 1;
            if (typeof candidate.usernameFragment === "string" && candidate.usernameFragment) {
              state.remoteCandidateAssociationSummary.usernameFragmentPresent += 1;
            }
          }
          try {
            const result = await nativeAddIceCandidate(candidate);
            state.remoteCandidateAssociationSummary.addSucceeded += 1;
            return result;
          } catch (error) {
            state.remoteCandidateAssociationSummary.addFailed += 1;
            throw error;
          }
        };
        const sampleStats = async () => {
          try {
            const report = await peer.getStats();
            const selectedPairIds = new Set();
            const remoteCandidates = newCandidateSummary();
            const candidatePairs = newCandidatePairSummary();
            for (const row of report.values()) {
              if (row.type === "transport" && typeof row.selectedCandidatePairId === "string") {
                selectedPairIds.add(row.selectedCandidatePairId);
              }
            }
            for (const row of report.values()) {
              if (row.type === "candidate-pair") {
                const pairState = String(row.state ?? "").toLowerCase();
                if (pairState === "waiting") candidatePairs.waiting += 1;
                else if (pairState === "in-progress") candidatePairs.inProgress += 1;
                else if (pairState === "succeeded") candidatePairs.succeeded += 1;
                else if (pairState === "failed") candidatePairs.failed += 1;
                else if (pairState === "frozen") candidatePairs.frozen += 1;
                else candidatePairs.other += 1;
                if (selectedPairIds.has(row.id)) candidatePairs.selected += 1;
              }
              if (row.type === "remote-candidate") {
                classifyCandidate({
                  candidate: "",
                  protocol: row.protocol,
                  type: row.candidateType,
                  address: row.address,
                }, remoteCandidates);
              }
            }
            mergeMaximums(state.statsRemoteCandidateSummary, remoteCandidates);
            mergeMaximums(state.candidatePairSummary, candidatePairs);
            mergeMaximums(
              state.localDescriptionSummary,
              classifyDescription(peer.localDescription),
            );
            mergeMaximums(
              state.remoteDescriptionSummary,
              classifyDescription(peer.remoteDescription),
            );
            const transceivers = newTransceiverSummary();
            for (const transceiver of peer.getTransceivers()) {
              transceivers.count += 1;
              if (typeof transceiver.mid === "string" && transceiver.mid) {
                transceivers.midPresent += 1;
              }
              const direction = transceiver.currentDirection;
              if (direction === null) transceivers.currentNull += 1;
              else if (direction === "sendrecv") transceivers.sendrecv += 1;
              else if (direction === "recvonly") transceivers.recvonly += 1;
              else if (direction === "sendonly") transceivers.sendonly += 1;
              else if (direction === "inactive") transceivers.inactive += 1;
              else transceivers.other += 1;
            }
            mergeMaximums(state.transceiverSummary, transceivers);
            state.statsSamples = Math.min(4096, state.statsSamples + 1);
          } catch {
            // Closed peer diagnostics are intentionally excluded.
          }
        };
        const statsTimer = setInterval(() => void sampleStats(), 100);
        peer.addEventListener("connectionstatechange", () => {
          void sampleStats();
          if (peer.connectionState === "closed") clearInterval(statsTimer);
        });
        peer.addEventListener("track", (event) => {
          if (event.track?.kind === "audio") observeTrack(event.track);
        });
        peer.addEventListener("icecandidate", (event) => {
          const candidate = event.candidate;
          if (!candidate) return;
          classifyCandidate(candidate, state.iceCandidateSummary);
        });
        return peer;
      },
    });
  }
}

async function probeSnapshot(page) {
  return page.evaluate(async () => {
    const state = globalThis.__bridgefuVapiProbe;
    if (!state) return null;
    let audioPacketsSent = 0;
    let audioBytesSent = 0;
    let audioPacketsReceived = 0;
    let audioBytesReceived = 0;
    let telephoneEventPacketsReceived = 0;
    for (const peer of globalThis.__bridgefuVapiPeers ?? []) {
      try {
        const report = await peer.getStats();
        const telephoneEventCodecs = new Set();
        for (const row of report.values()) {
          if (
            row.type === "codec" &&
            typeof row.mimeType === "string" &&
            row.mimeType.toLowerCase() === "audio/telephone-event"
          ) {
            telephoneEventCodecs.add(row.id);
          }
        }
        for (const row of report.values()) {
          if (row.type === "outbound-rtp" && row.kind === "audio" && !row.isRemote) {
            audioPacketsSent += Number(row.packetsSent ?? 0);
            audioBytesSent += Number(row.bytesSent ?? 0);
          }
          if (row.type === "inbound-rtp" && row.kind === "audio" && !row.isRemote) {
            audioPacketsReceived += Number(row.packetsReceived ?? 0);
            audioBytesReceived += Number(row.bytesReceived ?? 0);
          }
          if (
            row.type === "inbound-rtp" &&
            telephoneEventCodecs.has(row.codecId)
          ) {
            telephoneEventPacketsReceived += Number(row.packetsReceived ?? 0);
          }
        }
      } catch {
        // Closed peer counters are intentionally excluded.
      }
    }
    return {
      captureRequestedAtMs: state.captureRequestedAtMs,
      captureResolvedAtMs: state.captureResolvedAtMs,
      agentMarkerObservedAtMs: [...state.agentMarkerObservedAtMs],
      agentMarkerFrames: state.agentMarkerFrames,
      dtmfAgentToSourceObserved: state.dtmfAgentToSourceObserved,
      remoteAudioTracks: state.remoteAudioTracks,
      remoteAudioActiveFrames: state.remoteAudioActiveFrames,
      remoteAudioMaxRms: state.remoteAudioMaxRms,
      audioPacketsSent,
      audioBytesSent,
      audioPacketsReceived,
      audioBytesReceived,
      telephoneEventPacketsReceived,
    };
  });
}

function sourceMarkerSchedule(captureStartedAtMs, triggerAtMs, observedAtMs) {
  const firstMarker = captureStartedAtMs + PROBE_INITIAL_SILENCE_MS;
  const firstCycle = Math.max(0, Math.ceil((triggerAtMs + 500 - firstMarker) / PROBE_CYCLE_MS));
  const result = [];
  for (let cycle = firstCycle; result.length < 32; cycle += 1) {
    const cycleStart = firstMarker + cycle * PROBE_CYCLE_MS;
    for (let pulse = 0; pulse < PROBE_PULSES_PER_CYCLE; pulse += 1) {
      const timestamp = cycleStart + pulse * 1000;
      if (timestamp > observedAtMs) return result;
      result.push(timestamp);
    }
  }
  return result;
}

function sourceDtmfSchedule(captureStartedAtMs, triggerAtMs, observedAtMs) {
  const firstDtmf = captureStartedAtMs + PROBE_INITIAL_SILENCE_MS + DTMF_START_MS;
  const firstCycle = Math.max(
    0,
    Math.ceil((triggerAtMs + 500 - firstDtmf) / PROBE_CYCLE_MS),
  );
  const result = [];
  for (let cycle = firstCycle; result.length < 16; cycle += 1) {
    const timestamp = firstDtmf + cycle * PROBE_CYCLE_MS;
    if (timestamp > observedAtMs) return result;
    result.push(timestamp);
  }
  return result;
}

async function applicationSnapshot(page, nonce) {
  const value = await page.evaluate(
    (qualificationNonce) => {
      const snapshot =
        globalThis.__BRIDGEFU_RECIPE_QUALIFICATION__?.snapshot(qualificationNonce) ?? null;
      if (snapshot === null) return null;
      return {
        ...snapshot,
        iceCandidateSummary: {
          ...(globalThis.__bridgefuVapiProbe?.iceCandidateSummary ?? {}),
        },
        remoteIceCandidateSummary: {
          ...(globalThis.__bridgefuVapiProbe?.remoteIceCandidateSummary ?? {}),
        },
        remoteIceComplete: globalThis.__bridgefuVapiProbe?.remoteIceComplete ?? 0,
        statsRemoteCandidateSummary: {
          ...(globalThis.__bridgefuVapiProbe?.statsRemoteCandidateSummary ?? {}),
        },
        candidatePairSummary: {
          ...(globalThis.__bridgefuVapiProbe?.candidatePairSummary ?? {}),
        },
        localDescriptionSummary: {
          ...(globalThis.__bridgefuVapiProbe?.localDescriptionSummary ?? {}),
        },
        remoteDescriptionSummary: {
          ...(globalThis.__bridgefuVapiProbe?.remoteDescriptionSummary ?? {}),
        },
        remoteCandidateAssociationSummary: {
          ...(globalThis.__bridgefuVapiProbe?.remoteCandidateAssociationSummary ?? {}),
        },
        transceiverSummary: {
          ...(globalThis.__bridgefuVapiProbe?.transceiverSummary ?? {}),
        },
        statsSamples: globalThis.__bridgefuVapiProbe?.statsSamples ?? 0,
      };
    },
    nonce,
  );
  if (value === null) return null;
  if (
    !value || typeof value !== "object" || Array.isArray(value)
    || (value.errorType !== null && !STARTUP_ERROR_TYPES.has(value.errorType))
    || !PEER_CONNECTION_STATES.has(value.peerConnectionState)
    || !ICE_CONNECTION_STATES.has(value.iceConnectionState)
    || !ICE_GATHERING_STATES.has(value.iceGatheringState)
    || !SIGNALING_STATES.has(value.signalingState)
    || !exactKeys(
      value.iceCandidateSummary,
      new Set(["udpIpv4Srflx", "udpIpv4Host", "udpIpv6", "tcp", "other"]),
    )
    || !Object.values(value.iceCandidateSummary).every(
      (count) => Number.isSafeInteger(count) && count >= 0 && count <= 256,
    )
    || !exactKeys(
      value.remoteIceCandidateSummary,
      new Set(["udpIpv4Srflx", "udpIpv4Host", "udpIpv6", "tcp", "other"]),
    )
    || !Object.values(value.remoteIceCandidateSummary).every(
      (count) => Number.isSafeInteger(count) && count >= 0 && count <= 256,
    )
    || !Number.isSafeInteger(value.remoteIceComplete)
    || value.remoteIceComplete < 0
    || value.remoteIceComplete > 16
    || !exactKeys(
      value.statsRemoteCandidateSummary,
      new Set(["udpIpv4Srflx", "udpIpv4Host", "udpIpv6", "tcp", "other"]),
    )
    || !Object.values(value.statsRemoteCandidateSummary).every(
      (count) => Number.isSafeInteger(count) && count >= 0 && count <= 256,
    )
    || !exactKeys(
      value.candidatePairSummary,
      new Set(["waiting", "inProgress", "succeeded", "failed", "frozen", "other", "selected"]),
    )
    || !Object.values(value.candidatePairSummary).every(
      (count) => Number.isSafeInteger(count) && count >= 0 && count <= 1024,
    )
    || !exactKeys(
      value.localDescriptionSummary,
      new Set([
        "present", "audioMedia", "applicationMedia", "rejectedMedia", "mids",
        "iceUfrag", "icePwd", "fingerprint", "inlineCandidates", "endOfCandidates",
        "iceLite", "setupActive", "setupPassive", "setupActpass", "bundleGroups",
        "bundleMids", "uniqueIceUfrag", "uniqueIcePwd", "uniqueFingerprint",
        "sendrecv", "recvonly", "sendonly", "inactive",
      ]),
    )
    || !Object.values(value.localDescriptionSummary).every(
      (count) => Number.isSafeInteger(count) && count >= 0 && count <= 4096,
    )
    || !exactKeys(
      value.remoteDescriptionSummary,
      new Set([
        "present", "audioMedia", "applicationMedia", "rejectedMedia", "mids",
        "iceUfrag", "icePwd", "fingerprint", "inlineCandidates", "endOfCandidates",
        "iceLite", "setupActive", "setupPassive", "setupActpass", "bundleGroups",
        "bundleMids", "uniqueIceUfrag", "uniqueIcePwd", "uniqueFingerprint",
        "sendrecv", "recvonly", "sendonly", "inactive",
      ]),
    )
    || !Object.values(value.remoteDescriptionSummary).every(
      (count) => Number.isSafeInteger(count) && count >= 0 && count <= 4096,
    )
    || !exactKeys(
      value.remoteCandidateAssociationSummary,
      new Set([
        "sdpMidEmpty", "sdpMidAbsent", "sdpMidNonempty", "mLineZero", "mLineOther",
        "mLineAbsent", "usernameFragmentPresent", "addSucceeded", "addFailed",
      ]),
    )
    || !Object.values(value.remoteCandidateAssociationSummary).every(
      (count) => Number.isSafeInteger(count) && count >= 0 && count <= 256,
    )
    || !exactKeys(
      value.transceiverSummary,
      new Set([
        "count", "midPresent", "currentNull", "sendrecv", "recvonly", "sendonly",
        "inactive", "other",
      ]),
    )
    || !Object.values(value.transceiverSummary).every(
      (count) => Number.isSafeInteger(count) && count >= 0 && count <= 256,
    )
    || !Number.isSafeInteger(value.statsSamples)
    || value.statsSamples < 0
    || value.statsSamples > 4096
  ) {
    fail("Bridgefu WebRTC application returned invalid diagnostic state");
  }
  return value;
}

function failStartup(value) {
  if (value?.status !== "failed") return;
  const errorType = value.errorType ?? "unknown";
  fail(
    `Bridgefu WebRTC start failed e=${errorType} p=${value.peerConnectionState} `
    + `i=${value.iceConnectionState} g=${value.iceGatheringState} s=${value.signalingState} `
    + `l4s=${value.iceCandidateSummary.udpIpv4Srflx} `
    + `r4h=${value.remoteIceCandidateSummary.udpIpv4Host} rc=${value.remoteIceComplete} `
    + `pair=${value.candidatePairSummary.waiting}/${value.candidatePairSummary.inProgress}/`
    + `${value.candidatePairSummary.succeeded}/${value.candidatePairSummary.failed}/`
    + `${value.candidatePairSummary.selected} samples=${value.statsSamples} `
    + `mid=${value.remoteCandidateAssociationSummary.sdpMidEmpty}/`
    + `${value.remoteCandidateAssociationSummary.sdpMidAbsent}/`
    + `${value.remoteCandidateAssociationSummary.sdpMidNonempty} `
    + `ml0=${value.remoteCandidateAssociationSummary.mLineZero} `
    + `add=${value.remoteCandidateAssociationSummary.addSucceeded}/`
    + `${value.remoteCandidateAssociationSummary.addFailed} `
    + `ld=${value.localDescriptionSummary.audioMedia}/`
    + `${value.localDescriptionSummary.applicationMedia}/`
    + `${value.localDescriptionSummary.rejectedMedia}/`
    + `${value.localDescriptionSummary.bundleMids}/`
    + `${value.localDescriptionSummary.uniqueIceUfrag}/`
    + `${value.localDescriptionSummary.uniqueIcePwd}/`
    + `${value.localDescriptionSummary.uniqueFingerprint}/`
    + `${value.localDescriptionSummary.inlineCandidates} `
    + `rd=${value.remoteDescriptionSummary.audioMedia}/`
    + `${value.remoteDescriptionSummary.applicationMedia}/`
    + `${value.remoteDescriptionSummary.rejectedMedia}/`
    + `${value.remoteDescriptionSummary.bundleMids}/`
    + `${value.remoteDescriptionSummary.uniqueIceUfrag}/`
    + `${value.remoteDescriptionSummary.uniqueIcePwd}/`
    + `${value.remoteDescriptionSummary.uniqueFingerprint}/`
    + `${value.remoteDescriptionSummary.inlineCandidates}/`
    + `${value.remoteDescriptionSummary.setupActive}/`
    + `${value.remoteDescriptionSummary.setupPassive}/`
    + `${value.remoteDescriptionSummary.setupActpass} `
    + `tx=${value.transceiverSummary.count}/${value.transceiverSummary.midPresent}/`
    + `${value.transceiverSummary.currentNull}/${value.transceiverSummary.sendrecv}/`
    + `${value.transceiverSummary.recvonly}/${value.transceiverSummary.sendonly}/`
    + `${value.transceiverSummary.inactive}`,
  );
}

async function waitForSiteReady(page, timeoutMs) {
  try {
    await waitUntil(
      () => page.locator("#start").isEnabled(),
      timeoutMs,
      "immutable Bridgefu demo site did not become ready",
    );
  } catch (error) {
    const state = await page.evaluate(() => {
      const value = globalThis.__BRIDGEFU_RECIPE_TEST__;
      return value && typeof value === "object"
        ? { status: value.status, errorType: value.errorType }
        : null;
    }).catch(() => null);
    if (state?.status === "failed") {
      if (state.errorType === "configuration-invalid") {
        fail("immutable Bridgefu demo site rejected its configuration");
      }
      if (state.errorType === "configuration-unavailable") {
        fail("immutable Bridgefu demo site configuration was unavailable");
      }
      fail("immutable Bridgefu demo site failed during initialization");
    }
    if (state?.status === "loading") {
      fail("immutable Bridgefu demo site configuration load did not settle");
    }
    throw error;
  }
}

function contentType(path) {
  if (path.endsWith(".html")) return "text/html; charset=utf-8";
  if (path.endsWith(".css")) return "text/css; charset=utf-8";
  if (path.endsWith(".js")) return "text/javascript; charset=utf-8";
  if (path.endsWith(".json")) return "application/json; charset=utf-8";
  return "text/plain; charset=utf-8";
}

async function localSite(siteDir, config) {
  const assets = new Map();
  for (const name of ["index.html", "style.css", "app.js", "app.js.LEGAL.txt", "third-party-licenses.json"]) {
    assets.set(`/${name}`, boundedPublicFile(join(siteDir, name)));
  }
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    const path = url.pathname === "/" ? "/index.html" : url.pathname;
    const body = path === "/config.json" ? Buffer.from(JSON.stringify(config)) : assets.get(path);
    if (request.method !== "GET" || !body) {
      response.writeHead(404, { "Cache-Control": "no-store" });
      response.end();
      return;
    }
    response.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": contentType(path),
      "Cross-Origin-Opener-Policy": "same-origin",
      "Permissions-Policy": "microphone=(self)",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    });
    response.end(body);
  });
  await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  const address = server.address();
  if (!address || typeof address === "string") fail("local qualification site did not bind");
  return {
    url: `http://127.0.0.1:${address.port}/`,
    close: () => new Promise((resolvePromise) => server.close(resolvePromise)),
  };
}

async function observe(options) {
  const siteDirectoryOption = options.get("--site-dir");
  const siteUrlOption = options.get("--site-url");
  if ((typeof siteDirectoryOption === "string") === (typeof siteUrlOption === "string")) {
    fail("provide exactly one of --site-dir or --site-url");
  }
  const siteDir =
    typeof siteDirectoryOption === "string" ? resolve(siteDirectoryOption) : null;
  const routeInput = validateRouteInput(resolve(required(options, "--route-attachment")));
  const sessionPath = resolve(required(options, "--session"));
  const readyPath = resolve(required(options, "--ready"));
  const triggerPath = resolve(required(options, "--trigger"));
  const observationPath = resolve(required(options, "--observation"));
  const siteBundleSha256 = validateSha256(
    required(options, "--site-bundle-sha256"),
    "site bundle",
  );
  const promptPcm = resolve(required(options, "--prompt-pcm"));
  const signalingHostname = required(options, "--signaling-hostname").toLowerCase();
  if (
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/.test(
      signalingHostname,
    )
  ) {
    fail("Bridgefu signaling hostname is invalid");
  }
  if (new URL(routeInput.route_attachment.signaling_uri).hostname !== signalingHostname) {
    fail("Bridgefu signaling hostname does not match the attachment");
  }
  const hangupOrigin = required(options, "--hangup-origin");
  if (!["source", "agent"].includes(hangupOrigin)) fail("hangup origin is invalid");
  const timeoutMs = timeoutMilliseconds(options);
  for (const output of [readyPath, triggerPath, observationPath]) {
    if (existsSync(output)) fail("qualification output path already exists");
  }
  const nonce = randomBytes(32).toString("base64url");
  const qualificationConfig = {
    schema_version: 2,
    recipe: "vapi-amazon-connect-screen-pop@1",
    route_attachment: routeInput.route_attachment,
    route_binding: routeInput.route_binding,
    release_revision: siteBundleSha256,
    qualification_nonce: nonce,
    qualification_hangup_origin: hangupOrigin,
  };
  const site = siteDir
    ? await localSite(siteDir, qualificationConfig)
    : { url: validateSiteUrl(siteUrlOption), close: async () => {} };
  const probePath = join(dirname(observationPath), `.vapi-probe-${randomBytes(12).toString("hex")}.wav`);
  writeProbeWav(probePath, promptPcm);
  const browser = await chromium.launch({
    headless: !options.has("--headed"),
    args: [
      "--use-fake-ui-for-media-stream",
      "--use-fake-device-for-media-stream",
      `--use-file-for-fake-audio-capture=${probePath}`,
      `--host-resolver-rules=MAP ${signalingHostname} 127.0.0.1, EXCLUDE localhost`,
      "--autoplay-policy=no-user-gesture-required",
      "--no-sandbox",
    ],
  });
  try {
    const context = await browser.newContext({ permissions: ["microphone"] });
    await context.addInitScript(installProbe);
    const page = await context.newPage();
    if (!siteDir) {
      await page.route(new URL("config.json", site.url).href, (route) =>
        route.fulfill({
          status: 200,
          contentType: "application/json; charset=utf-8",
          headers: { "Cache-Control": "no-store" },
          body: JSON.stringify(qualificationConfig),
        }),
      );
    }
    const navigation = await page.goto(site.url, {
      waitUntil: "domcontentloaded",
      timeout: 30_000,
    });
    if (!navigation || navigation.status() !== 200) {
      fail("immutable Bridgefu demo site navigation failed");
    }
    if (!siteDir) {
      const headers = navigation.headers();
      if (
        !headers["cache-control"]?.toLowerCase().includes("no-store") ||
        headers["x-frame-options"]?.toUpperCase() !== "DENY" ||
        headers["x-content-type-options"]?.toLowerCase() !== "nosniff" ||
        headers["cross-origin-opener-policy"]?.toLowerCase() !== "same-origin" ||
        headers["permissions-policy"]?.replaceAll(" ", "") !== "microphone=(self)" ||
        !headers["content-security-policy"]?.includes("frame-ancestors 'none'")
      ) {
        fail("deployed CloudFront demo site security headers changed");
      }
    }
    await waitForSiteReady(page, Math.min(timeoutMs, 30_000));
    const startedAtMs = Date.now();
    await page.locator("#start").click();
    const initial = await waitUntil(
      async () => {
        const value = await applicationSnapshot(page, nonce);
        failStartup(value);
        const media = await probeSnapshot(page);
        return value?.callStartObserved
          && value.peerConnectionState === "connected"
          && ["connected", "completed"].includes(value.iceConnectionState)
          && typeof value.callId === "string"
          && Number.isInteger(media?.captureRequestedAtMs)
          && Number.isInteger(media?.captureResolvedAtMs)
          && media.audioPacketsSent > 5
          && media.audioBytesSent > 0
          ? { ...value, captureRequestedAtMs: media.captureRequestedAtMs }
          : false;
      },
      Math.min(timeoutMs, 90_000),
      "Bridgefu WebRTC media did not establish",
    );
    if (Date.now() - initial.captureRequestedAtMs >= PROMPT_START_MS) {
      fail("Bridgefu WebRTC media missed the spoken-trigger window");
    }
    const callId = initial.callId;
    if (callId !== routeInput.route_binding.callId) {
      fail("Bridgefu WebRTC call identity changed");
    }
    const sourceCallFingerprint = sha256Bytes(callId).slice(0, 12);
    exclusiveJson(readyPath, {
      schema_version: 1,
      call_id: callId,
      source_call_fingerprint: sourceCallFingerprint,
      started_at: new Date(startedAtMs).toISOString(),
      started_epoch_ms: startedAtMs,
    });
    await waitForPrivateFile(sessionPath, timeoutMs);
    const session = validateSession(sessionPath, callId, hangupOrigin);
    await waitForPrivateFile(triggerPath, timeoutMs);
    const triggerAtMs = Date.now();
    const triggered = await page.evaluate(
      (qualificationNonce) =>
        globalThis.__BRIDGEFU_RECIPE_QUALIFICATION__?.markServerHandoffTriggered(qualificationNonce) ?? false,
      nonce,
    );
    if (!triggered) fail("Bridgefu server handoff marker was not accepted exactly once");
    const dtmfSent = await page.evaluate(
      (qualificationNonce) =>
        globalThis.__BRIDGEFU_RECIPE_QUALIFICATION__?.sendDtmf(qualificationNonce, "9") ?? false,
      nonce,
    );
    if (!dtmfSent) fail("Bridgefu browser DTMF was not accepted");
    try {
      await waitUntil(
        async () => {
          const probe = await probeSnapshot(page);
          return (
            probe?.agentMarkerObservedAtMs.length >= 5 &&
            probe.agentMarkerFrames >= 5 &&
            probe.dtmfAgentToSourceObserved &&
            probe.remoteAudioTracks > 0 &&
            probe.audioPacketsSent > 5 &&
            probe.audioBytesSent > 0
          );
        },
        Math.min(timeoutMs, 120_000),
        "Bridgefu browser media observations did not converge",
      );
    } catch {
      const probe = await probeSnapshot(page);
      fail(
        "Bridgefu browser media observations did not converge "
        + `markers=${probe?.agentMarkerObservedAtMs.length ?? 0} `
        + `frames=${probe?.agentMarkerFrames ?? 0} `
        + `dtmf=${probe?.dtmfAgentToSourceObserved === true ? 1 : 0} `
        + `tracks=${probe?.remoteAudioTracks ?? 0} `
        + `sent_packets=${probe?.audioPacketsSent ?? 0} `
        + `sent_bytes=${probe?.audioBytesSent ?? 0} `
        + `received_packets=${probe?.audioPacketsReceived ?? 0} `
        + `received_bytes=${probe?.audioBytesReceived ?? 0} `
        + `active_frames=${probe?.remoteAudioActiveFrames ?? 0} `
        + `max_rms=${Number(probe?.remoteAudioMaxRms ?? 0).toFixed(6)}`,
      );
    }
    let localEndCompleted = false;
    let remoteEndObserved = false;
    if (hangupOrigin === "source") {
      const ended = await page.evaluate(
        (qualificationNonce) =>
          globalThis.__BRIDGEFU_RECIPE_QUALIFICATION__?.endFromSource(qualificationNonce) ?? false,
        nonce,
      );
      if (!ended) fail("Bridgefu browser could not originate hangup");
      localEndCompleted = true;
    }
    await waitUntil(
      async () => (await applicationSnapshot(page, nonce))?.callEndObserved === true,
      Math.min(timeoutMs, 60_000),
      "Bridgefu browser did not observe terminal cleanup",
    );
    if (hangupOrigin === "agent") remoteEndObserved = true;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 1000));
    const application = await applicationSnapshot(page, nonce);
    if (!application?.callEndObserved) fail("Bridgefu browser cleanup was not stable");
    const probe = await probeSnapshot(page);
    const observedAtMs = Date.now();
    const sourceMarkers = sourceMarkerSchedule(
      probe.captureRequestedAtMs,
      triggerAtMs,
      observedAtMs,
    );
    const sourceDtmfSentAtMs = sourceDtmfSchedule(
      probe.captureRequestedAtMs,
      triggerAtMs,
      observedAtMs,
    );
    if (
      sourceMarkers.length < 5 ||
      sourceDtmfSentAtMs.length < 1 ||
      probe.agentMarkerObservedAtMs.length < 5 ||
      probe.agentMarkerFrames < 5 ||
      !probe.dtmfAgentToSourceObserved
    ) {
      fail("Bridgefu browser final media evidence is incomplete");
    }
    exclusiveJson(observationPath, {
      schema_version: 1,
      producer: PRODUCER,
      producer_revision_sha256: sha256File(fileURLToPath(import.meta.url)),
      site_bundle_sha256: siteBundleSha256,
      browser_sdk_name: SDK_NAME,
      browser_sdk_version: SDK_VERSION,
      execution_id: session.execution_id,
      scenario_id: session.scenario_id,
      hangup_origin: session.hangup_origin,
      correlation_fingerprint: session.correlation_fingerprint,
      source_call_fingerprint: sourceCallFingerprint,
      observed_at: new Date(observedAtMs).toISOString(),
      bridgefu: {
        webrtc_call_started: true,
        server_handoff_triggered: true,
        call_end_observed: true,
      },
      media: {
        codec: "negotiated",
        security: "srtp",
        source_marker_sent_at_ms: sourceMarkers.slice(0, 32),
        dtmf_source_to_agent_sent_at_ms: sourceDtmfSentAtMs,
        agent_marker_observed_at_ms: probe.agentMarkerObservedAtMs.slice(0, 16),
        source_to_agent_marker_frames_sent: sourceMarkers.length * 5,
        agent_to_source_marker_frames: probe.agentMarkerFrames,
        dtmf_agent_to_source_observed: probe.dtmfAgentToSourceObserved,
      },
      hangup: {
        origin: session.hangup_origin,
        local_end_completed: localEndCompleted,
        remote_end_observed: remoteEndObserved,
        cleanup_observed: true,
      },
      redacted: true,
    });
  } finally {
    await browser.close();
    await site.close();
    rmSync(probePath, { force: true });
  }
}

async function main() {
  const [command, ...values] = process.argv.slice(2);
  if (command !== "observe") fail("expected observe command");
  await observe(parseOptions(values));
}

main().catch((error) => {
  process.stderr.write(`error: ${error instanceof HarnessError ? error.message : "Bridgefu browser observer failed"}\n`);
  process.exitCode = 1;
});
