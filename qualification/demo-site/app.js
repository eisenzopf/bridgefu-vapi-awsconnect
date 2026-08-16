import {
  BridgefuWebRtcClient,
  normalizeBridgefuRouteAttachment,
} from "@bridgefu/webrtc-browser";

const elements = {
  status: document.querySelector("#status"),
  transcript: document.querySelector("#transcript"),
  start: document.querySelector("#start"),
  mute: document.querySelector("#mute"),
  end: document.querySelector("#end"),
  remote: document.querySelector("#remote-audio"),
};

const safeState = {
  recipe: "vapi-amazon-connect-screen-pop@1",
  sdk: "@bridgefu/webrtc-browser",
  status: "loading",
  callStartObserved: false,
  callEndObserved: false,
  remoteAudioTracks: 0,
  handoffStates: [],
  errorType: null,
  peerConnectionState: "new",
  iceConnectionState: "new",
  iceGatheringState: "new",
  signalingState: "stable",
};
window.__BRIDGEFU_RECIPE_TEST__ = safeState;

let client;
let attachment;
let muted = false;
let qualification;

function setStatus(status, text) {
  safeState.status = status;
  elements.status.textContent = text;
}

function safeErrorType(value) {
  const normalized = String(value ?? "unknown").toLowerCase();
  return /^[a-z0-9._-]{1,64}$/.test(normalized) ? normalized : "unknown";
}

function capturePeerStates() {
  const peer = client?.peerConnection;
  if (!peer) return;
  const allowed = {
    peerConnectionState: new Set([
      "new", "connecting", "connected", "disconnected", "failed", "closed",
    ]),
    iceConnectionState: new Set([
      "new", "checking", "connected", "completed", "disconnected", "failed", "closed",
    ]),
    iceGatheringState: new Set(["new", "gathering", "complete"]),
    signalingState: new Set([
      "stable", "have-local-offer", "have-remote-offer", "have-local-pranswer",
      "have-remote-pranswer", "closed",
    ]),
  };
  const observed = {
    peerConnectionState: peer.connectionState,
    iceConnectionState: peer.iceConnectionState,
    iceGatheringState: peer.iceGatheringState,
    signalingState: peer.signalingState,
  };
  for (const [name, values] of Object.entries(allowed)) {
    const value = observed[name];
    if (values.has(value)) safeState[name] = value;
  }
}

function validQualificationNonce(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(value);
}

function installQualificationControl(config) {
  if (
    !validQualificationNonce(config.qualification_nonce)
    || !["source", "agent"].includes(config.qualification_hangup_origin)
  ) return;
  const state = {
    serverHandoffTriggered: false,
    sourceEndRequested: false,
  };
  qualification = state;
  const authorize = (nonce) => nonce === config.qualification_nonce;
  window.__BRIDGEFU_RECIPE_QUALIFICATION__ = Object.freeze({
    snapshot(nonce) {
      if (!authorize(nonce)) return null;
      capturePeerStates();
      return {
        callId: attachment?.callId ?? null,
        serverHandoffTriggered: state.serverHandoffTriggered,
        sourceEndRequested: state.sourceEndRequested,
        callStartObserved: safeState.callStartObserved,
        callEndObserved: safeState.callEndObserved,
        handoffStates: [...safeState.handoffStates],
        status: safeState.status,
        errorType: safeState.errorType,
        peerConnectionState: safeState.peerConnectionState,
        iceConnectionState: safeState.iceConnectionState,
        iceGatheringState: safeState.iceGatheringState,
        signalingState: safeState.signalingState,
      };
    },
    markServerHandoffTriggered(nonce) {
      if (!authorize(nonce) || state.serverHandoffTriggered) return false;
      state.serverHandoffTriggered = true;
      return true;
    },
    sendDtmf(nonce, digits) {
      if (!authorize(nonce) || client?.state !== "connected" || digits !== "9") return false;
      client.sendDtmf(digits);
      return true;
    },
    async endFromSource(nonce) {
      if (!authorize(nonce) || !client || state.sourceEndRequested) return false;
      state.sourceEndRequested = true;
      await client.disconnect();
      return true;
    },
  });
}

function connectEvents(value) {
  value.on("state", ({ state }) => {
    if (state === "connected") {
      safeState.callStartObserved = true;
      setStatus("active", "Bridgefu call connected");
      elements.start.disabled = true;
      elements.mute.disabled = false;
      elements.end.disabled = false;
    } else if (state === "closed") {
      safeState.callEndObserved = true;
      setStatus("ended", "Bridgefu call ended");
      elements.start.disabled = true;
      elements.mute.disabled = true;
      elements.end.disabled = true;
    }
  });
  value.on("handoff", ({ status }) => {
    if (safeState.handoffStates.at(-1) !== status && safeState.handoffStates.length < 32) {
      safeState.handoffStates.push(status);
    }
  });
  value.on("remoteTrack", ({ event }) => {
    if (event.track?.kind === "audio") safeState.remoteAudioTracks += 1;
  });
  value.on("error", ({ error }) => {
    safeState.errorType = safeErrorType(error?.code ?? error?.name);
    setStatus("failed", "The Bridgefu test call could not continue.");
    elements.start.disabled = true;
    elements.mute.disabled = true;
    elements.end.disabled = true;
  });
}

async function load() {
  try {
    const response = await fetch("./config.json", {
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    });
    if (!response.ok) throw new Error("configuration-unavailable");
    const config = await response.json();
    if (
      config?.schema_version !== 2
      || config?.recipe !== safeState.recipe
      || typeof config?.route_attachment !== "object"
      || typeof config?.route_binding !== "object"
    ) {
      throw new Error("configuration-invalid");
    }
    attachment = normalizeBridgefuRouteAttachment(
      config.route_attachment,
      config.route_binding,
    );
    client = new BridgefuWebRtcClient({
      remoteAudioElement: elements.remote,
      connectTimeoutMs: 30_000,
      disconnectGraceMs: 2_000,
    });
    connectEvents(client);
    installQualificationControl(config);
    setStatus("ready", "Ready for a synthetic Bridgefu call");
    elements.start.disabled = false;

    elements.start.addEventListener("click", async () => {
      elements.start.disabled = true;
      safeState.errorType = null;
      setStatus("starting", "Attaching to Bridgefu…");
      try {
        await client.connect(attachment);
      } catch (error) {
        safeState.errorType = safeErrorType(error?.code ?? error?.name ?? "connect-failed");
        setStatus("failed", "Bridgefu call start failed.");
      }
    });

    elements.mute.addEventListener("click", () => {
      muted = !muted;
      for (const sender of client.peerConnection?.getSenders() ?? []) {
        if (sender.track?.kind === "audio") sender.track.enabled = !muted;
      }
      elements.mute.textContent = muted ? "Unmute" : "Mute";
    });
    elements.end.addEventListener("click", async () => client.disconnect());
  } catch (error) {
    safeState.errorType = safeErrorType(error?.message ?? "load-failed");
    setStatus("failed", "Test configuration is unavailable.");
  }
}

window.addEventListener("pagehide", () => {
  delete window.__BRIDGEFU_RECIPE_QUALIFICATION__;
  void client?.disconnect().catch(() => {});
});

void load();
