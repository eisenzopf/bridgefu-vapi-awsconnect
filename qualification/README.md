# Release smoke tests

These tests qualify the AMIs and CloudFormation templates built by this
repository. They are maintainer release gates, not customer deployment steps.

Both tests create a fresh disposable Amazon Connect instance and a new Vapi
template assistant, connect a call to the generated Connect agent, verify the
screen pop, audio in both directions, and deterministic in-band DTMF, and then
remove the environment. The controller selects the exact disposable agent's
routable `Available` status through the Amazon Connect API before each call.

1. `vapi-sip-transfer`: a controlled SIP client calls a temporary Vapi SIP URI.
2. `bridgefu-web-sdk-handoff`: a browser attaches through
   `@bridgefu/webrtc-browser`, Bridgefu calls a dedicated Vapi SIP assistant,
   and a trusted server-side request replaces that Vapi leg with Connect.

The SDK is not copied into this repository. Before AWS credentials are read,
the qualification build fetches the pinned Bridgefu source, verifies its commit
and Cargo lock digest, builds `sdk/typescript` from its own npm lock, and seals
the SDK and site digests into the demo manifest. This path never imports
`@vapi-ai/web` or starts a Vapi `webCall`. The smoke controller and evidence
contracts live here because they are specific to this CloudFormation release.

Before either Vapi smoke, the controller runs one direct secure preflight
against the fresh candidate host. A separate, session-free Agent Workspace
observer proves the sole contact was auto-accepted, remote audio and outbound
RTP were present, and the remote hangup cleaned up. The preflight reserves its
own one-use Bridgefu route and requires SIPS over TLS with RTP/SAVP,
SDES-SRTP contexts, and exactly one correlation header. It is a prerequisite,
not a third scenario, and it does not call Vapi.

The controller uploads only the supplied static `--direct-secure-probe` binary
to a unique qualification prefix. The host verifies its SHA-256 before use;
the route URI, correlation value, and local bearer remain in remote memory.
The disposable stack creates an exact-name Route53 private hosted zone in the
Bridgefu VPC. The public SIP name still resolves to the EIP for Vapi, while the
same name resolves to the instance private address for this same-host probe.
The guarded test window therefore rewrites only the SDP media address; it does
not alter `/etc/hosts` or the TLS advertised address. The production runtime
must advertise a DNS `sips:` Contact with `transport=tls`; the probe fails
unless it observes that Contact, the 200 response, the subsequent ACK, and an
exact private-DNS resolution. Both the command trap and a separate
controller-owned cleanup restore byte-exact runtime configuration, remove the
run directory, and prove Bridgefu active and ready before Vapi credentials are
read. Stack deletion owns the private zone and the zero-resource proof confirms
that hosted zone is gone.

The two Vapi scenarios then exercise the candidate's
`sips_optional_srtp` policy. Each scenario must prove SIPS/TLS and an exact,
internally consistent media posture from Bridgefu's correlated runtime event.
Evidence records `RTP/SAVP` + `SDES-SRTP` + the negotiated suite when Vapi
offers SRTP, or `RTP/AVP` + `none` when Vapi offers only clear RTP. The latter
is an explicit compatibility result, never reported as SRTP. The strict direct
preflight remains mandatory in either case, proving the same candidate accepts
and establishes a correct SDES-SRTP offer before any Vapi smoke begins.

No smoke may accept an existing Amazon Connect instance ARN. A successful run
must finish with evidence that its disposable Connect instance, customer stack,
temporary Vapi resources, test credentials, and qualification S3 objects are
absent.

The controller does not use a Vapi web call for the SIP test. It creates a
temporary Vapi SIP URI and runs the statically linked `rvoip-sip = 0.3.7`
client on the candidate Bridgefu host. The Web SDK test is a separate call.

## Run it

Use the **Remote live qualification** GitHub workflow for an already uploaded
candidate. Choose `us-west-2` unless the release specifically needs an East
region compatibility run. The protected `live-qualification` environment must
provide:

- `AWS_QUALIFICATION_ROLE_ARN`
- `AWS_QUALIFICATION_CLOUDFORMATION_ROLE_ARN`
- `VAPI_API_KEY_SECRET_ARN`
- `PUBLIC_HOSTED_ZONE_ID`
- `PUBLIC_HOSTED_ZONE_NAME`
- the Vapi private API key secret ARN; no Vapi browser/public key is used

The controller keeps the Vapi private key and generated Connect password only
in process memory. Retained evidence contains hashes, fixed synthetic values,
counts, timestamps, and resource-absence booleans.

Normal tagged releases run the same controller automatically. Candidate AMIs
stay private and `latest` is not updated until both calls and teardown pass.
Failed candidates are deregistered and their versioned staging objects removed.
CloudFormation rollback is held only until a bounded, redacted failure record
has been written to `failure-evidence.json`, including bounded nested-stack
events without emitting the API's physical-ID fields. Failed disposable stacks
are then deleted unless the run was explicitly started with
`--retain-on-failure`.
