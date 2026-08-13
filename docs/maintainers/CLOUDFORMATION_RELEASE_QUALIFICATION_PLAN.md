# Bridgefu Vapi → Amazon Connect CloudFormation Release Plan

## Objective

Produce a production CloudFormation template that a Vapi customer can launch in
their AWS account to deploy:

- Bridgefu on EC2.
- The Bridgefu VPC, networking, TLS certificate, and DNS records.
- DynamoDB call-context storage.
- Handoff, transfer, and Amazon Connect lookup Lambdas.
- Amazon Connect wrapper flow and screen-pop integration.
- A new Bridgefu Vapi template assistant, tool, and webhook credential.
- CloudWatch logs, metrics, alarms, and dashboard.

The release is not complete until the exact published template and AMIs have
passed both live call paths in Oregon and Virginia:

```text
rvoip SIP client → Vapi → Bridgefu → Amazon Connect
Bridgefu Web SDK → Vapi → Bridgefu → Amazon Connect
```

## Why the release process is staged

The full release workflow must not be used to discover ordinary build, AWS,
Vapi, browser, SIP, or test-harness defects. Each boundary is proven separately
and in order. A later stage cannot run until the earlier stage passes.

When a stage fails:

1. Stop at that stage.
2. Preserve the minimum safe diagnostic environment and redacted evidence.
3. Determine the exact root cause.
4. Add a regression test.
5. Rerun that stage only.

Do not rebuild two AMIs, deploy two regions, and execute the whole publication
pipeline merely to inspect one Vapi call failure.

## Repository responsibilities

### `bridgefu`

Owns the Bridgefu runtime:

- SIP/TLS and RTP/SRTP behavior.
- Vapi-to-Bridgefu call admission.
- One-use route handling.
- Correlation-header handling.
- Amazon Connect call bridging.
- Redacted signaling and negotiated-media evidence.
- Exact crates.io `rvoip = 0.3.7` dependency.

### `bridgefu-vapi-awsconnect`

Owns the AWS distribution:

- Packer AMI build.
- Product and qualification CloudFormation templates.
- Lambda code and deterministic Lambda packaging.
- Vapi assistant/tool/credential provisioning.
- Screen-pop schema and Connect integration.
- Release buckets, signing, publication, and Quick Create link.
- Direct secure probe and both end-to-end smoke tests.
- Cleanup and zero-resource verification.

## Stage 1 — Local contract gate

Prove the code and generated artifacts before any AWS deployment.

### Bridgefu runtime

- Run formatting, Clippy, and all Rust tests.
- Verify every rvoip dependency is exactly version `0.3.7` from crates.io.
- Test the SIP security matrix:
  - `sips_srtp`: TLS signaling and SRTP media required.
  - `sips_optional_srtp`: TLS signaling required; accept SRTP when offered and
    allow RTP/AVP only when the peer does not offer SRTP.
  - `sip_rtp`: plain SIP/RTP allowed only in disposable `TestDelete` tests.
- Test URI scheme and observed transport independently. A URI string alone
  cannot prove TLS.
- Test SDP profiles, SDES suites, installed send/receive SRTP contexts, ACK,
  audio, DTMF, BYE, and cleanup.
- Test that runtime evidence contains only closed, redacted protocol facts.

### Lambda and Vapi provisioning

- Test context storage before transfer.
- Test deterministic correlation IDs, one-use routes, idempotency, replay,
  conflict handling, expiry, and DynamoDB schema compatibility.
- Test configurable field validation and ordered screen-pop rendering.
- Test Vapi ownership and create/update/delete behavior.
- Test the complete Vapi failure matrix:
  - Bounded GET retries for 429, 5xx, and transport failures.
  - Bounded `Retry-After` handling.
  - POST reconciliation after ambiguous responses.
  - PATCH reread and desired-state verification.
  - DELETE ownership verification and absence polling.
  - Immediate, exact failure categories for 400, 401, 403, 409, and 422.
- Logs may contain operation, resource type, HTTP status, attempt, and result
  category. They may not contain API keys, response bodies, prompts, webhook
  tokens, SIP route tokens, or customer data.

### Qualification harness

- Test the Rust SIP source, direct secure probe, Web SDK driver, and Amazon
  Connect Agent Workspace observer.
- Render every SSM command exactly as AWS receives it.
- Run `bash -n` over every generated SSM command.
- Test browser readiness before starting either call source.
- Test timeout, cancellation, retain-on-failure, restoration, and cleanup.
- Test machine-readable SIP/SDP trace redaction.

### Packaging and templates

- Build Lambda ZIPs twice and prove byte-for-byte deterministic output.
- Build the qualification Web assets deterministically.
- Run Python, Rust, Node, Ruff, shell, and policy checks.
- Run `cfn-lint` against product, nested, qualification, and publisher
  templates.
- Run `packer validate` using the pinned Bridgefu commit and Cargo.lock digest.

### Exit condition

All local tests, deterministic packaging checks, CloudFormation lint checks,
and Packer validation pass from clean commits.

## Stage 2 — Remote CloudFormation validation gate

Validate AWS syntax and template contracts without deploying infrastructure.

1. Build private, immutable diagnostic artifacts under a unique diagnostic build
   identifier. Do not reserve a release version.
2. Upload the Lambda ZIPs and templates privately.
3. Bind nested template and Lambda references to exact S3 VersionIds.
4. Run AWS `ValidateTemplate` against every exact root and nested template in:
   - `us-west-2`
   - `us-east-1`
5. Validate the exact template URLs, not only local files.

### Exit condition

AWS accepts every exact template and URL in both supported regions. No stack,
AMI publication, release tag, or `latest` pointer is created.

## Stage 3 — Retained Oregon diagnostic gate

Deploy one disposable Oregon environment and keep it running while diagnosing
the full call path. This is the only debugging environment.

### Environment

Deploy the exact customer template plus qualification-only resources with:

- Region: `us-west-2`.
- `DataRetentionMode=TestDelete`.
- One disposable Amazon Connect instance and published flow.
- One Bridgefu EC2 instance.
- One DynamoDB table and the production Lambdas.
- Public SIP DNS and certificate.
- Qualification-only private split-horizon DNS for the same-instance probe.
- One stack-owned Vapi template assistant and its exact owned resources.
- Retain-on-failure enabled.

Do not deploy Virginia and do not create a release candidate.

### 3.1 Direct secure Bridgefu control

Run the direct rvoip probe without Vapi and require:

- SIPS Request-URI.
- An actual accepted TLS connection.
- SDP `RTP/SAVP` and a supported SDES `a=crypto` suite.
- Installed inbound and outbound SRTP contexts.
- SIP 200 and ACK.
- Connected Amazon Connect contact.
- Bidirectional audio and required DTMF.
- Clean hangup and complete runtime restoration.

This proves Bridgefu and crates.io rvoip 0.3.7 can negotiate and carry secure
media through the real AWS runtime.

### 3.2 Vapi URI and SDP A/B test

Use the same Vapi organization, assistant, Bridgefu instance, DNS hostname, and
machine-readable TLS SIP proxy. Run sequential calls with fresh one-use routes:

```text
sips:<route>@<host>:5061;transport=tls
sip:<route>@<host>:5061;transport=tls
```

Do not rebuild the AMI or redeploy the environment between calls. Vary only the
destination URI returned to Vapi. Any diagnostic override must be scoped to
the owned test resources, restored exactly, and followed by a drift check.

For each call, save a redacted machine-readable trace containing:

- Vapi transfer request and terminal call result.
- Whether Vapi established a destination TCP/TLS connection.
- Negotiated TLS version and certificate-verification result.
- SIP message sequence and response statuses.
- INVITE URI scheme and transport parameter with route and target redacted.
- SDP media profile.
- SDES crypto-line count and recognized suite names.
- DTLS fingerprint and setup presence.
- SIP 200, ACK, media establishment, BYE, and cleanup.

### Decision

- If `sips:` works, keep `sips:` and investigate the earlier failure elsewhere.
- If `sips:` fails before a destination call but
  `sip:...;transport=tls` creates a verified TLS connection, use the latter in
  optional-SRTP mode.
- If `sip:...;transport=tls` does not actually use TLS, stop. Do not ship it.
- If Vapi offers `RTP/SAVP`, Bridgefu must negotiate SRTP.
- If Vapi offers only `RTP/AVP` over verified TLS, Bridgefu may accept it only
  in optional-SRTP mode.
- If the evidence is ambiguous, improve the trace and repeat this stage. Do not
  infer a product contract.

### 3.3 End-to-end smoke: rvoip SIP source

Run:

```text
rvoip SIP client → Vapi → Bridgefu → Amazon Connect
```

Prove:

- Vapi assistant and temporary SIP endpoint ownership.
- Context stored before transfer.
- Exactly one correlation header.
- Actual TLS signaling at Bridgefu.
- SDP/media posture allowed by the selected security mode.
- SIP answer, ACK, and established media.
- Amazon Connect `correlation_id` attribute.
- Successful DynamoDB lookup and ordered screen-pop fields.
- Audio in both directions.
- Source-to-agent DTMF.
- Correct source and agent hangup.
- Successful terminal Vapi call state.

### 3.4 End-to-end smoke: Bridgefu Web SDK source

Run:

```text
Bridgefu Web SDK → Vapi → Bridgefu → Amazon Connect
```

Prove the same items as the SIP-source smoke plus agent-to-source DTMF.

The two sources run sequentially against the same retained environment.

### 3.5 Vapi provisioning resilience

- Delete the exact stack-owned Vapi assistant, tool, and credential.
- Recreate them with the same deterministic configuration.
- Repeat create/delete/recreate.
- Prove no duplicate or unrelated Vapi resource is created, modified, or
  deleted.
- Exercise an ambiguous-write reconciliation case and prove exact adoption or
  fail-closed behavior.

### 3.6 Cleanup

After both smoke tests pass:

- Delete temporary Vapi phone and authentication resources.
- Delete the qualification root stack and all nested stacks.
- Delete only exact stack-owned ACM validation records.
- Delete qualification S3 object versions and delete markers.
- Prove absence of Connect, EC2, EBS, ENIs, VPC, endpoints, DynamoDB, Lambdas,
  API Gateway, ACM, private DNS, alarms, logs, and Vapi resources.
- Save a redacted zero-resource receipt.

### Exit condition

The direct secure control, URI/SDP A/B test, both end-to-end sources, repeated
Vapi provisioning, and complete teardown all pass in Oregon.

## Stage 4 — Finalize the product from observed behavior

Only now apply the URI and media behavior proven in Oregon.

If the A/B result proves the expected compatibility contract:

- `sips_optional_srtp` returns:

  ```text
  sip:<one-use-route>@<host>:5061;transport=tls
  ```

- `sips_srtp` returns:

  ```text
  sips:<one-use-route>@<host>:5061;transport=tls
  ```

- `sip_rtp` remains disposable-test-only plain SIP/RTP.
- Bridgefu accepts `sip:` only in optional mode and only on an observed TLS
  transport.
- Bridgefu negotiates SRTP whenever Vapi offers `RTP/SAVP`.
- Bridgefu accepts `RTP/AVP` only in optional mode.
- URI scheme, signaling transport, SDP profile, keying, suite, contexts, and
  answer state are independently recorded in redacted evidence.
- CIDR admission, one-use routes, correlation validation, and exact Contact
  behavior remain unchanged.

Merge and pin in this order:

1. Merge the tested Bridgefu runtime change.
2. Record the exact Bridgefu main-branch commit and Cargo.lock SHA-256.
3. Update `bridgefu.lock.json` in the AWS distribution.
4. Merge the tested distribution change.

Run Stages 1 and 2 again against the final merged commits.

## Stage 5 — Fresh Oregon release qualification

Build the first immutable release candidate only after the retained Oregon
diagnostic passes.

1. Build the ARM64 AMI from the pinned Bridgefu commit.
2. Package deterministic Lambdas and templates.
3. Upload every private object under its final immutable release key.
4. Bind all template and Lambda references to exact S3 VersionIds.
5. Run remote `ValidateTemplate` again.
6. Deploy a fresh Oregon environment from those exact immutable bits.
7. Run the direct secure preflight and both end-to-end smoke tests.
8. Destroy the environment and prove zero resources.

If this stage fails, stop in Oregon. Do not run Virginia.

## Stage 6 — Fresh Virginia release qualification

After Oregon passes:

1. Copy the same private AMI to `us-east-1`.
2. Use the same immutable templates, Lambda objects, and source commits.
3. Run the identical direct secure preflight and both smoke tests.
4. Destroy the environment and prove zero resources.

Oregon and Virginia must never provision Vapi resources concurrently.

## Stage 7 — Seal the candidate

- Verify evidence schema and every required boolean independently.
- Verify exact scenario IDs for the SIP and Web SDK sources.
- Verify zero-resource receipts from both regions.
- Verify exact AMI IDs, snapshot IDs, S3 keys, VersionIds, hashes, and source
  commits.
- Sign the manifest and dual-region qualification receipt with KMS.
- Keep AMIs, snapshots, and S3 artifacts private.

## Stage 8 — Publish the customer release

1. Review the signed receipt and evidence.
2. Tag the exact qualified distribution commit.
3. Verify the tag version exactly matches the qualified template version.
4. Make the two AMIs and backing snapshots public.
5. Publish the immutable Lambda, nested-template, root-template, manifest, and
   signature objects.
6. Publish the root template last.
7. Update `latest` manifest, signature, template, and Quick Create link last.
8. Verify a customer account can read the template and launch the referenced
   regional AMI.

## Shareable release artifacts

The customer release contains:

- Immutable versioned CloudFormation template URL.
- `latest` CloudFormation template URL.
- AWS Quick Create link that lets the customer choose Oregon or Virginia in the
  CloudFormation console.
- Public ARM64 AMI in both supported regions.
- Versioned Lambda and nested-template objects.
- SHA-256 manifest and KMS signature.
- Signed dual-region qualification receipt.
- Deployment, configuration, monitoring, update, detach, and uninstall guide.

## Release acceptance criteria

The CloudFormation template is production-ready only when both source paths pass
in both regions and prove:

- Exact Vapi resource ownership.
- Context stored before transfer.
- One correlation header.
- Actual TLS signaling.
- Media posture consistent with the selected policy.
- SIP answer, ACK, and established media.
- Amazon Connect contact and correlation attribute.
- DynamoDB lookup and ordered screen pop.
- Bidirectional audio.
- Required DTMF.
- Correct hangup.
- Successful terminal Vapi state.
- Complete teardown and zero-resource evidence.

No release version is published, and no `latest` pointer is updated, until every
acceptance criterion passes.
