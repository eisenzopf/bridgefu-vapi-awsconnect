# CloudFormation Release Qualification Status

This is the living execution ledger for
[CLOUDFORMATION_RELEASE_QUALIFICATION_PLAN.md](CLOUDFORMATION_RELEASE_QUALIFICATION_PLAN.md).
The plan defines the required process. This file records what has actually
happened.

## Status rules

- Update this file after every material implementation, test, failure, root
  cause, deployment, cleanup, gate transition, commit, and pull-request change.
- Record only evidence-backed results.
- `PASSED` means every exit condition for that stage has passed against the
  exact identified source and artifacts.
- `PARTIAL` means useful checks passed but the stage exit condition has not.
- `BLOCKED` means a named condition prevents progress.
- `NOT STARTED` means no qualifying execution has begun.
- A result from speculative or superseded source does not qualify final release
  source.
- Never silently erase a failure. Append it to the execution history with its
  root cause and disposition.

## Current summary

| Item | Current state |
|---|---|
| Active stage | **Stage 4 — freeze locally proven source and repeat remote template validation** |
| Overall qualification | **IN PROGRESS** |
| New Oregon diagnostic environment | **RETAINED / CREATE_COMPLETE** — `bridgefu-bfq-d19854f1-1` |
| New Virginia qualification | **NOT STARTED** |
| Release candidate | **NOT CREATED** |
| Reserved release version | **NONE** |
| Customer-visible `latest` pointer | **NOT CREATED** |
| Publication | **NOT STARTED** |
| Vapi SIP/SDP A/B | **PASSED** — optional mode uses `sip:...;transport=tls` over observed TLS with RTP/AVP |
| Direct mandatory-SRTP control | **PASSED** — SIPS/TLS plus RTP/SAVP/SDES-SRTP |
| Prior Web smoke | **INVALID / SUPERSEDED** — used stock `@vapi-ai/web`, not Bridgefu's SDK |
| Next permitted AWS action | No new deployment; reuse retained Oregon only after the corrected local SDK gate passes |

## Source under evaluation

### Bridgefu runtime

| Field | Value |
|---|---|
| Repository | `eisenzopf/bridgefu` |
| Local worktree | `/Users/jonathan/Developer/bridgefu-main-clean` |
| Branch | `codex/vapi-tls-rtp-evidence` |
| Commit | `2fb2eaede9420c7d6980c5e0cfeb74eb786a2add` |
| Local delta | None; outbound Bridgefu-to-Vapi redacted security evidence is committed and pushed |
| Pull request | [bridgefu#4](https://github.com/eisenzopf/bridgefu/pull/4) |
| PR state at last update | Open, not merged |
| Dependency posture | Exact crates.io `rvoip = 0.3.7`; no local rvoip dependency |

The Oregon Vapi A/B test selected the optional-mode URI/media contract for this
Bridgefu change. It remains unqualified product behavior until the corrected
Bridgefu Web SDK smoke, SIP-source smoke, final local/remote validation rerun,
and fresh regional qualifications pass.

### AWS distribution

| Field | Value |
|---|---|
| Repository | `eisenzopf/bridgefu-vapi-awsconnect` |
| Local worktree | `/Users/jonathan/Developer/bridgefu-vapi-awsconnect` |
| Branch | `codex/staged-vapi-qualification` |
| Implementation commit | `19854f1` |
| Local delta | Correct Bridgefu Web SDK orchestration, direct handoff/runtime resources, qualification evidence, and live Vapi resilience gate; complete local gate passed, commit/push is next |
| Pull request | [bridgefu-vapi-awsconnect#26](https://github.com/eisenzopf/bridgefu-vapi-awsconnect/pull/26) |
| PR state at last update | Draft, open, not merged |

The distribution branch contains the candidate optional-mode URI behavior,
scheme-aware qualification checks, Vapi retry/reconciliation diagnostics, and
sequential Oregon-then-Virginia workflow structure. These changes remain under
evaluation until Stage 3 proves the live contract.

## Stage status

### Stage 1 — Local contract gate: PASSED

Completed against the source commits above:

- [x] Distribution Python unit suite: **257 passed**.
- [x] Bridgefu scheme-aware security-evidence suite: **16 passed**.
- [x] Bridgefu full local Rust suite completed without failures.
- [x] Direct secure probe suite: **16 passed**.
- [x] Qualification SIP-client suite: **4 passed**.
- [x] Rust formatting and Clippy passed for the changed Bridgefu code.
- [x] Ruff and Python compilation checks passed.
- [x] Browser driver JavaScript syntax checks passed.
- [x] Exact pinned Bridgefu Web SDK package suite: **20 passed**.
- [x] Deterministic Lambda packaging passed.
- [x] `cfn-lint` passed for rendered product, nested, qualification, and
  publisher templates.
- [x] Candidate workflow changed from parallel regional qualification to
  sequential Oregon then Virginia.
- [x] Vapi API tests cover bounded GET retry, bounded `Retry-After`, ambiguous
  POST reconciliation, PATCH reread, DELETE absence verification, collision
  failure, exact HTTP status categories, and response-body redaction.

Still required before Stage 1 is `PASSED`:

- [x] Every controller SSM dispatch uses one bounded JSON command-array encoder.
- [x] Exact decoded command arrays pass `bash -n`; probe, cleanup, SDP capture,
  runtime readiness, and SIP-source programs have focused coverage.
- [x] Complete all GitHub checks for Bridgefu PR #4: infrastructure, full test,
  ARM64 image, AMD64 image, and Trivy passed.
- [x] Distribution PR #26 CI run `31662616227` passed all three jobs against
  the exact current implementation source.
- [x] Packer 1.12.0 validation passed locally and in the prior CI validation
  job; the authoritative current-commit CI rerun remains required.
- [x] The complete gate was repeated after the corrected Bridgefu Web SDK
  harness and live Vapi resilience implementation were finalized locally.
- [ ] Repeat the affected gate once more after the Bridgefu evidence commit is
  pushed and the distribution lock is repinned to its immutable hash.

### Stage 2 — Remote CloudFormation validation: PASSED

Completed against distribution commit
`19854f1fb4fd2a48571584a5a628067952ebf585`:

- [x] Rendered product, nested, qualification, and publisher templates.
- [x] AWS `ValidateTemplate` accepted every rendered template in `us-west-2`.
- [x] AWS `ValidateTemplate` accepted every rendered template in `us-east-1`.
- [x] No CloudFormation stack was created by this validation.

Still required before Stage 2 is `PASSED`:

- [x] Uploaded 25 private diagnostic objects with exact S3 VersionIds under
  `diagnostics/bfq-d19854f1-1/` and journaled each version.
- [x] Validated 10 exact versioned template URLs in both supported regions.
- [ ] Repeat all remote validation against the final source selected after the
  retained Oregon smokes; this is a Stage 4 requirement and does not invalidate the
  current diagnostic-source Stage 2 pass.

Stage 2 preflight evidence gathered without writing AWS resources:

- [x] AWS identity reverified as account `225478700523` using the authorized
  `vapi-admin` profile.
- [x] The Oregon and Virginia artifact buckets both have S3 versioning enabled.
- [x] Bucket policy inspection confirms that an untagged unique
  `diagnostics/...` prefix remains private; public reads are scoped to
  publication-tagged `releases/...` and `latest/...` objects.

### Stage 3 — Retained Oregon diagnostic: IN PROGRESS

- [x] Zero-state audit immediately before deployment passed for exact execution
  `bfq-d19854f1-1`.
- [x] Deploy one retained `TestDelete` Oregon diagnostic environment. Root stack
  `bridgefu-bfq-d19854f1-1` reached `CREATE_COMPLETE`; all nested stacks,
  runtime health, the qualification-only split-horizon private SIP record, and
  ACM validation completed without a failed or rollback event.
- [x] Run direct Bridgefu secure control. After correcting the missing pinned
  browser prerequisite, the retained control passed all 24 evidence checks and
  proved SIPS/TLS, RTP/SAVP, SDES-SRTP contexts, INVITE 200/ACK, secure Contact,
  Amazon Connect delivery/media, hangup, and exact runtime restoration.
- [x] Run Vapi `sips:` versus `sip:...;transport=tls` A/B trace.
- [x] Select the diagnostic URI/media contract from observed evidence:
  optional-SRTP returns `sip:...;transport=tls`, requires actual TLS, and may
  negotiate RTP/AVP; mandatory SRTP remains `sips:` plus RTP/SAVP/SDES.
- [ ] Run rvoip SIP-source end-to-end smoke.
- [ ] Run Bridgefu Web SDK end-to-end smoke.
- [ ] Run Vapi create/delete/recreate resilience cycle.
- [ ] Tear down and produce zero-resource evidence.

### Stage 4 — Finalize product behavior: IN PROGRESS

The corrected Bridgefu Web SDK harness, outbound security evidence, cleanup
ordering, and live Vapi delete/recreate/lost-response gate are locally green.
The next boundary is freezing those exact sources in commits, repinning the
distribution, and repeating local plus remote CloudFormation validation before
the retained Oregon environment is touched.

### Stage 5 — Fresh Oregon release qualification: NOT STARTED

Blocked on Stages 3 and 4.

### Stage 6 — Fresh Virginia release qualification: NOT STARTED

Blocked on a passing fresh Oregon release qualification.

### Stage 7 — Seal candidate: NOT STARTED

Blocked on passing qualifications in both regions.

### Stage 8 — Publish customer release: NOT STARTED

Blocked on a signed, sealed candidate.

## Current CI state

Last observed on 2026-08-12 against implementation commit `19854f1`:

### Bridgefu PR #4

- `infrastructure`: passed.
- `image (arm64)`: passed.
- `image (amd64)`: passed.
- `test`: passed.
- `Trivy`: passed.

### Distribution PR #26

- `validate`: passed.
- `sdp-diagnostics`: passed.
- `qualification-client`: passed.

Authoritative CI run: `31662616227`. Stage 1 passed against the exact current
diagnostic source.

CI monitors are not running locally. CI completion must be read explicitly
before updating these states.

## Evidence inventory

| Evidence | Location or identity | State |
|---|---|---|
| Qualification plan | `docs/maintainers/CLOUDFORMATION_RELEASE_QUALIFICATION_PLAN.md` | Committed and pushed |
| Status ledger | `docs/maintainers/CLOUDFORMATION_RELEASE_QUALIFICATION_STATUS.md` | Committed and pushed; this update is local pending the next implementation commit |
| Bridgefu implementation commit | `2fb2eaede9420c7d6980c5e0cfeb74eb786a2add` | Pushed, unmerged |
| Distribution implementation commit | `19854f1fb4fd2a48571584a5a628067952ebf585` | Pushed, unmerged |
| Local test results | Current task execution logs | Passed as listed above |
| Remote template-body validation | AWS account `225478700523`, both supported regions | Passed against current branch render |
| Oregon A/B SIP/SDP traces | Retained diagnostic execution `bfq-d19854f1-1` | Passed; `sip:...;transport=tls` produced actual TLS plus RTP/AVP in optional mode |
| Oregon end-to-end smoke evidence | — | Not created |
| Oregon zero-resource receipt | — | Not created |
| Virginia qualification evidence | — | Not created |
| Signed candidate receipt | — | Not created |

## Blockers and decisions required

1. The corrected Bridgefu Web SDK harness and its outbound Bridgefu-to-Vapi
   security evidence must pass the complete local gate before the retained
   Oregon environment is touched again.
2. Neither implementation PR should be treated as qualified until both live
   Stage 3 sources pass and retained-environment cleanup proves zero state.
3. The outbound evidence and corrected qualification changes are still local,
   uncommitted source and therefore cannot identify a release candidate yet.

## Next actions

The next actions, in order, are:

1. Commit/push the proven Bridgefu evidence source, repin the distribution
   source lock, and repeat the exact final-source local/remote template gates.
2. Update the retained Oregon runtime with those exact diagnostic bits and run
   the Bridgefu Web SDK source once, without rebuilding the environment between
   diagnosis attempts.
3. Run the rvoip SIP source, Vapi create/delete/recreate cycle, and exact
   retained-environment cleanup/zero-resource proof.

### 2026-08-12 — Retained Oregon deployment started

- The exact Stage 2 qualification template VersionId
  `V0HzoatwWjDBavZyGiYLQJ7fVwgzQyoQ` was submitted to CloudFormation in
  `us-west-2` as root stack `bridgefu-bfq-d19854f1-1`.
- CloudFormation created the disposable Connect nested stack successfully.
- Candidate Configuration and Network nested stacks reached
  `CREATE_COMPLETE`; HandoffService entered `CREATE_IN_PROGRESS`.
- Root and Candidate stack event audits found no `FAILED` or `ROLLBACK`
  event at this checkpoint.
- The environment remains retained for the Stage 3 direct secure and Vapi A/B
  tests. No release workflow, release version, or publication was started.

### 2026-08-12 — Retained Oregon deployment passed

- Root stack `bridgefu-bfq-d19854f1-1` reached `CREATE_COMPLETE` from exact
  diagnostic template VersionId `V0HzoatwWjDBavZyGiYLQJ7fVwgzQyoQ`.
- Disposable Connect and every Candidate nested stack reached
  `CREATE_COMPLETE`; the Bridgefu EC2 instance is running with both EC2 status
  checks healthy and SSM online.
- ACM issued the certificate after successful validation of both the SIP and
  control names.
- The qualification-only private hosted zone and exact SIP A record completed;
  it exists only to keep the same-instance direct control off the EC2 public-IP
  hairpin while retaining the public hostname and TLS identity.
- Deployment, retained-state, and exact ACM ownership receipts were written
  under `target/diagnostic/bfq-d19854f1-1/qualification/` with mode `0600`.
- The next permitted action is the direct secure control. The Vapi A/B and both
  source smokes remain blocked until that control passes.

### 2026-08-12 — Direct secure control attempt 1 stopped before SIP

- The retained-control wrapper reloaded exact stack outputs and attempted to
  create a private Amazon Connect Agent Workspace storage state.
- The browser harness returned the fixed redacted category
  `Agent Workspace harness failed`; no direct probe S3 upload or SSM dispatch
  occurred.
- Therefore this result says nothing about SIP, SDP, TLS, SRTP, Bridgefu, or
  Vapi. It is an Agent Workspace authentication-gate failure only.
- The retained stack remains `CREATE_COMPLETE`. Diagnosis will reuse that same
  environment; no rebuild, redeploy, candidate workflow, or release workflow is
  permitted.
- Root cause: the harness sets `PLAYWRIGHT_BROWSERS_PATH=0` to require the
  pinned repository-local browser, but the matching Chromium headless-shell
  executable was not installed in that path on this workstation. A separate
  read-only login diagnostic using the system Playwright cache reached the
  expected Agent Workspace, proving the generated Connect credential and login
  flow were valid.
- The harness now maps unexpected authentication failures to a fixed phase and
  safe closed category without printing browser errors, page bodies, URLs,
  credentials, or remote responses. The first classified failure was
  `browser-launch`, matching the missing pinned executable.
- Corrective action: install the pinned Playwright Chromium into the exact
  repository-local path, verify its launch, and rerun only the direct-control
  gate against the same retained stack.
- Corrective-action result: Playwright Chromium/headless-shell `v1234` was
  installed under `qualification/node_modules/playwright-core/.local-browsers/`.
  The exact qualification authentication command then completed and wrote a
  mode-`0600` storage state. This closes the browser-launch prerequisite; the
  direct SIP control itself is still untested.

### 2026-08-12 — Direct secure control passed

- The exact ARM64 direct-probe binary SHA-256
  `33d8f7cd1f65c90480b1dcd8292d8025884a7f40eaed16bda26924dae6e2f6bd`
  ran against retained stack `bridgefu-bfq-d19854f1-1`.
- All 24 closed evidence checks passed, including actual SIPS signaling, TLS
  transport, RTP/SAVP, SDES-SRTP, installed send/receive contexts, exactly one
  correlation header, inbound 200, outbound ACK, DNS/SIPS/TLS Contact, answer,
  sole Connect contact auto-accept, remote audio, agent outbound RTP, remote
  hangup, and contact cleanup.
- Mandatory cleanup passed: both SSM commands were terminal, the temporary
  binary version was purged, the probe process and run artifacts were absent,
  private DNS was reverified, the original runtime configuration was restored,
  and Bridgefu was healthy and ready.
- Redacted receipt:
  `target/diagnostic/bfq-d19854f1-1/qualification/direct-secure-control/direct-secure-control.json`
  (mode `0600`).
- This independently proves that the candidate Bridgefu/rvoip path correctly
  negotiates mandatory SDES-SRTP. The next gate is the machine-readable Vapi
  `sips:` versus `sip:...;transport=tls` A/B trace; no product contract is yet
  selected from this control alone.

### 2026-08-12 — Vapi A/B trace assets installed

- Generated the fixed synthetic transfer prompt with Amazon Polly at 8-kHz
  signed PCM; no customer data is present.
- Uploaded the trace proxy, exact CI-built ARM64 SIP client, and prompt as three
  private AES256-encrypted, versioned objects under the execution-owned
  `qualification/bfq-d19854f1-1/diagnostics/assets/` prefix.
- SSM installed the three assets into the retained instance's execution-owned
  diagnostic directory and verified their exact SHA-256 digests before use.
- The remote receipt reports `assets_installed=true`; no call has yet been made
  for either A/B leg. These assets and every S3 version remain explicitly owned
  cleanup obligations for Stage 3.

### 2026-08-12 — Vapi A/B `sip:...;transport=tls` attempt 1 failed

- The first optional-mode trace attempt exited without a trace artifact. The
  retained diagnostic deliberately collapsed the primary failure, so no SIP or
  SDP conclusion can be drawn from this attempt.
- Remote cleanup did restore Bridgefu and proved both SSM commands terminal,
  all redirect rules absent, proxy/source processes absent, and the temporary
  encrypted auth object absent.
- Cleanup did **not** prove the temporary Vapi SIP endpoint absent; the cleanup
  receipt is therefore `passed=false`. This is an active cleanup obligation and
  blocks any retry or `sips:` leg until exact ownership is re-established and
  the endpoint is removed.
- Evidence:
  `target/diagnostic/bfq-d19854f1-1/qualification/trace-sip-tls/cleanup-receipt.json`
  (mode `0600`). Diagnosis and cleanup will remain at this gate and reuse the
  retained stack; no deployment or release workflow will run.

### 2026-08-12 — Trace failure root cause fixed at the same gate

- SSM evidence identified the exact primary failure: the proxy observer stopped
  at `sip_trace_phase=install_redirect` because `iptables` was absent from the
  Amazon Linux image. No Vapi INVITE reached the proxy, so this was a diagnostic
  harness prerequisite failure, not Vapi, SIP, SDP, Bridgefu, or Connect.
- Exactly one owner-equivalent Vapi endpoint was found by deterministic name,
  stack-owned assistant ID, provider, and bounded SIP URI shape. It was
  re-read, deleted by exact ID, and polled to absence. Receipt:
  `trace-sip-tls/phone-cleanup-receipt.json`.
- The diagnostic now checks remote `iptables`, proxy, SIP client, prompt,
  Bridgefu service, and `/readyz` **before** it creates any Vapi endpoint.
  Focused regression tests pass (`10 passed`), including a proof that a missing
  prerequisite cannot call `prepare_phone`; Ruff and shell/source checks pass.
- Because NAT redirection is diagnostic-only, the retained test instance—not
  the product AMI—received the available Amazon Linux `iptables-nft` package.
  The original package-name set and exact newly added package set are sealed on
  the instance. A restore is mandatory after the A/B traces, and Stage 3 cannot
  pass unless the final package-name set is byte-identical to the original.

### 2026-08-12 — Vapi A/B `sip:...;transport=tls` trace captured; cleanup failed

- The retry captured a complete four-message redacted exchange: Vapi INVITE,
  Bridgefu 180, Bridgefu 200 with explicit SIPS/TLS Contact, and Vapi ACK.
- Both actual TLS legs negotiated TLS 1.3, and the proxy verified Bridgefu's
  certificate. This proves `sip:...;transport=tls` caused a real encrypted SIP
  signaling connection; TLS is not inferred from URI spelling.
- Vapi's INVITE SDP offered `m=audio ... RTP/AVP ...`, zero `a=crypto` lines,
  and zero DTLS fingerprint lines. Bridgefu's optional-SRTP policy correctly
  answered RTP/AVP, and Vapi ACKed the answer.
- Trace:
  `target/diagnostic/bfq-d19854f1-1/qualification/trace-sip-tls-attempt2/sip-trace.json`
  (mode `0600`). Raw SIP, addresses, identifiers, correlation value, credentials,
  SDP keys, and customer data were not persisted.
- The command still failed because the diagnostic's cleanup called the legacy
  ID-only phone deletion API. The shared Vapi client now correctly rejects that
  path and requires an exact ownership intent; the older diagnostic had not
  been migrated. Remote runtime/auth cleanup passed, but temporary Vapi endpoint
  absence did not, so the overall cleanup receipt remains `passed=false`.
- Required corrective action before the `sips:` leg: bind the diagnostic to the
  exact generated phone intent, use ownership-validating `delete_phone`, add a
  regression test, and remove/poll the one owner-equivalent endpoint to absence.
- Corrective action completed: the diagnostic now constructs and retains the
  same non-secret ownership intent used for creation and passes it to
  `delete_phone`. The focused suite passes (`11 passed`), including an exact
  assertion that ID plus intent are used and cleared only after verified
  deletion.
- Exactly one endpoint from attempt 2 was reconciled by deterministic name,
  stack-owned assistant, provider, and SIP shape; it was re-read, deleted by
  exact ID and intent, and polled absent. A subsequent bounded owner-equivalent
  listing returned zero matches. The `sips:` leg is now permitted.
- Before the `sips:` leg, the transfer Lambda's exact nine-variable environment
  and revision were sealed locally at mode `0600` with SHA-256
  `0d97fdc3baf81d8cf2f6112f20196a432fb1d80f83f7752e6d1ba82d489fae33`.
  A revision-guarded update changed only `SIP_SECURITY` from
  `sips_optional_srtp` to `sips_srtp`; Lambda returned Active/Successful with
  all nine variables present. Exact restoration and digest verification are
  mandatory immediately after this leg.

### 2026-08-12 — Vapi A/B `sips:...;transport=tls` trace completed

- The `sips:` leg completed with a passing cleanup receipt and zero remaining
  owner-equivalent Vapi endpoints.
- Both actual signaling legs again negotiated TLS 1.3, and the proxy verified
  Bridgefu's certificate.
- Vapi sent `INVITE sips:...;transport=tls` but offered the same unencrypted
  SDP as the `sip:` leg: `RTP/AVP`, zero SDES `a=crypto` lines, and zero DTLS
  fingerprint lines.
- Bridgefu returned 100 Trying. After approximately 60 seconds, Vapi sent
  CANCEL; Bridgefu returned 200 to CANCEL and 487 to INVITE; Vapi ACKed the
  487. No answered call or media was established on this leg.
- Trace:
  `target/diagnostic/bfq-d19854f1-1/qualification/trace-sips-tls/sip-trace.json`
  (mode `0600`); cleanup receipt in the same directory is `passed=true`.
- The transfer Lambda's exact nine-variable environment was restored to
  `sips_optional_srtp`, returned Active/Successful, and its canonical variable
  digest exactly matched the sealed pre-test environment
  (`aa43b39919218c4fb35ac3c2621ed3497996fe1ef9806a5584a41d9f8d217f97`).
- A/B result: both URI forms produce real TLS signaling, but Vapi offers
  only RTP/AVP for both. `sip:...;transport=tls` answered and ACKed; `sips:` did
  not answer and was cancelled. Before selecting the product contract, the
  correlated Bridgefu and Vapi call records for the `sips:` leg must explain
  why it remained in Trying rather than assuming the URI string alone caused
  the failure.

### 2026-08-12 — Vapi A/B root cause and contract selected

- Correlated Bridgefu logs show the `sips:` INVITE created a server transaction
  and immediately failed as an unassociated transaction event. No Bridgefu
  route execution or Connect contact was created.
- The trace supplies the missing cause: Vapi used a SIPS Request-URI and To but
  a plain SIP Contact. rvoip 0.3.7 derives the dialog remote target from Contact
  and rejects a non-SIPS target for a secure SIPS dialog, so no dialog mapping
  could be formed. The later CANCEL consequently also had no dialog mapping.
- Closed correlated finding:
  `trace-sips-tls/correlated-finding.json` (mode `0600`). The temporary raw
  CloudWatch export was deleted after extracting these closed facts because it
  was not a redacted evidence artifact and is not recoverable from the local
  task directory.
- Contract selected for the remaining diagnostic smokes:
  `sips_optional_srtp` returns `sip:<one-use-route>@host:5061;transport=tls`;
  Bridgefu independently requires actual TLS and accepts RTP/AVP only in this
  optional mode. `sips_srtp` remains strict SIPS plus RTP/SAVP/SDES-SRTP.
- The test-only `iptables-nft` package and every dependency added with it were
  removed. The final RPM package-name set is byte-identical to the sealed
  pre-install set, `iptables` is absent again, and the restoration receipt is
  `qualification/trace-package-restored.json` (mode `0600`).
- The next gate is the Web SDK source smoke against the restored optional-mode
  stack, followed by the rvoip SIP-source smoke. They will run sequentially.

### 2026-08-12 — Retained Web SDK smoke attempt 1 failed

- The Web SDK smoke reused the retained stack after exact input, demo-bundle,
  Connect authentication, and stack-owned Vapi assistant validation.
- It failed at the bounded source-browser gate with the closed category
  `Vapi browser media observations did not converge`.
- The verifier did not emit a passing scenario, and the SIP-source smoke remains
  blocked. This result does not yet identify whether the call failed before
  transfer, on the Vapi destination leg, in Bridgefu/Connect, or only in the Web
  browser's media observer.
- Diagnosis will use the same call's safe local browser artifacts, exact Vapi
  terminal record, Bridgefu runtime events, Connect contact, handoff record, and
  lookup logs. No retry, redeploy, candidate, Virginia run, or release workflow
  is permitted until the exact cause is established and regressed.
- The first read-only Vapi call-inspection helper failed locally before any API
  call because it omitted the explicit `phone_number_id=None` and
  `call_id=None` keyword-only filters required by the hardened Vapi client.
  The helper was corrected; this local signature error did not change AWS,
  Vapi, Bridgefu, or the retained stack.
- A subsequent read-only call-log inspector initially failed locally because
  Vapi's presigned call log is gzip-compressed rather than raw UTF-8. No log
  body was printed or persisted. The helper now detects gzip magic, bounds both
  compressed and expanded sizes, and retains only hashes, key shapes, and a
  closed category count.

### 2026-08-13 — Web smoke harness root cause corrected

- The failed call was a Vapi `webCall`, not the Bridgefu Web SDK source
  required by the qualification plan. The retained call record's
  `type=webCall` was accurate evidence of the wrong harness path.
- The deployed demo source imports `@vapi-ai/web` 2.5.2 directly. This
  contradicts the qualification README, which claimed that the build fetched
  and used Bridgefu's Web SDK from the commit pinned by `bridgefu.lock.json`.
- The failed Vapi web transfer is therefore not evidence that Bridgefu's Web
  SDK path is blocked and is not a valid Stage 3 smoke result.
- The required path is now recorded explicitly in the plan: browser attaches
  through `@bridgefu/webrtc-browser`; Bridgefu originates the SIP leg to the
  Vapi assistant; a trusted server-side Bridgefu handoff replaces that leg with
  Amazon Connect while preserving the browser PeerConnection.
- Before another Web-source run, the immutable demo-site builder, browser
  driver, controller, qualification-only runtime configuration, and evidence
  contract must be changed to exercise that exact pinned SDK and topology.
  The stock `@vapi-ai/web` dependency and all `webCall` success claims must be
  removed from this gate.
- No AWS, Vapi, or retained-stack mutation was made while establishing this
  root cause. The Oregon diagnostic stack remains retained and the SIP-source
  smoke remains pending.

### 2026-08-13 — Correct Bridgefu Web SDK implementation plan adopted

The corrected smoke will follow Bridgefu's implemented direct-browser topology
and the working ownership pattern in `/Users/jonathan/Developer/standardcharter`
instead of attempting a stock Vapi `webCall` transfer.

The exact call path is:

```text
browser -> @bridgefu/webrtc-browser -> Bridgefu -> dedicated Vapi SIP assistant
                                              -> trusted replace-leg request
                                              -> Amazon Connect wrapper flow
```

Implementation order and boundaries:

1. **Bind the demo bundle to the pinned Bridgefu SDK.**
   - Check out `bridgefu.lock.json.repository` at its exact 40-character commit
     before building the site and before obtaining AWS credentials.
   - Verify the pinned Bridgefu `Cargo.lock` digest and the SDK package identity
     `@bridgefu/webrtc-browser`.
   - Run the SDK's locked build from `sdk/typescript`, then bundle the
     qualification page against that exact output.
   - Remove `@vapi-ai/web` and the Vapi public key from the demo-site dependency
     and configuration contracts.
   - Seal the Bridgefu commit, SDK package-lock digest, built SDK digest, and
     final site archive digest into the immutable demo-site manifest.

2. **Use the server-owned direct-handoff pattern.**
   - Model the flow on StandardCharter's `direct-agent-handoff` tool and
     `/vapi/direct/handoff` endpoint: the browser receives only a one-use
     Bridgefu WebRTC attachment, never a Bridgefu control bearer or Vapi key.
   - Create a qualification-owned Vapi SIP assistant/endpoint for this path;
     Bridgefu, not the browser, originates the SIP call to it.
   - Generate a signed, opaque handoff token on the trusted side and map it to
     the exact Bridgefu call, replaceable Vapi leg, correlation ID, and allowed
     `amazon-connect` route. Inject the token as a static Vapi tool parameter so
     it is not model-controlled.
   - The trusted handoff endpoint validates that token and the configured field
     values, stores the DynamoDB context first, and only then invokes
     Bridgefu's protected exact-leg replacement API. The model cannot provide a
     call ID, leg ID, route endpoint, control credential, or correlation ID.

3. **Install only a reversible qualification runtime overlay.**
   - Keep the exact customer `vapi-amazon-connect-screen-pop@1` recipe active.
     Add TestDelete-only WebRTC ingress, the `vapi-direct-assistant` SIP route,
     and the `amazon-connect` replacement route for the SDK smoke.
   - Use the existing Connect wrapper flow so the Lambda lookup and ordered
     screen pop remain in the call path.
   - Keep Vapi SIP authentication in a qualification-owned Secrets Manager
     secret readable only by the retained runtime role; never place it in an
     SSM command, browser configuration, artifact, or log.
   - Reach the private control/WSS listener through a bounded controller-owned
     tunnel and admit browser media only from the exact test source for the
     bounded run. Do not add a broad public control rule.
   - Back up and hash the runtime config before the overlay. A separate cleanup
     command must prove byte-identical restoration, Bridgefu readiness, tunnel
     and temporary rule absence, and secret/resource removal.

4. **Replace the browser driver and evidence contract.**
   - The page consumes a Bridgefu route attachment and connects with
     `BridgefuWebRtcClient`; it must never call `new Vapi()` or produce a Vapi
     `webCall`.
   - Observe authenticated `bridgefu.handoff.v1` states while proving the same
     browser PeerConnection survives the Vapi-to-Connect replacement.
   - Prove Vapi SIP assistant establishment, context stored before replacement,
     one correlation value, Connect lookup/screen pop, bidirectional audio,
     source-to-agent and agent-to-source DTMF, both hangup directions, and exact
     cleanup.
   - Rename the scenario/evidence producer so no passing artifact can be
     confused with the invalid stock-Vapi `vapi-web-transfer` path.

5. **Gate live execution.**
   - Add deterministic bundle tests that fail if `@vapi-ai/web`,
     `VAPI_PUBLIC_KEY`, or a `webCall` start path reappears.
   - Test attachment/token ownership, replace-leg allowlisting, store-before-
     replace ordering, credential redaction, generated SSM syntax, restoration,
     and evidence schema locally.
   - Only after those local checks pass may the retained Oregon stack be
     touched. Run the corrected SDK smoke once, diagnose against that same
     environment if necessary, then run the rvoip SIP-source smoke.

6. **Promote only after retained proof.**
   - Run Vapi create/delete/recreate resilience.
   - Remove every qualification-only assistant, tool, phone, secret, tunnel,
     rule, and runtime overlay; delete the retained stack and prove complete
     zero state.
   - Then repeat Stages 1 and 2 against final source before starting a fresh
     Oregon release qualification. No release workflow is used during this
   implementation or retained diagnostic work.

### 2026-08-13 — Pinned Bridgefu SDK bundle slice passed locally

- Removed the stock `@vapi-ai/web` dependency from the qualification package.
- `qualification/build_demo_site.py` now requires an explicit Bridgefu
  checkout, verifies its exact pinned Git commit and Cargo.lock digest, builds
  `sdk/typescript` with its own lockfile, and bundles
  `@bridgefu/webrtc-browser` into the deterministic demo site.
- Demo-site manifest schema v2 binds the Bridgefu commit, Bridgefu Cargo.lock,
  SDK name/version, SDK package-lock digest, built SDK tree digest, site
  package-lock digest, every public file digest, and final archive digest.
- Replaced the demo page's Vapi client with `BridgefuWebRtcClient` and a
  one-use route-attachment configuration boundary. The page no longer accepts
  a Vapi public key or assistant ID and cannot initiate a Vapi `webCall`.
- Local build against pinned Bridgefu commit
  `2f6cf2f6dec72856479cd74b5f23af702ae1dffa` passed. The resulting test archive
  digest was `cfa04f3a2fc745f899b90e2cc0b4a21334ac3f3dfbd3dc3375f09068a063ab08`;
  its bundled JavaScript contains Bridgefu SDK code and contains none of
  `@vapi-ai/web`, `VAPI_PUBLIC_KEY`, or `webCall`.
- This is a local bundle result only. The browser driver, controller, immutable
  workflow checkout order, direct-handoff coordinator, runtime overlay, and
  evidence schema are not yet converted. No AWS or Vapi mutation was made.
- The first focused asset run passed 23 of 24 tests. Its only failure expected
  the source-level class name `BridgefuWebRtcClient` to survive minification;
  esbuild correctly renamed the class. This was a brittle test assertion, not
  a product or SDK failure.
- The bundle assertion now uses the stable Bridgefu wire markers
  `bridgefu.handoff.v1`, `rvoip.webrtc.v1`, and `bridgefu.attach.` while the
  source test still requires the exact SDK import. The focused qualification
  asset suite then passed 24 of 24 tests. No AWS or Vapi mutation was made.
- The active diagnostic path was reconfirmed: GitHub Actions will not deploy or
  debug the retained environment. Local validation runs first; this workstation
  will then manage the one retained Oregon environment directly. Only after
  both corrected sources pass will proven changes be folded into the customer
  and disposable qualification CloudFormation templates, validated, and run
  as fresh regional qualifications. GitHub Actions resumes only as the final
  reproducible build/qualification/publication mechanism.
- A focused local test invocation incorrectly addressed `tests.unit` as an
  importable Python package. It failed at discovery with three
  `ModuleNotFoundError` entries and executed zero tests. This was a local test
  command error; it made no AWS or Vapi call. The rerun uses the repository's
  supported `unittest discover -s tests/unit -p ...` form.
- The supported rerun passed: 24 qualification asset tests, 36 controller
  tests, and 7 scenario security/readiness tests. The browser runner is now
  named `bridgefu-web-playwright.mjs`, accepts only a private one-use Bridgefu
  route attachment, identifies SDK `@bridgefu/webrtc-browser` 0.1.0, and emits
  a Bridgefu-specific observation contract. The release scenario is now named
  `bridgefu-web-sdk-handoff`; the invalid `vapi-web-transfer` success identity
  is removed from active schemas and release gates. No AWS or Vapi mutation was
  made.
- This does not yet open the live gate. The controller still needs the
  qualification-only WebRTC-to-Vapi named route, trusted server-side
  replacement coordinator, one-use attachment creation, and byte-identical
  runtime restoration before it can supply the new runner's required input.
- The first pure coordinator-contract run failed before executing its tests:
  the test's custom import loader did not register the module before Python
  evaluated a dataclass. Ruff also rejected an outdated `typing.Mapping`
  import, ambiguous constant names that looked like hardcoded secrets, and the
  loader's bare `assert`. These are local implementation/test hygiene defects;
  no AWS or Vapi mutation occurred. They are being corrected before the
  coordinator slice can be marked passed.
- The corrected pure coordinator contract now passes 5 of 5 tests plus Ruff,
  format, and diff checks. It issues and verifies a bounded HS256 token that
  contains no call, leg, route, endpoint, or credential; constructs only a
  server-owned WebRTC route context; binds exactly one inbound WebRTC leg and
  one outbound Vapi SIP leg; keeps `handoff_token` outside the model-facing
  tool schema; and proves the assistant overlay can be removed byte-for-byte
  without changing unowned assistant properties. No AWS or Vapi mutation was
  made.
- The first direct server-contract run passed all 19 handoff behavior tests,
  including shared token vectors, store-before-replace ordering, exact
  call/leg/route binding, tamper rejection, and Vapi identity rejection. Ruff
  then found only a quoted forward annotation and import ordering; the slice is
  not marked clean until those style checks are corrected and rerun. No AWS or
  Vapi mutation occurred.
- After the two style corrections, the complete 19-test handoff suite, Ruff,
  format, and diff checks pass. The trusted direct handler now validates the
  exact Vapi org/assistant, verifies the signed opaque token, validates only
  configured screen-pop fields, commits them through the direct store before
  invoking replacement, targets one stored call/leg plus the server-owned
  `amazon-connect` route, and returns only a correlated opaque success result.
  No AWS or Vapi mutation was made.
- The first AWS adapter slice passed all 4 behavior tests: direct Dynamo
  preparation returns only the prebound call/leg/route/idempotency receipt,
  stores a Vapi identity hash rather than raw identity, transitions only from
  the mapped/prepared states, and the Bridgefu replacement client refuses a
  route other than its configured server-owned route. Ruff passed; the format
  check requested changes in the two edited files, so this slice remains
  pending until formatted and rerun. No AWS call was made.
- After formatting, the AWS adapter slice passes all 4 tests plus Ruff,
  format, and diff checks. This establishes the local store-before-replace and
  exact Bridgefu replacement transport contract, but it is not yet wired to a
  Lambda entrypoint or CloudFormation resource. No AWS or Vapi mutation was
  made.
- The Lambda dispatch slice passed both behavior tests: the new exact API route
  invokes only the direct store/replace contract, while the existing transfer
  route does not read the direct signing authority or invoke direct logic.
- The qualification template now renders the direct-handoff signing secret,
  private Lambda, exact IAM scope, and HTTP API from the same immutable
  transfer Lambda artifact used by the customer template. The customer root
  exports only the exact nested runtime/table/secret identities needed by that
  qualification-only layer. `release/validate.py`, including deterministic
  rendering and local CloudFormation linting, passes. No AWS stack or Vapi
  resource was changed.
- A controller audit found two remaining live-gate blockers before a retained
  call is permitted: the browser readiness ID belongs to the Bridgefu call and
  must not be substituted for the independently observed Vapi call ID, and the
  owned Vapi SIP endpoint/authentication must exist before Bridgefu creates the
  WebRTC-to-Vapi route. The current `web_smoke` still supplies the removed
  `--assistant-id` option and therefore remains deliberately non-runnable until
  these two contracts and reversible cleanup are implemented and tested.
- The qualification stack now owns a separate, initially empty Vapi SIP-auth
  secret and attaches one exact read-only policy to the stack-owned Bridgefu
  gateway role. The customer stack exposes the non-secret gateway role, gateway
  security group, and public media address only so the disposable outer stack
  can install and later delete that qualification-only capability. Local
  deterministic release validation and all 24 release contract tests pass.
  No secret value was written and no AWS resource was changed.
- The first generated WebRTC runtime-overlay test failed locally for two useful
  reasons. Its secret scanner rejected the required `env:` password reference
  as though it were literal secret material, and the exact pinned Bridgefu
  validator rejected the overlay because optional-SRTP recipe posture did not
  match the generic SIP child's default disabled posture. No remote command was
  generated or run.
- The scanner now requires the one exact environment reference instead of
  rejecting the field name, and the overlay explicitly sets the shared inbound
  SIP child to `preferred`, matching `sips_optional_srtp`. The complete
  canonical JSON/YAML overlay passes three contract tests, Ruff, formatting,
  diff checks, and—most importantly—the exact pinned Bridgefu binary's real
  `validate` command. It owns only `vapi-direct-assistant` and
  `amazon-connect`, uses WSS/WebRTC with a bounded public ICE port range, and
  contains no Vapi password. No AWS or Vapi mutation was made.
- The runtime slice now also generates the exact SSM install and independent
  cleanup scripts. Install downloads one SHA-256-bound config, preserves the
  original bytes, validates the candidate with the deployed Bridgefu binary,
  installs a systemd drop-in, reads the exact stack-owned SIP-auth secret only
  inside the runtime process, and requires readiness plus the loopback WSS
  listener. Cleanup restores the original config, removes the drop-in, wrapper,
  secret environment file, and bounded run directory, then requires Bridgefu
  readiness. Five focused tests pass, including `bash -n` on the exact generated
  scripts and closed-vocabulary receipt validation. No SSM or AWS command was
  executed.
  Ruff passed; the format check requested changes in the two edited files, so
  the slice remains pending until formatted and rerun. No Lambda or stack was
  deployed.
- After formatting, both Lambda dispatch tests plus Ruff, format, and diff
  checks pass. The direct handler remains local-only until its secret, IAM,
  route, and environment contracts are added to CloudFormation and validated.
  No Lambda or stack was deployed.
- The exact qualification Vapi tool ownership boundary now includes the
  execution ID as well as the direct endpoint and fixed Bridgefu marker.
  Ten focused handoff/runtime tests pass, including rejection of a foreign
  execution's tool. No Vapi API call was made.
- Browser-session identity is now explicit: `source_call_id` is the Bridgefu
  WebRTC call, while `vapi_call_id` is the independently discovered downstream
  Vapi SIP call used for terminal Vapi evidence. A server-issued correlation
  ID can be supplied without deriving it from either call identity. The
  Bridgefu and Agent Workspace runners accept the same exact private session
  shape.
- The browser runner now requires a private 8-kHz signed-PCM spoken handoff
  prompt and mixes it into the fake microphone stream. It also requires the
  exact WSS hostname from the one-use attachment and launches Chromium with a
  bounded hostname-to-loopback resolver rule, allowing SSM local port
  forwarding to preserve TLS hostname verification without a public control
  listener. Node syntax checks and 68 focused controller/asset/readiness tests
  pass.
- Ruff still correctly blocks the live gate because the old `web_smoke`
  implementation contains its prior undefined `env` argument and removed
  `--assistant-id` path. That method is the next replacement boundary; no AWS
  or Vapi mutation occurred.
- The obsolete `web_smoke` path is now replaced locally. The controller
  provisions an authenticated temporary Vapi SIP endpoint, creates one
  endpoint/credential-bound function tool, overlays only that tool and one
  marked system message onto the stack-owned assistant, validates and installs
  the reversible Bridgefu WebRTC runtime, and uses SSM loopback tunnels for WSS
  and control. It grants only the browser's observed public `/32` access to the
  bounded WebRTC UDP range and records the exact permission for revocation.
- Before browser attachment, the controller issues the opaque handoff token,
  creates one `vapi-direct-assistant` route, and writes the exact `MAPPED`
  DynamoDB binding with the Bridgefu call, replaceable Vapi leg,
  `amazon-connect` route, schema hash, expiry, and idempotency identity. The
  Vapi API key, SIP password, Bridgefu bearer, handoff token, attachment, and
  correlation value remain out of argv and retained evidence.
- The Agent Workspace observer now reaches Available before route creation and
  waits for the later private session file. The browser and agent therefore
  bind to the real Bridgefu call while the controller independently discovers
  the exact downstream Vapi call and writes a single shared session before the
  tool can complete the Connect handoff.
- Cleanup is ordered and fail-closed: stop browser/tunnels, restore the exact
  runtime, revoke media admission, clear the stack-owned SIP-auth secret,
  purge the versioned runtime object, remove only the marked assistant overlay,
  exact-delete its tool, then exact-delete the temporary Vapi endpoint and
  journals. The SIP-source smoke reuses the same create/delete path afterward,
  making endpoint recreation part of qualification.
- Current focused gate: 106 controller/asset/runtime/release tests pass, both
  Node runners pass syntax checking, Ruff passes, and `git diff --check`
  passes. No AWS or Vapi mutation occurred.
- A new evidence gap remains open before the live gate: pinned Bridgefu emits
  the exact security event for an inbound Vapi-to-Bridgefu SIP leg, including
  optional TLS/RTP, but the corrected browser topology first creates an
  outbound Bridgefu-to-Vapi SIP leg. That opposite direction cannot be claimed
  from the inbound event and needs an explicit redacted outbound security
  evidence contract plus controller/schema tests.
- That outbound evidence gap is now closed locally. Bridgefu observes the
  actual outbound INVITE trace over TLS, the redacted SIP/SIPS target scheme,
  the peer SDP answer (`RTP/AVP` or `RTP/SAVP`), typed SDES suite/context
  installation when present, and the established call. It emits one closed
  `bridgefu_vapi_source_security_evidence` event without target, SDP, key,
  address, or raw correlation data. It handles `CallAnswered` before or after
  the trace instead of relying on event order.
- The qualification controller now requires that outbound event for the
  Bridgefu Web SDK scenario and continues requiring the independent inbound
  event for the rvoip SIP-source scenario. Focused tests cover optional
  TLS/RTP, rejection of a false UDP claim, exact leg/message vocabulary, and
  the separate Bridgefu/Vapi call identities.
- The spoken Bridgefu Web SDK prompt and the exact DynamoDB/screen-pop value
  now use the same natural value, `Qualification Bridgefu Web SDK source
  hangup.` The prior prompt removed hyphens from an internal scenario ID while
  the verifier expected them, which could have created a false live mismatch.
- Current focused gate after these changes: Bridgefu security evidence **16
  passed**, Bridgefu Clippy passed, and **100** distribution controller,
  browser-asset, runtime, handoff, and release tests passed. Ruff, both Node
  syntax checks, Rust formatting, and diff checks passed. No AWS, SSM, Vapi,
  Route53, Connect, or CloudFormation mutation occurred.

## Execution history

### 2026-08-12 — Status ledger created

- Qualification plan written.
- Status ledger created as a separate living document.
- Active stage recorded as Stage 1.
- No diagnostic stack or release candidate created.
- Existing implementation branches and partial validation evidence recorded.

### 2026-08-12 — Exact SSM serialization gate completed

- Routed all three controller `AWS-RunShellScript` dispatch sites through one
  bounded JSON command-array encoder.
- Added exact decode and `bash -n` regression coverage.
- Focused SSM/diagnostic/controller suite: 65 passed.
- Full distribution Python suite: 226 passed.
- Deterministic packaging and local release validation passed.
- Read final Bridgefu PR #4 checks: all passed.
- Committed and pushed the exact SSM gate and plan/status documents as
  distribution implementation commit `40c175b`.
- Distribution CI run `31661830627` started against that commit.

The first encoder bound allowed at most 512 command entries. Focused tests
immediately rejected the real direct-probe program because it has 539 bounded
command entries. No AWS call was made. The bound was corrected to 1,024
entries plus a 60 KiB aggregate limit, after which the focused 65-test suite
and full 226-test Python suite passed.

### 2026-08-12 — Stage 1 CI and Stage 2 preflight

- A status-only commit `97a0e9a` superseded the first CI run; authoritative
  distribution CI run `31661852590` started against that exact branch head.
- `validate` passed, including deterministic packaging, CloudFormation lint,
  and pinned Packer validation.
- `sdp-diagnostics` passed.
- `qualification-client` remains in progress; Stage 1 has not been advanced.
- AWS identity was reverified as account `225478700523`.
- Both regional artifact buckets were verified to have versioning enabled.
- Bucket policies were verified to keep untagged `diagnostics/...` objects
  private. No object was uploaded and no AWS resource was created.

### 2026-08-12 — Diagnostic-prefix renderer defect found and fixed locally

- A local ignored-output dry run used the non-release prefix
  `diagnostics/diagnostic-97a0e9a`; no AWS write occurred.
- The dry run proved nested template URLs honored the diagnostic prefix, but
  all five Lambda artifact keys were incorrectly hardcoded to `releases/...`.
  A staged diagnostic deployment would therefore have failed when Lambda tried
  to load artifacts from keys that were never uploaded.
- The renderer now applies the validated release-prefix token to both template
  URLs and Lambda artifact keys.
- Added a phased-render regression that requires all diagnostic Lambda keys to
  use `diagnostics/build-123/...` and forbids `ArtifactKey: releases/`.
- Focused release contract suite: 24 passed. The regenerated local diagnostic
  root contains five diagnostic-prefix Lambda keys and no release-prefix
  Lambda key.
- An initial attempt to address one unittest by dotted module name failed
  locally because `tests` is not a Python package. This was a test invocation
  error, not a product failure; the supported discovery invocation then passed
  all 24 tests.
- Because source changed after CI run `31661852590` began, that run cannot be
  the final Stage 1 authority even if it passes. Stage 1 must rerun after this
  fix is committed.
- The distribution source lock now pins Bridgefu PR #4 commit
  `2f6cf2f6dec72856479cd74b5f23af702ae1dffa` while retaining
  `release_ready=false`. `release/verify_bridgefu.py` accepted the exact clean
  checkout, Cargo.lock digest, and all 25 crates.io rvoip 0.3.7 packages.
- Full Python suite: 226 passed. Local release validation and `ruff check .`
  passed after the renderer and source-lock changes.
- An additional `ruff format --check .` command failed because 11 pre-existing
  repository files are not Ruff-formatted. CI and the written Stage 1 contract
  require `ruff check`, not repository-wide Ruff reformatting. No file was
  reformatted, and this unrelated baseline formatting debt is not being mixed
  into the diagnostic fix.
- Committed and pushed the source-lock and diagnostic-prefix fix as `d8823bc`.
- Cancelled obsolete PR CI runs `31660862098`, `31661830627`, and
  `31661852590`; they target superseded commits and cannot qualify the current
  source. Authoritative run `31662335450` started for `d8823bc`.
- Downloaded Packer 1.12.0 for macOS arm64 into ignored `target/tools/` and
  verified its archive against HashiCorp SHA-256
  `448bebeb5741eebd5fdc92609e75213665366970cd607ec57e7a5516d7067b3d`.
- Local pinned `packer init` and `packer validate` passed for Bridgefu commit
  `2f6cf2f6`, Cargo.lock digest `bc49cee0...`, and distribution commit
  `d8823bc`.

### 2026-08-12 — Exact native diagnostic clients retained by CI

- The Stage 3 controller requires the exact ARM64 static SIP client and direct
  secure probe, but CI previously discarded both after proving them.
- CI now uploads only those two non-secret verified executables in a seven-day
  artifact named with the exact tested GitHub workflow SHA. The run ID and
  artifact digest will be recorded before Stage 3 uses them.
- Added workflow contract coverage for the artifact name, both exact binary
  paths, and bounded retention.
- Focused qualification-asset suite: 24 passed. Full Python suite: 226 passed.
  Local release validation, Ruff, and diff checks passed.
- This workflow change supersedes CI run `31662335450`; a new authoritative
  Stage 1 run is required after commit and push.
- Committed and pushed the artifact-retention change as `19854f1`.
- Cancelled superseded CI run `31662335450`. Authoritative Stage 1 CI run
  `31662616227` started for the exact current implementation commit.
- Repeated `gh run watch` polling exhausted the authenticated GitHub core API
  limit at 20:14 PDT while the valid ARM job was still running. CI itself was
  unaffected. Authenticated polling was stopped until the 20:53 PDT reset;
  later status checks use the public read-only endpoint sparingly. This was an
  orchestration mistake, not a test or product failure.
- CI run `31662616227` completed successfully: `validate`, `sdp-diagnostics`,
  and `qualification-client` all passed. The latter also uploaded artifact ID
  `9167368330`, named
  `qualification-native-clients-b53b0ffd2ad3310a812df6b45025df6617b11958`,
  expiring 2026-08-20.
- Stage 1 advanced to `PASSED`; Stage 2 became active.
- An immediate authenticated artifact download attempt was blocked by the same
  exhausted GitHub core limit. No artifact was partially accepted and this
  does not block Stage 2 template staging; download will resume after the
  recorded reset before Stage 3.

### 2026-08-12 — Stage 2 private diagnostic build started

- Created local diagnostic execution identity `bfq-d19854f1-1`, version
  `0.0.0-diagnostic-19854f1-1`, and cleanup-owned state journal.
- Built the deterministic qualification demo-site archive locally; SHA-256 is
  `47663971aace191457a6b667aa3c08f9141df24c0b336f97d83e40911ad188a3`.
- Uploaded the first non-secret state-journal version privately to
  `s3://bridgefu-vapi-awsconnect-225478700523-us-east-1/diagnostics/bfq-d19854f1-1/state.json`;
  exact VersionId is `EVdDfvAIUGGyzB_759lJ_XENM5fmsEmC`.
- Started one Packer 1.12.0 Oregon AMI build pinned to Bridgefu
  `2f6cf2f6`, its exact Cargo.lock digest, distribution `19854f1`, and exact
  crates.io rvoip 0.3.7. Temporary build instance
  `i-0e684157ce48e7c21` was created by Packer; no qualification stack has been
  deployed.

### 2026-08-12 — Stage 2 passed

- Packer completed successfully in 34 minutes and terminated temporary builder
  `i-0e684157ce48e7c21`.
- Private Oregon AMI `ami-072ed04e8129a7579` and snapshot
  `snap-0b15079c16735b4d9` are available and exactly tagged.
- Private Virginia copy `ami-0ffe549c2a8717cd3` and snapshot
  `snap-0e0c197d357fa6384` are available and exactly tagged. No Virginia stack
  was created.
- Uploaded and journaled 25 private objects under the unique diagnostic prefix.
- Renderer inspection proves all five Lambda artifact keys use the diagnostic
  prefix; none uses `ArtifactKey: releases/`.
- AWS `ValidateTemplate` passed for all 10 local template bodies in both
  regions and all 10 exact S3 VersionId template URLs in both regions.
- Validation receipt is
  `target/diagnostic/bfq-d19854f1-1/validation-receipt.json`; it records
  `stack_created=false`, `published=false`, and `redacted=true`.
- Stage 2 advanced to `PASSED`. Stage 3 is active only for its required
  read-only zero-state preflight; no diagnostic stack has been deployed yet.

### 2026-08-12 — Stage 3 zero-state preflight passed

- Exact execution `bfq-d19854f1-1` has no CloudFormation stack, Connect alias,
  tagged AWS resources, public DNS/ACM, qualification S3 prefix, runtime EC2,
  DynamoDB, Secrets Manager, log groups, private hosted zones, API Gateway, or
  owner-equivalent Vapi assistant/phone resources.
- The two Stage 2 private AMIs and private `diagnostics/bfq-d19854f1-1/`
  artifact prefix were explicitly excluded as expected immutable inputs.
- Redacted receipt `predeploy-zero-state.json` was uploaded privately and
  journaled as exact VersionId `hd6N1lgzkjpphSUSBNsgQ3GUYwobQJuP`.
- Downloaded CI artifact ID `9167368330`. Exact ARM64 static binary digests:
  direct probe `33d8f7cd1f65c90480b1dcd8292d8025884a7f40eaed16bda26924dae6e2f6bd`;
  SIP client `df92f441323f914a5cf69e004fc6c77e7b5a26d187b033f0a8cf5ff911f4c25b`.
- `VAPI_PUBLIC_KEY` is present in the authorized local login environment; its
  value was not printed or written.
- The first local retained-deployment wrapper invocation failed before any AWS
  call with `ModuleNotFoundError: qualification` because Python used the
  ignored `target/...` script directory as its import root. The wrapper now
  inserts the exact repository root before importing the controller. No stack
  was created and the zero-state result remained valid.

### 2026-08-13 — Corrected local qualification gate passed

- Bridgefu now emits a redacted outbound `bridgefu-to-vapi` security event
  derived from the actual TLS SIP trace, URI scheme, negotiated media profile,
  typed SDES suite/context state, answer, and establishment events. The focused
  suite passed 16 tests; the full locked Bridgefu Rust suite passed without a
  failure; formatting and Clippy with warnings denied passed.
- The browser smoke now uses Bridgefu's pinned `@bridgefu/webrtc-browser` SDK,
  not Vapi's Web SDK. Its package suite passed 20 tests and both Playwright
  drivers passed Node syntax validation.
- The qualification controller now runs the exact production Vapi provisioner
  after both smokes: delete the stack-owned assistant/tool/credential, simulate
  one committed assistant POST whose response is lost, require deterministic
  reconciliation with no duplicate owner, delete that cycle, recreate once,
  and leave the exact recreated resources for CloudFormation cleanup.
- Evidence v2 and candidate sealing require the closed boolean resilience
  receipt. Adversarial tests prove a string `"false"` cannot satisfy the gate.
- Complete distribution local results: 257 Python tests passed;
  `make qualification-test` passed (4 SIP-client and 16 direct-probe tests);
  Ruff, Python compilation, deterministic Lambda/release packaging,
  `cfn-lint`, release validation, Packer 1.12.0 validation, actionlint, and
  `git diff --check` all passed.
- No AWS, Vapi, Route53, CloudFormation, or GitHub release mutation was made
  while completing this gate. The next action is to commit/push the proven
  Bridgefu evidence source, repin the distribution lock, and repeat affected
  local plus remote `ValidateTemplate` checks before reusing Oregon.
- Bridgefu evidence commit `2fb2eaede9420c7d6980c5e0cfeb74eb786a2add`
  was pushed to `origin/codex/vapi-tls-rtp-evidence`; the distribution source
  lock now pins that exact commit with unchanged Cargo.lock SHA-256
  `bc49cee0aedbd61eb85d5c438b26da7138e8e86f875747f1ff6af53c99424e7d`.
- The complete distribution gate passed again after that immutable repin: 257
  Python tests, both Rust qualification suites, pinned SDK/Node checks, Ruff,
  deterministic packaging, `cfn-lint`, Packer 1.12.0 validation, actionlint,
  and diff checks.
- Authorized identity `arn:aws:sts::225478700523:assumed-role/`
  `AWSReservedSSO_AdministratorAccess_c8906abb6cf545fa/jonathan.e-vapi`
  submitted all ten final rendered template bodies to AWS
  `ValidateTemplate`; all ten passed in `us-west-2` and all ten passed in
  `us-east-1`. This validation created no stack or other AWS infrastructure.
