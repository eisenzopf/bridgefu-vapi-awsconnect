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
| Active stage | **Stage 3 — update and finish retained Oregon diagnostic** |
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
| Next permitted AWS action | **NONE until the direct-only Vapi assistant boundary, exact replacement-status diagnostic, and runtime-restoration regression pass locally.** Then inspect a retained-Oregon-only qualification change set before one Web smoke; SIP-source smoke remains blocked |

## Source under evaluation

### Bridgefu runtime

| Field | Value |
|---|---|
| Repository | `eisenzopf/bridgefu` |
| Local worktree | `/Users/jonathan/Developer/bridgefu-main-clean` |
| Branch | `codex/vapi-tls-rtp-evidence` |
| Commit | `22424d27650979e7e2071a5d0c1d17b6b2ebcb72` |
| Local delta | None; the named SIP-egress media-bind fix is committed and pushed |
| Pull request | [bridgefu#4](https://github.com/eisenzopf/bridgefu/pull/4) |
| PR state at last update | Open, not merged |
| Dependency posture | Exact crates.io `rvoip = 0.3.8`; no local rvoip dependency |

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
| Implementation commit | `bb6a6ebaf40b1bfcae7511f1ebffe4a828260d4a` |
| Local delta | None before this ledger correction; the source lock is repinned to Bridgefu `22424d2` and pushed |
| Pull request | [bridgefu-vapi-awsconnect#26](https://github.com/eisenzopf/bridgefu-vapi-awsconnect/pull/26) |
| PR state at last update | Draft, open, not merged |

The distribution branch contains the candidate optional-mode URI behavior,
scheme-aware qualification checks, Vapi retry/reconciliation diagnostics, and
sequential Oregon-then-Virginia workflow structure. These changes remain under
evaluation until Stage 3 proves the live contract.

## Stage status

### Stage 1 — Local contract gate: PASSED

Completed against the source commits above:

- [x] Distribution Python unit suite: **265 passed**.
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
- [x] Repeated the affected gate after the Bridgefu evidence commit was pushed,
  the distribution lock was repinned, and the retained-harness boundary fixes
  were added: **265 passed** plus local release validation.

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
- [ ] Run Bridgefu Web SDK end-to-end smoke.
- [ ] Run rvoip SIP-source end-to-end smoke after Web passes.
- [ ] Run Vapi create/delete/recreate resilience cycle.
- [ ] Tear down and produce zero-resource evidence.

Bridgefu `22424d2` is now installed in the retained environment and the
corrected call crossed ICE, authenticated to Vapi, negotiated TLS plus
`RTP/SAVP`/SDES-SRTP, and no longer failed on the first outbound RTP write.
The Web gate still failed before Amazon Connect. The stack-owned assistant was
temporarily configured by appending the direct tool and prompt while retaining
its production `prepare_handoff` tool, inline `transferCall`, and original
prepare/transfer prompt. The Vapi artifact consequently proves exactly one
`prepare_handoff` call and exactly one `bridgefu_direct_handoff` call, with no
`transferCall`. The direct call returned the safe category
`bridgefu_replacement_unavailable`; no Amazon Connect leg was started.

The mixed tool surface is an exact qualification-harness defect. It is not yet
evidence that the extra prepare call caused replacement to fail. The current
Bridgefu control client also catches Python `HTTPError` through its broader
`URLError` branch, so any Bridgefu HTTP 4xx/5xx is currently collapsed into the
same `bridgefu_replacement_unavailable` category as DNS, TLS, connection, and
timeout failures. A retry cannot distinguish those causes and is blocked.

### Stage 4 — Finalize product behavior: IN PROGRESS

The named SIP-egress media-bind fix is locally and live-probe validated, but the
qualification harness is not ready for another call. The next implementation
must create a qualification-owned direct-only Vapi assistant and dedicated
identity binding instead of patching the product assistant, require exactly one
successful direct tool call and zero other tool calls, preserve the exact
upstream Bridgefu HTTP status without retaining its body or URL, and repair the
failed runtime-restoration proof. Final local and remote CloudFormation
validation must be repeated after those changes and before the retained stack
is changed.

### Stage 5 — Fresh Oregon release qualification: NOT STARTED

Blocked on Stages 3 and 4.

### Stage 6 — Fresh Virginia release qualification: NOT STARTED

Blocked on a passing fresh Oregon release qualification.

### Stage 7 — Seal candidate: NOT STARTED

Blocked on passing qualifications in both regions.

### Stage 8 — Publish customer release: NOT STARTED

Blocked on a signed, sealed candidate.

## Current CI state

Last observed on 2026-08-13 against the current pushed heads:

### Bridgefu PR #4

- `infrastructure`: passed.
- `image (arm64)`: passed.
- `image (amd64)`: passed.
- `test`: passed.
- `Trivy`: passed.

Head checked: `22424d27650979e7e2071a5d0c1d17b6b2ebcb72`.

### Distribution PR #26

- `validate`: passed.
- `sdp-diagnostics`: passed.
- `qualification-client`: passed.

Current CI run: `31726812109`, head
`bb6a6ebaf40b1bfcae7511f1ebffe4a828260d4a`.

CI monitors are not running locally. CI completion must be read explicitly
before updating these states.

## Evidence inventory

| Evidence | Location or identity | State |
|---|---|---|
| Qualification plan | `docs/maintainers/CLOUDFORMATION_RELEASE_QUALIFICATION_PLAN.md` | Committed and pushed |
| Status ledger | `docs/maintainers/CLOUDFORMATION_RELEASE_QUALIFICATION_STATUS.md` | Committed and pushed; this update is local pending the next implementation commit |
| Bridgefu implementation commit | `22424d27650979e7e2071a5d0c1d17b6b2ebcb72` | Pushed, unmerged; all current checks passed |
| Distribution implementation commit | `bb6a6ebaf40b1bfcae7511f1ebffe4a828260d4a` | Pushed, unmerged; all three current CI jobs passed, but the live Web gate found a later harness defect |
| Local test results | Current task execution logs | Passed as listed above |
| Remote template-body validation | AWS account `225478700523`, both supported regions | Passed against current branch render |
| Oregon A/B SIP/SDP traces | Retained diagnostic execution `bfq-d19854f1-1` | Passed; `sip:...;transport=tls` produced actual TLS plus RTP/AVP in optional mode |
| Oregon Web diagnostic evidence | `target/diagnostic/bfq-d19854f1-1/qualification/retained-web-smoke-authready-22424d2-3/` | Failed: mixed Vapi tool surface, unclassified replacement rejection/transport result, and runtime restoration failure |
| Oregon passing end-to-end smoke evidence | — | Not created |
| Oregon zero-resource receipt | — | Not created |
| Virginia qualification evidence | — | Not created |
| Signed candidate receipt | — | Not created |

## Blockers and decisions required

1. Neither implementation PR should be treated as qualified until both live
   Stage 3 sources pass and retained-environment cleanup proves zero state.
2. The retained diagnostic must not be updated with an aggregate nested-stack
   change set that proposes replacement of persistent or call-path resources.
3. No further call is permitted while the Web assistant exposes production
   tools, Bridgefu HTTP rejection is collapsed into transport unavailability,
   or runtime restoration lacks a passing regression and receipt.

## Next actions

The next actions, in order, are:

1. Replace the temporary assistant overlay with a separately created,
   qualification-owned Vapi assistant whose complete model surface contains
   one marked prompt, one direct function-tool ID, and no inline tools. Build
   its request from the selected model/voice outputs rather than copying a Vapi
   response containing read-only or unrelated fields.
2. Give the direct-handoff Lambda a qualification-only identity-binding secret.
   Bind it to the verified temporary assistant and organization; do not change
   the product assistant's binding. Create the phone only after the assistant
   and binding are exact. Cleanup must delete the phone first, unbind only the
   exact direct identity, delete the exact assistant, then delete the exact
   direct tool while leaving the shared credential and product assistant
   untouched.
3. Split Bridgefu control `HTTPError` from transport failure. Retain only a
   bounded exact HTTP status and low-cardinality category, never the body, URL,
   bearer, call identity, or route. Require Web evidence to contain exactly one
   successful direct call with `accepted=true` and zero prepare, transfer, or
   other tool calls.
4. Add normal, ambiguous-create, collision, partial-create, concurrent-change,
   exact-delete, crash-recovery, product-assistant-unchanged, replacement-status,
   and runtime-restoration regressions. Pass Python tests, Ruff, deterministic
   packaging, rendered-template lint/policy checks, and exact remote
   `ValidateTemplate` in both supported regions.
5. Inspect a retained-Oregon-only CloudFormation change set and reject any
   customer-stack or persistent-resource replacement. After it applies and
   readiness plus clean transient state are proven, run exactly one Web SDK
   smoke. If it fails, diagnose that same call using the now exact replacement
   status; do not run the SIP source.
6. After Web passes, run the rvoip SIP-source smoke and Vapi
   create/delete/recreate resilience cycle in the same retained environment.
7. Tear down the retained environment and produce exact zero-resource evidence.
8. Freeze the final sources, repeat the full local gate and exact private remote
   CloudFormation validation in both regions, then proceed to fresh Oregon.

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
- Private exact-URL validation execution `bfq-s11a1ae6-1` uploaded and
  journaled 25 AES-256 S3 object versions under its unique `diagnostics/`
  prefix. All ten exact VersionId template URLs passed `ValidateTemplate` in
  both regions. Receipt:
  `target/diagnostic/bfq-s11a1ae6-1/validation-receipt.json`.
- The exact product root VersionId is
  `eYlOKr1wMYLgMB9mGcl9WfYLeyi4SzsW`; its tag set is empty, so it is private.
  Read-only stack checks prove `bridgefu-bfq-s11a1ae6-1` does not exist in
  either region. No release version, AMI publication, or `latest` pointer was
  created.
- Distribution commit `11a1ae62add89fc3e7955eaa80cd245cc88d8d49`
  was pushed to `origin/codex/staged-vapi-qualification`.

### 2026-08-13 — Retained Oregon update reviewed and constrained

- A nested aggregate change set against the final qualification template was
  created for review only. CloudFormation proposed broad replacements across
  runtime, data, secrets, networking, and other nested resources because the
  retained stack predates the final nested-template dependency/output model.
  The change set was not executed and was deleted.
- Four exact child-stack updates were then reviewed and applied independently:
  Configuration updated its Lambda code and immutable validation outputs;
  HandoffService updated only the prepare, transfer, and lookup Lambda code;
  VapiResources updated only the provisioner Lambda and added non-secret
  outputs; Runtime added only the gateway-role output. Each child reached
  `UPDATE_COMPLETE` without replacement.
- A second aggregate review still proposed broad nested replacements even
  after child convergence. It was not executed and was deleted. This proves an
  aggregate retained-stack migration is unsafe; it does not indicate a product
  failure in a fresh deployment.
- The root remains `CREATE_COMPLETE`. The Bridgefu instance remains
  `i-0aa9e3747232e17dd` and the Vapi assistant remains
  `aab176b8-22da-458e-aa84-22c7318addf3`. No EC2, VPC, DynamoDB, Connect,
  certificate, secret, or customer call-path resource was replaced.
- The permitted retained path is now a diagnostic-only compatibility product
  root derived from the deployed product template. It may expose the new child
  outputs but must retain the deployed nested resource definitions and pass a
  recursive change-set review proving no replacement. This compatibility root
  can never become a customer release artifact; fresh Stage 5 qualification
  must deploy the exact final customer template.
- Recursive review proved even the output-only product compatibility root
  caused CloudFormation to reinterpret directly updated nested stacks and
  propose replacements. It was not executed and its change set was deleted.
- Replaced that unsafe approach with standalone diagnostic add-on stack
  `bridgefu-bfq-d19854f1-1-direct`. Its exact template passed `cfn-lint` and
  AWS `ValidateTemplate` in both regions. The reviewed create change set
  contained exactly 11 `Add` actions for qualification-only API Gateway,
  Lambda, IAM, log-group, and disposable-secret resources and no modification
  or replacement.
- The add-on reached `CREATE_COMPLETE`. The retained root stayed
  `CREATE_COMPLETE`; instance `i-0aa9e3747232e17dd`, assistant
  `aab176b8-22da-458e-aa84-22c7318addf3`, Connect instance
  `fb81d6a6-eb92-4301-8812-6c3f3c034ffb`, Network child, and HandoffService
  child identities are unchanged. The add-on is cleanup-owned and is never a
  customer release artifact.
- The retained harness now merges the unchanged root, exact child-stack, and
  add-on outputs through a strict diagnostic-only adapter; the controller's
  complete required-output contract passes live. The corrected demo-site ZIP
  was rebuilt from Bridgefu `2fb2eaed` and the actual
  `@bridgefu/webrtc-browser` package; archive SHA-256 is
  `cfa04f3a2fc745f899b90e2cc0b4a21334ac3f3dfbd3dc3375f09068a063ab08`.
- A pre-live cleanup audit found that the provisioning resilience cycle could
  leave its recreated Vapi IDs outside CloudFormation's original physical ID.
  The controller now reconciles the exact deterministic owner, deletes those
  resources before stack teardown, proves assistant/tool/credential absence,
  and blocks stack deletion if cleanup cannot be proven. Full unit suite:
  **259 passed**; Ruff and diff checks passed. No live Vapi resilience mutation
  was attempted before this fix.
- The cleanup correction was committed and pushed as distribution commit
  `99c172bdef9c6ebac8fcbe95fa6756d75c8c82c3`. The retained Web, SIP, and Vapi
  resilience wrappers identify that exact diagnostic harness source.
- The exact Bridgefu `2fb2eaed` source is compiling on retained ARM instance
  `i-0aa9e3747232e17dd`. The remote build checked the Git commit and pinned
  Cargo.lock SHA-256 before compilation; observed rvoip paths are crates.io
  `0.3.7`. The currently installed service remains active and `/readyz` remains
  healthy; no binary replacement or live call has occurred yet.
- The first clean ARM build command reached the AWS-RunShellScript default
  3,600-second execution limit while compiling the final Bridgefu executable.
  This was an orchestration timeout, not a Rust compiler failure: all pinned
  dependencies had compiled, the target cache remained intact, no candidate
  binary was installed, and the existing service stayed active and ready. The
  same verified source/cache is being resumed with an explicit 7,200-second
  SSM document execution timeout; no dependency, configuration, or runtime
  input changed.
- The resumed exact build succeeded. Candidate binary SHA-256 is
  `f67543541105ff7a2e2b39774e86ba495d11248d09c08c49059b96feccf84bff`;
  Cargo reported a successful optimized release build of Bridgefu v0.9.0.
- The prior installed binary SHA-256
  `8bf8fbde0a7dd3c67f3e7e301fd2ef8dc79e3e6c3b4dc69c43db06dc5feace3d`
  was copied to the root-only diagnostic backup, the candidate was installed
  atomically, and Bridgefu was restarted once. Systemd is active, `/readyz`
  passed after startup, the installed digest matches `f6754354…`, and the
  backup digest remains exact. No live call has run against the new runtime
  yet; the next gate is the independent direct mandatory-SRTP control.
- The first post-install direct-control attempt stopped before browser
  navigation or any call. Exact root cause: the local `make qualification-test`
  gate ran `npm ci`, which correctly removed the previously downloaded
  Playwright browser; the harness's pinned Chromium executable path therefore
  did not exist and browser launch failed. This is a local prerequisite defect,
  not a Bridgefu, SIP, SRTP, Connect, or Vapi call failure. The candidate and
  remote workflows already install pinned Chromium explicitly. The retained
  workstation will now run that same pinned install command and verify the
  executable before retrying this gate.
- Pinned Playwright Chromium 151.0.7922.34 was installed with the same command
  used by the candidate workflow and its exact executable path was verified.
- The direct mandatory-SRTP control then passed on runtime digest `f6754354…`.
  All 24 closed checks are true: agent readiness/contact/media/hangup, SIP 200,
  ACK, exact one correlation header, DNS/SIPS/TLS Contact, actual TLS, SIPS,
  RTP/SAVP, SDES-SRTP, installed contexts, answer, private DNS, terminal SSM
  commands, absent probe/run artifacts, restored configuration, and Bridgefu
  readiness. Evidence is in
  `target/diagnostic/bfq-d19854f1-1/qualification/`
  `direct-secure-control-99c172b/direct-secure-control.json`.
- The first corrected Bridgefu browser SDK smoke exited without a pass
  artifact. Its retained-only wrapper phase was outside the production failure
  evidence schema, so the wrapper's best-effort evidence call wrote no receipt
  and the sanitized error was not preserved. This is a diagnostic-wrapper
  observability defect; no source result is claimed. Cleanup audit proves zero
  owner-equivalent temporary Vapi phones, absent temporary Web runtime, active
  and ready Bridgefu with unchanged `f6754354…` digest, and only expected
  versioned cleanup-journal history in S3. The retained wrappers now write a
  bounded redacted failure receipt before the schema-bound best-effort capture.
  The Web gate will be rerun; the SIP-source gate remains blocked on it.
- The preserved Web failure receipt identifies the exact pre-call cause:
  local `bridgefu validate` correctly resolved the generated runtime's
  `env:` references, but the workstation subprocess lacked values that exist
  only on EC2. The controller now supplies bounded synthetic placeholders for
  bearer, control-HMAC, and Vapi SIP-password references only to that local
  semantic-validation subprocess. The serialized/uploaded configuration still
  contains only `env:` references; no real secret is copied into source,
  arguments, config, logs, or evidence. Focused tests: **55 passed**; full unit
  suite: **260 passed**; Ruff and local release validation passed. The failed
  Web attempt placed no call and its temporary phone/runtime cleanup remained
  proven.
- The synthetic local-validation correction was committed and pushed as
  distribution commit `d7b1146d335cc952326b3f21f19451eee7f40d82`.
- The next retained Web attempt again stopped before placing a call. AWS CLI
  rejected `--cli-input-json file:///dev/stdin` for the Secrets Manager write,
  so the failure was command serialization at the harness boundary—not Vapi,
  Bridgefu, WebRTC, SIP, Connect, or media behavior. A non-mutating probe against
  a deliberately nonexistent secret proved that this installed AWS CLI accepts
  the secret body through `--secret-string file:///dev/stdin` while keeping the
  non-secret secret ARN on argv.
- `put_secret_json` now uses that verified shape. The stdin document contains
  only the compact secret value; credentials and secret values remain absent
  from argv, environment variables, source artifacts, logs, and evidence. The
  focused regression passed, the complete unit suite passed **260/260**, Ruff
  passed for the changed files, and local release validation passed. The fix was
  committed and pushed as
  `0fc67f71623e88a3474e86d513b92a095df2c34a`.
- The mandatory post-failure cleanup audit passed before another retry: zero
  owner-equivalent temporary Vapi phones, zero Bridgefu direct tools, zero
  marked assistant prompts, zero Web-runtime object versions, no temporary
  browser-media security-group rule, and no EC2 Web runtime directory,
  systemd drop-in, or temporary runtime secret file. Bridgefu remains active
  and ready with unchanged installed binary digest `f6754354…`; both retained
  CloudFormation stacks remain `CREATE_COMPLETE`.
- The next Web-only retry crossed the fixed Secrets Manager boundary but still
  stopped before a call. Exact SSM stderr showed that the Web runtime installer's
  embedded Python had received `rstrip("\\n")` and its output newline as two
  physical AWS command lines. Bash accepted the outer heredoc, but Python
  rejected the resulting unterminated string literal. This was another harness
  serialization defect, not a Vapi, Bridgefu, WebRTC, SIP, Connect, or media
  result.
- The generator now preserves those Python newline escapes. The regression
  extracts and validates all three actual program layers: the outer SSM shell
  passes `bash -n`, the emitted runtime wrapper passes `bash -n`, and the
  embedded Python compiles. The complete unit suite again passed **260/260**,
  Ruff passed for the changed files, and local release validation passed. The
  fix was committed and pushed as
  `13be5aea6eb51d931e7c3a0e0862d9003ba02dce`.
- Post-failure cleanup again passed before retry authority: zero owned Vapi
  phones, direct tools, and prompt markers; empty disposable SIP-auth secret;
  zero Web-runtime S3 versions; no browser media rule; no EC2 Web runtime,
  systemd drop-in, or temporary secret file; active/ready Bridgefu with the
  unchanged `f6754354…` digest.
- The following Web-only attempt successfully validated and installed the EC2
  runtime, but stopped before a call because the install command's stdout
  contained Bridgefu's `configuration is valid` line followed by the closed
  JSON receipt. The strict parser rejected that two-line output as designed.
  Exact SSM evidence proved the install and subsequent cleanup commands both
  completed successfully; no product call-path result was inferred.
- The generated installer now redirects only the successful validation line to
  `/dev/null`; validation failures remain on stderr, while SSM stdout is reserved
  for the single closed receipt. The generator also preserves each receipt's
  `printf` newline escape on one physical command line. The regression asserts
  exactly one install-receipt producer. All **260** unit tests and local release
  validation passed. The fix was committed and pushed as
  `7b3d399bd28d1b910849263f4b65022962d2f942`.
- Cleanup was re-proven after this failure: zero owned Vapi phone/tool/prompt,
  empty disposable auth secret, zero Web-runtime object versions, no media
  rule, and a successful EC2 cleanup receipt with Bridgefu ready.
- The next Web attempt passed the closed runtime install receipt and advanced to
  port-forward setup, then stopped before dialing because this workstation did
  not have AWS's `session-manager-plugin`. This was a local dependency preflight
  omission; the EC2 service, Vapi destination, SIP exchange, Connect contact,
  and media path were not exercised.
- The controller now requires `session-manager-plugin` during its initial input
  validation, before AWS or Vapi mutation. Candidate and remote-qualification
  workflows install AWS version `1.2.835.0` from the versioned AWS S3 URL and
  require exact package SHA-256
  `7c6dcad12518571cc7959a713e6a8ae1bdf6ed66fd9bee37dc189e39ca58ae03`.
  The workstation uses the same `1.2.835.0` binary extracted from AWS's signed,
  Apple-notarized package in `/Users/jonathan/.local/bin`; source and installed
  binary digests match.
- The new preflight/workflow regression passed, the full unit suite passed
  **261/261**, actionlint passed for both live workflows, and local release
  validation passed. The fix was committed and pushed as
  `6ba97cdb2996607911fe999950e56ac640f85336`.
- Cleanup was again proven before retry: zero owned Vapi phone/tool/prompt,
  empty disposable auth secret, zero Web-runtime versions, no media rule, no
  runtime overlay/drop-in/temp-secret file, and active/ready Bridgefu on the
  unchanged `f6754354…` digest.
- The first attempt with the Session Manager plugin crossed runtime install and
  both tunnel starts, but did not terminate within the call/cleanup deadline.
  Process inspection proved an AWS `start-session` child and an orphaned
  `session-manager-plugin` descendant retained the controller's stdout/stderr
  pipes. The controller terminated only the immediate process, then blocked in
  an unbounded second `communicate()`. This was local process-tree cleanup, not
  an AWS session, Vapi, Bridgefu, Connect, SIP, or media result.
- The single attempt was interrupted only after that exact state was proven.
  A bounded Vapi query found **zero calls** for the stack assistant during the
  attempt. Post-interrupt cleanup proved zero owned phone/tool/prompt, an empty
  disposable auth secret, zero Web-runtime S3 versions, no media rule, no EC2
  overlay/drop-in/temp-secret, and active/ready Bridgefu on `f6754354…`.
- Every harness subprocess now starts in its own OS session. All cleanup paths
  send bounded TERM then KILL to that entire owned process group, so an orphaned
  plugin cannot retain a pipe indefinitely. Regressions prove session isolation
  and group escalation without falling back to a single-process kill. The full
  unit suite passed **263/263** and local release validation passed. The fix was
  committed and pushed as
  `e88a21524b9eb0329b7e1cb5da2d3d3b7e5cb772`.
- The next Web attempt terminated cleanly and exposed the first actual API
  contract failure: Bridgefu created the direct route with HTTP 201, but the
  harness rejected the private response before browser attachment. Pinned
  Bridgefu source proved two incorrect harness assumptions. `LegKind` is
  serialized as `webrtc`, not `web_rtc`; and Bridgefu deliberately returns a
  43-character one-use attachment token plus a distinct `bfs1.<JWT>` signaling
  credential. The harness had required those two credentials to be identical.
  No Vapi call was created.
- Both the Python route parser and the Playwright source validator now require
  the actual pinned Bridgefu contract: inbound `webrtc`, bounded `bfs1.`
  signaling credential, `token.<signaling credential>`, and the separate
  `bridgefu.attach.<attachment token>`. Regressions reject conflating the two
  credentials and bind the browser validator to the same shape. All **263**
  unit tests, Node syntax validation, and local release validation passed. The
  fix was committed and pushed as
  `ba033da642c16b62720e7d0ac78bad2029299265`.
- Cleanup passed before another retry: zero owned Vapi phone/tool/prompt, empty
  auth secret, zero Web-runtime versions, no media rule, and no retained Web
  runtime on EC2.
- The corrected route contract passed on the next attempt. The harness created
  the Bridgefu WebRTC route and then stopped at the required store-before-
  transfer boundary: this AWS CLI also rejects DynamoDB
  `--cli-input-json file:///dev/stdin`. The DynamoDB item was not written and
  no Vapi call was created, so the ordering gate behaved correctly.
- A non-mutating request to a nonexistent table proved this CLI accepts the
  private item through `--item file:///dev/stdin`. The harness now puts the
  non-secret table name and fixed condition expression on argv while keeping
  the correlation ID, one-use token ID, and synthetic context only on stdin.
  The regression proves those private values never enter argv and validates
  the exact item shape. All **263** unit tests and local release validation
  passed. The fix was committed and pushed as
  `66a871530f68fe5248e2e4905c4f1e62f33ccc00`.
- Cleanup passed again: zero owned Vapi phone, no media rule, empty auth secret,
  and the retained handoff table still contains zero records.
- The next Web-only attempt crossed every previously repaired boundary: the
  temporary Vapi endpoint and direct tool were provisioned, the EC2 Web runtime
  was installed, both SSM tunnels started, Bridgefu returned a valid one-use
  browser attachment, and the synthetic DynamoDB context was stored before any
  transfer. The actual Bridgefu SDK browser never reached its connected state,
  so the controller correctly withheld the Vapi call trigger.
- Closed analysis of 154 runtime events proves that WSS signaling reached
  Bridgefu and completed offer/answer signaling (`have-remote-offer` then
  `stable`). The media boundary did not complete: zero ICE connected/completed
  transitions, two no-candidate-pair warnings, 48 IPv6-destination writes on an
  IPv4 socket rejected by the kernel, and zero DTLS-connected transitions. This
  is now isolated to browser-to-Bridgefu ICE candidate pairing; it is not a Vapi,
  SIP-transfer, Amazon Connect, credential, or WSS-admission result.
- Cleanup after that failed attempt removed the exact synthetic correlation
  record and proved the retained table count returned to zero. It also proved
  zero browser-media security-group rules. The existing wrapper cleanup had
  already removed the temporary Vapi objects, assistant overlay, runtime
  object, disposable secret value, EC2 runtime overlay, and SSM processes.
- The harness now retains only closed-enum SDK error and WebRTC state categories
  (`peer`, `ICE`, ICE gathering, and signaling) and fails immediately when the
  SDK reports a terminal startup error. It also tracks the exact controller-
  owned correlation key, deletes that DynamoDB item through private stdin, and
  performs a consistent-read absence check on every Web-smoke exit. No URI,
  SDP, address, credential, token, correlation ID, or customer value enters
  arguments or failure evidence.
- These diagnostics and cleanup guarantees were committed and pushed as
  `ab9c7ea125a67ca99d1404bfb9d55003d4f8b91c`. The full unit suite passed
  **265/265**, targeted Ruff and Node syntax checks passed, and local release
  validation passed. Exactly one instrumented retained Web attempt is now
  permitted; no SIP-source smoke or release workflow may run before it passes.
- Two invocations of that instrumented bundle stopped at their first read-only
  CloudFormation lookup because the retained wrapper inherited the expired
  default AWS profile even after `vapi-admin` SSO was refreshed. Neither
  invocation reached an AWS or Vapi mutation. The diagnostic invocation now
  explicitly exports `AWS_PROFILE=vapi-admin`; the authenticated identity was
  reverified before proceeding.
- The correctly profiled attempt reproduced the media failure with a precise
  browser result: SDK `signaling-failed`, peer connection `new`, ICE `new`, ICE
  gathering `complete`, signaling `stable`. In the same bounded interval,
  Bridgefu received the offer, returned to stable signaling, entered ICE
  `checking`, received browser candidates, produced no connected candidate pair,
  and never entered DTLS. The only WSS TLS warning was the controller's
  pre-call raw-port readiness probe; it was not the browser session. The only
  call-service error was a cleanup-time cancelled durable-work task.
- This directionality proves the browser completed its candidate gathering and
  Bridgefu consumed that signaling, while the browser received no usable
  Bridgefu candidate. rvoip 0.3.7's WSS answerer is configured for trickle ICE;
  the full-gather alternative is the minimum discriminating fix because it
  embeds the public Bridgefu candidate directly in the SDP answer.
- The Web qualification runtime now uses full ICE gathering. This is a
  qualification-only source setting and changes neither the customer SIP
  CloudFormation behavior nor the Bridgefu browser SDK. The controller's
  context absence verifier also accepts the AWS CLI's observed empty stdout for
  an absent DynamoDB item; live count independently proved the successful
  delete and zero retained records. The changes were committed and pushed as
  `b41417b44efad39c92dc28ae7f6d15d29a064ec3`; all **265** unit tests and local
  release validation passed. The next permitted action remains exactly one
  retained Web-only rerun.
- That full-gather rerun failed with the same closed browser result:
  `signaling-failed`, peer `new`, ICE `new`, gathering `complete`, signaling
  `stable`. A bounded Vapi query found zero calls for the stack-owned assistant
  in the attempt window. Full gathering therefore did not correct the failure
  and is rejected as the cause; the qualification overlay has been restored to
  its prior trickle-ICE posture.
- Correlated runtime evidence identified the earlier causal boundary. At
  `2026-08-13T13:10:28.290642Z`, the rvoip client INVITE transaction emitted
  exactly one `Failed to send initial request from Calling state` with the
  closed `operation_error` category. It then surfaced as one transaction-runner
  enter-state failure and one session state-machine failure. No Vapi call
  record existed because the outbound SIP request never reached Vapi.
- An independent, secret-free SSM probe ran on the retained EC2 and emitted
  only closed facts. DNS for the US Vapi SIP host passed, but TCP to its
  documented TLS listener on port 5061 timed out before a socket or TLS session
  was established: `dns=true`, `tcp=false`, `tls=false`, `category=timeout`.
  This reproduces the rvoip failure without Bridgefu, WebRTC, SIP parsing, SDP,
  authentication, or Vapi provisioning.
- Root cause in the deployed template: the Bridgefu gateway security group
  allowed outbound TCP/443 and UDP, but no outbound TCP/5061. Its inbound 5061
  rules made the security posture look symmetric during prior reviews. The
  customer call path is inbound Vapi -> Bridgefu and does not need this new
  egress; the corrected Bridgefu Web SDK qualification path deliberately
  originates Bridgefu -> Vapi and does.
- The code fix adds two qualification-only `AWS::EC2::SecurityGroupEgress`
  resources for TCP/5061 to Vapi's published US signaling addresses
  `44.229.228.186/32` and `44.238.177.138/32`. It does not add EU support or
  broaden the customer runtime security group. The Web overlay now dials the
  documented US TLS endpoint as `sip:<owned-user>@sip.vapi.ai:5061;transport=tls`
  and requires the independent Bridgefu event to prove actual TLS while keeping
  the URI scheme classified separately as `sip`.
- A new EC2-side DNS/TCP/TLS preflight runs before any temporary Vapi phone,
  tool, prompt overlay, or runtime secret is created. It retains no resolved
  address, certificate, socket error, SIP URI, credential, or remote response;
  any result other than all three closed booleans true stops the Web gate.
- One focused test command incorrectly used an unsupported dotted module path
  and ran zero tests. The supported discovery rerun exposed one fixture value
  mismatch, which was corrected without changing implementation behavior.
  Final local results: **267 unit tests passed**, deterministic release
  validation including rendered CloudFormation lint passed, Ruff passed, both
  browser Node syntax checks passed, and `git diff --check` passed. No release
  workflow, SIP-source smoke, Virginia run, candidate, or publication ran.
- The implementation and ledger through the root-cause fix were committed and
  pushed as distribution commit `f9e87120a1c451e143f64336b4a712eec43ce492`.
- Three retained add-on change-set creation requests made no AWS change while
  their contracts were corrected: the first omitted required previous
  parameter values, the second resolved no gateway security-group output from
  the compatibility root, and the third omitted the acknowledgement required
  by the add-on's unchanged named IAM role. A fourth change set included the
  two intended additions plus 11 unrelated non-replacement changes from
  resubmitted stack tags; it was rejected and deleted unexecuted.
- Change set `bfq-vapi-tls-egress-f9e8712-2` was then created without tag
  changes. CloudFormation reported exactly two actions: add
  `QualificationVapiTlsEgress1` and `QualificationVapiTlsEgress2`, both
  `AWS::EC2::SecurityGroupEgress`; there were no modifications, removals, or
  replacements. It was executed, and retained add-on stack
  `bridgefu-bfq-d19854f1-1-direct` reached `UPDATE_COMPLETE` with both resources
  `CREATE_COMPLETE`.
- The independent EC2-side preflight was rerun from the exact checked-in
  generator. It passed with `dns=true`, `tcp=true`, `tls=true`,
  `category=passed`, empty stderr, and no secret or remote-data output. This
  closes the outbound Vapi TLS prerequisite. Exactly one Bridgefu Web SDK smoke
  is now permitted; the SIP-source smoke remains blocked until Web passes.
- The first Web-only attempt after opening egress stopped before its SSM
  command and before any temporary Vapi resource. The generated reachability
  program contains readable blank lines, but `run_web_runtime_ssm` passed every
  `splitlines()` entry directly to the hardened encoder, which correctly
  rejects empty AWS command-array entries. The closed failure was
  `qualification SSM program is invalid`; this is harness serialization, not a
  Vapi, SIP, SDP, WebRTC, Connect, or media result.
- Post-failure zero state passed: handoff table count zero, no WebRTC media
  security-group rule, zero owned Vapi endpoints, and an empty disposable SIP
  authentication secret. The SSM runner now strips only empty source lines
  before encoding; a regression decodes the exact AWS parameter JSON and proves
  every resulting command is nonempty. The affected focused suites, all **267**
  unit tests, Ruff, deterministic release validation, and diff checks pass.
  One Web-only retry is permitted; the SIP source remains blocked.
- The normalized-command retry ran from distribution commit
  `602b418c5d8361e62c9e15b744515fda695dd2e6` and again stopped before browser
  readiness with the closed state `signaling-failed`, peer `new`, ICE `new`,
  gathering `complete`, signaling `stable`. The WebSocket offer did reach the
  exact retained Bridgefu runtime; this attempt is therefore distinct from the
  previously closed TCP/5061 egress failure. A bounded Vapi query found zero
  calls for the stack-owned assistant in the attempt window, so no SIP INVITE,
  SDP exchange with Vapi, handoff, or Connect call occurred.
- Exact on-instance runtime evidence at `2026-08-13T14:12:32Z` shows the WebRTC
  answerer accepted the remote offer and entered ICE checking. It then reported
  no usable candidate pair. Chromium's IPv4 candidates were TCP-active
  candidates, which rvoip correctly ignored; the remaining UDP candidates were
  IPv6. The retained EC2 WebRTC media socket is IPv4-only, so every attempted
  IPv6 send failed with the fixed operating-system category `address family not
  supported`. There was no IPv4/UDP server-reflexive browser candidate.
- Root cause is the qualification browser attachment's empty ICE-server list.
  In this browser/NAT environment, an empty list does not produce the public
  IPv4/UDP candidate required to reach the IPv4-only retained EC2 edge. This is
  a Bridgefu Web SDK qualification ICE configuration defect; it is not a Vapi,
  SIP, SDP, TLS, SRTP, Amazon Connect, or TCP/5061 result.
- The correction supplies the AWS-owned regional Kinesis Video WebRTC STUN
  endpoint on port 443 through the Bridgefu SDK's one-use route attachment.
  It does not add TURN credentials, a Vapi key, customer data, or a customer
  CloudFormation resource, and the Bridgefu EC2 side continues to advertise
  its configured public IPv4 directly. A regression requires the exact
  regional STUN URL in the generated browser attachment while keeping the
  server-side ICE list empty. No additional live retry is permitted until the
  local browser proves it gathers an IPv4/UDP server-reflexive candidate and
  all local gates pass.
- Cleanup after the failed retry is independently proven: the handoff table
  scan count is zero; the temporary media ingress rule is absent; the owned
  Vapi endpoint count is zero; the disposable authentication secret is `{}`;
  the Web-runtime S3 prefix has zero versions and delete markers; and a closed
  SSM receipt proves the overlay, systemd drop-in, and auth file absent with
  Bridgefu active and ready. The retained Oregon stacks remain intentionally
  deployed. The SIP-source smoke remains blocked.
- The exact local Playwright/Chromium runtime then exercised the configured
  Oregon STUN URL independently and produced a closed passing result:
  gathering complete, one IPv4/UDP server-reflexive candidate, no retained
  addresses, and `passed=true`. The browser harness now rejects an empty,
  foreign, or non-regional ICE-server attachment at its private input boundary
  and reports only bounded candidate-category counts if startup fails.
- The post-fix local contract ladder passed: all **267** Python unit tests; all
  4 rvoip SIP-source tests; all 16 direct-secure-probe tests; Rust formatting
  and Clippy with warnings denied; both browser syntax checks; Ruff; Lambda and
  deterministic release packaging; local release validation and `cfn-lint`;
  and Packer 1.12.0 initialization/validation using the ignored pinned binary.
  The first unqualified `make` invocation could not find Packer on `PATH`; it
  performed no build or AWS action, and the exact pinned rerun passed.
- AWS CloudFormation `ValidateTemplate` passed for all 13 rendered product,
  nested, qualification, and publisher templates in both `us-west-2` and
  `us-east-1` (**26/26** remote validations). No template deployment, candidate
  build, GitHub runner, Virginia smoke, version reservation, or publication was
  started. The next permitted live action is exactly one retained Oregon Web
  SDK smoke with this STUN-bound attachment; the SIP-source smoke remains
  blocked until it passes.
- The first post-STUN invocation stopped before `web_smoke` while launching the
  Amazon Connect authentication browser. It created no Vapi call or WebRTC
  attempt and is not counted as the permitted STUN-bound Web retry. Exact local
  cause: `make qualification-test` runs `npm ci --ignore-scripts`, which removes
  Playwright's package-local Chromium. The auth harness intentionally resolves
  that package-local browser, while the manual Make target previously restored
  only the Node packages. The release workflows already installed Chromium
  after `npm ci`; the direct/manual gate did not.
- `make qualification-test` now installs the exact lockfile-selected Playwright
  Chromium immediately after `npm ci`. A source contract locks that ordering.
  The corrected target passed all Rust tests, formatting, Clippy, browser
  installation, and both Node syntax checks. After that exact target completed,
  the local STUN preflight again produced one public IPv4/UDP server-reflexive
  candidate, and an isolated retained Connect authentication probe passed with
  a private storage-state file. Neither probe created a Vapi resource or call.
  Exactly one retained STUN-bound Web SDK smoke remains permitted; SIP remains
  blocked until it passes.
- The retained Web smoke from distribution commit
  `6a084d8bfafdb37d96f3c119992908fc3712590d` then reached the actual Bridgefu
  Web SDK with the regional STUN attachment. Its closed failure state was peer
  `new`, ICE `new`, gathering `gathering`, signaling `stable`, with two
  IPv4/UDP server-reflexive candidates, four IPv4/UDP host candidates, six
  IPv6 candidates, and ten TCP candidates. This proves the STUN correction is
  active in the real SDK path, but the browser still did not select an ICE
  candidate pair. Vapi was not invoked, so this is not a Vapi, SIP, SDP, TLS,
  SRTP, handoff-Lambda, or Amazon Connect result.
- Bridgefu runtime evidence for that same attempt shows the WebRTC offer was
  accepted and ICE entered checking. rvoip ignored unsupported browser TCP
  candidates and attempted IPv6 candidates that the IPv4-only EC2 socket could
  not use. No selected candidate pair was observed. A separate machine-readable
  Chromium probe proved the gathered IPv4/UDP server-reflexive address equals
  the exact public address authorized by the qualification security-group rule,
  without retaining or printing the address. A wrong browser source `/32` is
  therefore ruled out.
- Cleanup after this failure is independently proven again: the handoff table
  contains zero records; the temporary UDP 20000-20399 ingress rule is absent;
  the deterministic qualification Vapi phone match count is zero; the temporary
  authentication secret is exactly `{}`; the Web-runtime S3 prefix has zero
  versions and delete markers; and a closed SSM receipt proves the overlay,
  systemd drop-in, and temporary auth file absent with Bridgefu active and
  `/readyz` healthy. The retained Oregon stacks remain deployed intentionally.
- The next permitted work is diagnostic only: add closed browser evidence for
  received remote candidates and candidate-pair states, inspect rvoip 0.3.7's
  WebSocket answer/trickle path, and establish whether Bridgefu supplied a
  usable IPv4/UDP candidate to the browser. No further retained Web retry is
  allowed until that exact cause is proven and a regression passes. SIP-source
  smoke, Virginia qualification, candidate sealing, and publication remain
  blocked.
- The diagnostic harness now counts only closed, bounded facts from the actual
  browser peer: remote candidates passed to `addIceCandidate`, remote ICE
  completion, browser stats remote-candidate categories, candidate-pair states,
  and whether a pair was selected. It never emits an address, candidate string,
  SDP, peer identifier, credential, or customer value. Source contracts require
  these fields and prohibit reading `remoteDescription.sdp`. All **268** Python
  unit tests, browser syntax validation, Ruff, formatting, and diff checks pass.
  Source inspection confirms rvoip 0.3.7 creates the answer in trickle mode,
  sends that answer first, then starts a route-owned local ICE forwarder which
  should drain already-buffered candidates and send `ice-candidate` followed by
  `ice-complete`. The Bridgefu SDK serializes inbound WebSocket messages and
  applies those candidates only after the matching answer. One instrumentation-
  only retained diagnostic attempt is now permitted to determine which side of
  that contract failed; it is not a product smoke retry and cannot advance the
  Vapi or release gates by itself.
- The first instrumented retained attempt produced the exact signaling result:
  the Bridgefu server sent one IPv4/UDP host candidate and one ICE-complete
  signal; the SDK called the browser's `addIceCandidate` for that candidate and
  then applied completion. The browser still timed out before readiness. The
  post-failure stats query was empty because the SDK had already closed the peer,
  so it could not determine whether a candidate pair existed before cleanup.
  The gateway security group independently proves unrestricted UDP egress; the
  temporary inbound UDP rule and browser public `/32` were present during the
  attempt. This rules out missing server trickle signaling and an outbound-SG
  restriction, but does not yet distinguish browser pair construction from UDP
  packet delivery.
- The next diagnostic revision samples browser remote-candidate and candidate-
  pair stats every 100 ms and retains only per-category maxima after peer
  cleanup. The EC2 host has `tcpdump`; the next single attempt will run a
  count-only, address-free inbound/outbound packet observer for the WebRTC media
  port range. Together these observations will prove whether a pair was formed
  and whether ICE packets crossed the instance boundary. No packet body, IP,
  port outside the fixed configured range, SDP, candidate string, or identifier
  will be retained.
- The paired diagnostic captured one UDP packet entering the EC2 WebRTC media
  range and 49 leaving it. Across 898 browser stats samples, Chromium reported
  no remote candidate and no candidate-pair state, even though the SDK had
  called `addIceCandidate` once and then applied ICE completion. This proves the
  candidate crossed Bridgefu's WebSocket signaler but was not associated with a
  browser media section; AWS ingress/egress was not completely blocked.
- Exact crates.io source identifies the cause in `rvoip-rtc 0.3.7`:
  `RTCIceCandidate::to_json()` serializes every trickled candidate with
  `sdpMid: ""`, `sdpMLineIndex: 0`, and no username fragment. The empty MID
  names no SDP media section, while the valid zero m-line index is sufficient.
  The Bridgefu SDK now removes only an invalid empty `sdpMid` when a bounded
  integer `sdpMLineIndex` is present, preserving all nonempty MIDs and the exact
  candidate. Its regression passes a real rvoip-0.3.7-shaped candidate and
  asserts the browser receives the candidate plus m-line index without the
  empty selector. SDK typecheck, build, and all 20 tests pass.
- The SDK fix is committed and pushed on the existing Bridgefu qualification
  branch as `1fa3b364ba30f972600d904667563a1b4c0a156c`; no local rvoip fork is
  used. The distribution source lock now pins that remote commit, and a new
  deterministic demo-site artifact was built from it with archive SHA-256
  `e375ae9ede5cd0c737fff7880f3153df8d97ba8a0353d4d4477a4905fb529bdf`.
  The next permitted action is one retained Web smoke using exactly that sealed
  site. It tests the proven SDK correction at the current gate only; SIP-source
  smoke remains blocked until Web passes.
- That exact sealed-site run repeated the prior failure unchanged: one server
  IPv4/UDP candidate and ICE completion reached `addIceCandidate`, but Chromium
  remained peer/ICE `new` and reported no candidate pair across 898 samples.
  The minified deployed bundle was inspected and does contain the empty-MID
  normalization. Therefore the empty rvoip MID is a real interoperability defect
  and the SDK workaround is locally correct, but it is **not the live root
  cause** of this Oregon failure. The earlier status conclusion is superseded;
  no Vapi or release gate advanced.
- Cleanup is required and must be proven again before more live work. The next
  investigation must classify the offer/answer media and ICE attributes without
  retaining SDP, verify the server candidate's media-section association after
  normalization, and determine whether the 49 server-originated UDP packets are
  visible at the browser host. No additional Web retry is authorized until that
  diagnostic is implemented and locally tested.
- Cleanup after the disproving run is now proven: zero handoff records, no
  temporary media ingress, no owned Vapi phone, an exactly empty temporary auth
  secret, and no Web-runtime S3 versions or delete markers. The local Mac allows
  non-privileged count-only packet capture on its active interface, so the next
  diagnostic can compare browser-host and EC2 packet directions without
  retaining endpoints or payloads. The retained stacks remain otherwise
  unchanged and healthy.
- The next browser diagnostic is implemented and locally green. It samples only
  bounded counts for local/remote SDP media sections, rejected sections, MID,
  ICE credential, fingerprint, setup, inline-candidate and ICE-lite attributes;
  it also counts the normalized candidate's MID/index/username-fragment shape
  and whether `addIceCandidate` succeeded. Raw SDP, candidates, ICE credentials,
  addresses, and identifiers never leave browser memory. All **268** unit tests,
  browser syntax, Ruff, deterministic release validation, and diff checks pass.
  One paired browser/EC2 direction-only packet diagnostic is permitted next.
- The paired capture observed browser host UDP `out=1`, `in=1` and EC2 media-
  range UDP `in=1`, `out=49`; the exact EIP route uses the captured browser-host
  interface. Thus packets crossed both directions at least once, while the
  server's repeated checks did not result in a browser candidate pair. The first
  expanded failure line exceeded the controller's bounded diagnostic length and
  truncated before its SDP classification. The same closed values are now
  encoded compactly below that bound, with a source regression. One final
  classification-only attempt is permitted after cleanup; it must not be
  interpreted as a product/Vapi retry.
- The compact classification confirms the SDK workaround itself executed:
  empty MID count zero, absent MID count one, m-line-index-zero count one, and
  two successful `addIceCandidate` calls (the candidate plus completion) with
  zero failures. The local browser description had one audio and one application
  section, neither rejected, and 22 gathered candidates. The applied server
  description had one audio and one application section, neither rejected, two
  MIDs, two ICE-ufrag lines, two ICE-password lines, two fingerprints, one
  applied candidate, and no ICE-lite attribute. Despite this, the peer and ICE
  states remained `new` with zero candidate pairs. This further disproves the
  empty-MID defect as the live root cause.
- The remaining standards-relevant discriminator is whether bundled media uses
  one consistent set of transport parameters and whether the browser committed
  a non-null transceiver direction. The closed classifier now counts BUNDLE
  members, unique (not actual) ICE credential/fingerprint values, DTLS setup
  roles, and transceiver current-direction categories. The focused browser and
  source-contract tests pass; no raw value is retained.
- The sealed `74d3a66` classification run proves the offer/answer structure is
  internally consistent. The browser offer and server answer each contain one
  active audio section and one active application section, two BUNDLE members,
  one unique ICE username fragment, one unique ICE password, and one unique
  fingerprint. The server answer uses `setup:active` for both sections. The
  browser transceiver progressed from an initially null current direction to
  `sendrecv`. The normalized server candidate had no MID, retained m-line index
  zero, and both the candidate and end-of-candidates calls succeeded. Across
  897 samples Chromium nevertheless remained peer/ICE `new` with zero known,
  checking, succeeded, failed, selected, or nominated candidate pairs. This
  rules out rejected media, inconsistent BUNDLE credentials/fingerprints, an
  invalid DTLS answer role, a disabled transceiver, and the empty-MID defect as
  the current live cause.
- The matching Bridgefu runtime evidence is more specific: rvoip transitions
  its ICE transport to `Checking`, immediately reports that candidate probing
  has no candidate pairs, ignores TCP-active candidates, and attempts received
  IPv6 candidates on an IPv4-only WebRTC socket. It does not form a pair from
  either browser IPv4 server-reflexive candidate, even though the browser-host
  and EC2 count-only captures prove at least one UDP packet crossed in each
  direction. No Vapi call was created. The current gate is therefore a
  Bridgefu/rvoip WebRTC ICE candidate-pair problem before Vapi, SIP transfer,
  TLS/SRTP destination negotiation, Connect, or screen pop. No further live
  attempt is allowed until the exact rvoip 0.3.7 remote-candidate/pairing path is
  explained in source and covered by a local regression.
- Post-run cleanup is re-proven after that attempt: the handoff table contains
  zero records; the temporary UDP media ingress rule is absent; zero owned
  Vapi phones exist; the temporary authentication secret is exactly `{}`; the
  Web-runtime S3 prefix contains zero object versions and zero delete markers;
  and an SSM check proves the runtime overlay directory, systemd drop-in, and
  temporary authentication file are absent while Bridgefu is active and
  `/readyz` is healthy. The retained Oregon root and direct-probe add-on stacks
  remain `CREATE_COMPLETE` and `UPDATE_COMPLETE`, respectively.
- The source-level rvoip regression now reproduces the blocker without AWS.
  On the existing `codex/fix-sips-contact-fallback` worktree, a WebRTC peer was
  configured with `nat_1to1_ips=["192.0.2.44"]` and host-candidate mapping.
  The exact test expected the signaled candidate address to be `192.0.2.44`,
  but rvoip signaled `127.0.0.1`. This is the expected failing-before-fix result
  and confirms that the rvoip 0.3.7 one-to-one NAT option is not applied to the
  gathered/signaled ICE candidate. No AWS mutation occurred for this test.
- The retained-release workaround keeps the exact crates.io rvoip 0.3.7
  dependency and does not introduce a local rvoip build. The temporary WebRTC
  runtime overlay now gives both the browser route and Bridgefu's server peer
  the same regional AWS STUN endpoint and leaves `nat_1to1_ips` empty. This asks
  the ICE implementation to gather a real server-reflexive EC2 address instead
  of relying on the ignored address-rewrite option. The focused runtime tests
  require the exact regional STUN URL and an empty NAT mapping list; all seven
  pass, as do Ruff check/format and the diff check. A new live call remains
  blocked until the broader local contract suite is green.
- The broader local gate is now green: all 268 Python unit/contract tests pass;
  deterministic release validation (including rendered CloudFormation lint)
  passes; compile/lint, Ruff format, and diff checks pass. The workaround is
  therefore eligible for one retained Oregon Web smoke. It is not a release
  result and does not authorize Virginia, a candidate build, sealing, or
  publication.
- The single retained Web attempt from distribution commit `b306488` crossed
  the former ICE boundary. Bridgefu's WebRTC peer reached `connected`, it
  originated the authenticated TLS SIP call to Vapi, Vapi answered, and the SIP
  state became active. The later browser error, `Bridgefu browser DTMF was not
  accepted`, occurred only after that call had already terminated and is not
  the initiating failure.
- Same-call Bridgefu evidence identifies the initiating failure at the first
  browser-audio frame sent toward Vapi: the plain RTP write returned Linux
  `EINVAL`, `SipMediaStream` stopped, Bridgefu sent BYE, and Vapi recorded the
  otherwise clean call as `customer-ended-call`. Vapi emitted no SIP, transfer,
  or media error for this call. This proves the AWS-STUN workaround fixed the
  ICE blocker and isolates the new boundary to Bridgefu's outbound SIP media
  socket before DTMF, handoff, or Connect.
- The exact source defect is in Bridgefu's rvoip projection. Secure and
  WebRTC-to-SIP recipes intentionally put the unused clear SIP listener on
  loopback. Bridgefu constructed rvoip from that listener address, which also
  left `Config::local_ip` on loopback even while advertising a public media
  address. rvoip allocates RTP sockets from `Config::local_ip`; a loopback-bound
  UDP socket cannot send to Vapi's public RTP address and Linux returns
  `EINVAL` for that operation.
- Bridgefu commit `7c8089096894792b7694a5a1353d086ca551a6c9` fixes the
  projection without exposing the clear SIP listener: `bind_addr` remains on
  loopback, while public-media recipes set rvoip's RTP `local_ip` to the
  matching wildcard address family. Regression assertions cover both the
  flagship secure SIP recipe and WebRTC-to-SIP recipe. Validation passed all
  151 Bridgefu binary tests, the full direct browser/Vapi/Connect handoff test,
  the real SRTP transcoding/DTMF/BYE test, Clippy with warnings denied, format,
  and diff checks. The distribution source lock now pins this remote commit;
  the Cargo lock digest is unchanged and still resolves exact crates.io rvoip
  0.3.7.
- Cleanup after the failed live attempt is independently re-proven: zero
  DynamoDB handoff records, zero temporary UDP media ingress rules, zero owned
  Vapi phones, an exactly empty temporary SIP-auth secret, zero Web-runtime S3
  versions/delete markers, and an SSM receipt proving the runtime overlay,
  systemd drop-in, and temporary auth file absent while Bridgefu is active and
  ready. No retry is authorized until the repinned distribution contracts pass
  and a new deterministic SDK/demo artifact is sealed.
- The exact repinned Bridgefu `7c8089096894792b7694a5a1353d086ca551a6c9`
  source built successfully on the retained ARM instance. The candidate binary
  SHA-256 is
  `29db3618fa9d7869c78bfae34f785cf85793b783d7dd73164e3eec66d6f5e6f4`;
  the build checked the exact Git commit, unchanged Cargo lock digest, mode
  `0755`, and `root:root` ownership before installation.
- The guarded installation first verified the running binary digest
  `f67543541105ff7a2e2b39774e86ba495d11248d09c08c49059b96feccf84bff`,
  preserved that exact binary in a new root-only rollback directory, installed
  the new candidate atomically, and restarted Bridgefu once. The installed and
  backup digests match their expected values, systemd is active, and `/readyz`
  is healthy. No call has yet been run against this binary; the next and only
  authorized live action is one retained Oregon Bridgefu Web SDK smoke.
- The one authorized retained Web SDK smoke against distribution `1efa4b2`
  and Bridgefu `7c80890` did not pass, so no SIP-source smoke or release action
  is authorized. The former WebRTC boundary remained fixed: browser and
  Bridgefu ICE reached `connected`, with a selected candidate pair. Bridgefu
  then originated the Vapi SIP leg, received the expected initial `401`
  challenge, but Vapi rejected the authenticated retry with SIP `403`; rvoip
  reported call failure and closed the WebRTC peer. No Vapi call record,
  transfer, handoff, or Connect call was established. The browser's final
  `signaling-failed` category is therefore a consequence of that exact SIP
  rejection, not a new ICE failure. Retries are frozen while the authenticated
  INVITE and the effect of the new rvoip `Config::local_ip` projection on SIP
  signaling are examined from this same execution.
- Cleanup and the absence of downstream side effects are independently proven
  after that failure: Vapi reports zero calls for the owned assistant in the
  execution window and zero owner-equivalent temporary phones; DynamoDB has
  zero handoff records; the temporary browser media ingress rule is absent;
  the temporary authentication secret is exactly `{}`; and the Web-runtime S3
  prefix contains zero versions and zero delete markers. Read-only SSM command
  `5f8dd888-47b0-468e-a7df-bf18c6c86085` proves the runtime overlay, systemd
  drop-in, and temporary auth file are absent while Bridgefu is active, ready,
  and still running exact digest `29db3618…e6f4`. The retained stacks remain
  available for diagnosis; no retry has been started.
- A separate no-call diagnostic then created one exact owned Vapi SIP endpoint,
  waited for API status `active`, and used exact crates.io rvoip `0.3.7` to send
  SIP `OPTIONS` over TLS. Vapi returned `200` on the first attempt, after which
  the endpoint and its current ownership journals were exact-deleted. No
  assistant call, transfer, media, or Connect contact was created. This was
  initially classified as authentication-readiness evidence, but the
  dual-gateway follow-up below proved that classification wrong because Vapi
  does not challenge `OPTIONS` on this path.
- Historical retained logs contain ten authenticated INVITE attempts on this
  date. Eight followed `401` with `200`; two followed `401` with `403`, at
  14:12:33Z and 16:40:14Z. Both failures occurred about 46–47 seconds after
  their endpoint intent was sealed, but successful attempts used comparable
  timing. Both Vapi US signaling addresses have accepted successful attempts,
  while both observed `403` attempts happened to use `44.229.228.186`. That
  address also accepted several successes, so the evidence does not support a
  permanently bad gateway. Passwords were compared only as closed character
  classes and lengths; successful and failed attempts overlap, ruling out the
  URL-safe dash/underscore characters as a deterministic cause. The current
  hypothesis is intermittent Vapi endpoint/auth routing state or another
  INVITE-specific Vapi policy, not the Bridgefu media-bind projection.
- The subsequent dual-gateway diagnostic corrected an important assumption in
  the preceding `OPTIONS` result. With one newly owned temporary Vapi endpoint,
  certificate-verified TLS connections to both published US SIP addresses
  (`44.229.228.186` and `44.238.177.138`) each received an unauthenticated SIP
  `200` for `OPTIONS`; neither gateway issued a digest challenge. The endpoint
  was then exact-deleted. This proves TLS reachability and certificate identity
  on both gateways, but it means `OPTIONS` is not an authentication-readiness
  check and the earlier first-attempt `OPTIONS` success must not be used as
  evidence that endpoint credentials had propagated. The `401` then `403`
  failure remains specific to authenticated `INVITE`. The next diagnostic must
  therefore be a deliberately bounded call test that records the initial and
  authenticated `INVITE` status separately; no blind Web or release retry is
  authorized from the `OPTIONS` result.
- The replacement readiness diagnostic used authenticated `INVITE`, not
  `OPTIONS`, and followed the complete INVITE transaction sequence. Its first
  implementation exposed and then fixed a diagnostic-only protocol error: an
  INVITE client must ACK the non-2xx `401` final response before issuing the
  authenticated retry; omitting that ACK caused `491 Request Pending` on both
  gateways and created zero calls. With that correction, one newly owned Vapi
  SIP endpoint passed on both published US gateways sequentially. Each gateway
  produced one provisional response, `401`, a challenge ACK, then one
  provisional response and authenticated `200`; the client sent ACK and
  received `200` for BYE. Both exact assistant/phone-bound call records were
  found and ended; one API record lagged the successful BYE and required the
  ownership-checked Vapi stop operation before absence/terminal state was
  proven. The endpoint was exact-deleted. This proves both gateways can accept
  the generated credentials and rules out a consistently bad gateway or a
  general rvoip digest defect. It does not erase the earlier intermittent
  authenticated `403`. The next retained Web SDK run must use the same endpoint
  that first passes this two-gateway authenticated-INVITE gate, so it is an
  evidence-bound retry rather than another newly created, unproven endpoint.
- That evidence-bound retained Web SDK run used one exact endpoint only after
  it passed authenticated `INVITE` against both Vapi US gateways. The WebRTC
  side again reached connected state and Vapi accepted the real Bridgefu call:
  the transaction completed `401`, authenticated `200`, and ACK. The call then
  ended before DTMF, handoff, or Connect; Vapi's terminal record is
  `customer-ended-call`. All temporary Web runtime, endpoint, direct overlay,
  route/context, and active-process cleanup completed successfully.
- The exact call's private Vapi PCAP proves the SDP and remote media target were
  valid. Bridgefu offered public IPv4 port `24576` with `RTP/SAVP`; Vapi
  answered with a nonzero public IPv4 port and `RTP/SAVP`; the SIP exchange
  contains `401`, challenge ACK, authenticated INVITE, `200`, ACK, BYE, and BYE
  `200`. No RTP packet reached Vapi. The matching Bridgefu runtime event shows
  its first outbound RTP write failed with Linux `EINVAL`, after which
  `SipMediaStream` stopped and Bridgefu ended the call. Therefore this failure
  is after successful Vapi authentication and SDES-SRTP negotiation, inside the
  Bridgefu/rvoip local media send path.
- Source inspection found the exact Bridgefu projection defect. The base SIP
  stack correctly changed RTP `Config::local_ip` from its loopback signaling
  bind to IPv4 wildcard for public media. But every isolated named SIP egress
  child cloned that base and then overwrote `local_ip` with the child's
  loopback-only signaling bind. The child consequently advertised the public
  media address while allocating its actual RTP socket on loopback; Linux
  rejects its public-destination send with `EINVAL`. Bridgefu commit
  `22424d27650979e7e2071a5d0c1d17b6b2ebcb72` preserves the base RTP bind while
  continuing to isolate the child's SIP signaling bind, TLS client state, port
  range, credentials, and Contact. Regressions require a loopback child
  `bind_addr`, IPv4-wildcard child `local_ip`, the unchanged public media
  address, and the same media bind across conflicting isolated profiles.
  Validation passed all 151 Bridgefu binary tests, the complete direct
  browser/Vapi/Connect handoff integration, the real named-route SRTP
  transcoding/bidirectional DTMF/BYE integration, Clippy with warnings denied,
  format, and diff checks. The distribution lock now pins that remote commit;
  Cargo.lock remains unchanged and still resolves exact crates.io rvoip 0.3.7.
  Per the explicit stop point, no rebuilt binary, AWS deployment, or live call
  retry has been started from this fix.
- Current distribution CI run `31726812109` completed successfully at exact
  head `bb6a6ebaf40b1bfcae7511f1ebffe4a828260d4a`: `validate`,
  `sdp-diagnostics`, and `qualification-client` all passed.
- Exact Bridgefu `22424d27650979e7e2071a5d0c1d17b6b2ebcb72` built on the
  retained ARM instance with the locked Cargo digest. The optimized build took
  27m14s and produced mode-0755, root-owned binary SHA-256
  `f6a3bdbd488ed3b1b95b855c709d92ca165f718d31d43873e58b9a0a1da97428`.
- The first guarded install attempt stopped before mutation because the old
  runtime returned 503. Its closed readiness state was `call_runtime=lease_lost`:
  the all-core build delayed coordination heartbeats and the fail-closed lease
  state intentionally required restart. The installed digest remained the
  prior `29db3618…e6f4`, no backup or `.next` file existed, and the handoff table
  contained zero records.
- The adjusted guarded install required that exact lease-lost state, the exact
  old/new digests, and zero call context. It preserved the prior binary at
  `/var/lib/bridgefu/diagnostic-backup/22424d27650979e7/bridgefu`, installed
  `f6a3bdbd…97428` atomically, restarted once, and passed an independent check
  of installed/backup/source digests, systemd state, `/readyz`, and healthy call
  runtime. No live call had begun at this ledger update.

### 2026-08-13 — Direct-only assistant defect found after media-bind fix

- The retained Web run against installed Bridgefu `22424d2` crossed the prior
  WebRTC, SIP-authentication, SRTP-negotiation, and first-media-write boundaries.
  It therefore confirms the named SIP-egress media-bind fix changed the live
  failure boundary as intended.
- The terminal Vapi call was an `inboundPhoneCall` that ended
  `silence-timed-out`. Its bounded artifact classification contains 14 messages,
  exactly two function-tool calls, and exactly two tool results. One call/result
  is `prepare_handoff`; the other is `bridgefu_direct_handoff`. There is no
  `transferCall`, no transfer artifact, and no Amazon Connect destination leg.
- This behavior follows directly from the current harness. The product
  assistant template contains one production prepare tool ID, one inline
  `transferCall`, and a system message directing that two-step sequence. The
  Web overlay appends the direct tool ID and a second system message but removes
  none of those production capabilities. A prompt that says not to use an
  exposed tool is not an isolation boundary.
- The direct tool reached its Lambda but returned
  `bridgefu_replacement_unavailable`. That category is not a root-cause-level
  network result: `urllib.error.HTTPError` derives from `URLError`, and the
  current replacement client catches the broader type. A Bridgefu HTTP reject
  is therefore indistinguishable from DNS, TLS, connection, or timeout failure
  in this evidence. The extra prepare call made the scenario invalid but is not
  proven to have caused the replacement result.
- Cleanup removed the temporary Vapi assistant overlay and call transients, but
  the run also reported `Bridgefu Web runtime restoration failed`. That cleanup
  boundary must have a local regression and a positive retained receipt before
  the next call; passing call behavior cannot waive failed restoration.
- The accepted fix is a separately created qualification assistant, not a more
  forceful patch of the product assistant. Its request is constructed only from
  known model/voice settings and contains one direct prompt, one direct tool ID,
  no inline tools, no assistant-wide server, and deterministic ownership
  metadata. A dedicated qualification identity secret binds only that assistant
  and organization to the direct Lambda. The temporary SIP endpoint is created
  only after both are verified.
- Ambiguous assistant creation reconciles by deterministic name and exact
  ownership metadata, adopts exactly one match, fails on multiple matches, and
  retries once only after bounded reads prove zero. Cleanup deletes the exact
  phone, unbinds the exact direct identity, deletes the exact assistant, and
  deletes the exact direct tool. The product assistant and shared webhook
  credential are never patched or deleted.
- No AWS mutation, Vapi mutation, release run, candidate reservation, or
  publication occurred while establishing this root cause and fix contract.
  SIP-source qualification remains blocked until the corrected Web gate passes.

### 2026-08-13 — Direct-Web root cause fixed locally and release gates re-proven

- The replacement failure is now exact. The retained AMI's HAProxy private
  control allowlist admitted health checks and route creation, but not
  `POST /v1/calls/{call_uuid}/legs/{leg_uuid}/replace`. HAProxy returned 404
  before the request reached Bridgefu. Python then caught that `HTTPError`
  through its `URLError` superclass and mislabeled it
  `bridgefu_replacement_unavailable`. The unrelated production
  `prepare_handoff` call came from the conflicting overlay described above.
- HAProxy now permits only `POST` to the exact UUID-shaped replacement path;
  all other private-control paths remain denied. The Bridgefu client validates
  both identifiers as UUIDs before issuing the request. HTTP 4xx/5xx responses
  are caught before transport failures and mapped to bounded status categories
  without response bodies, URLs, tokens, call IDs, or customer data.
- The product-assistant overlay has been removed. The Web scenario now creates
  an execution-owned assistant containing one marked prompt and exactly one
  direct tool reference. It has no inline transfer tool, assistant server, or
  extra tool surface. The product assistant is read only to bind its
  organization and to prove its canonical digest remains unchanged.
- The direct endpoint has a dedicated identity-binding secret and bypasses the
  warm Lambda secret cache. An unbound identity fails closed. Cleanup order is
  exact: temporary phone, identity unbind, direct assistant, direct tool. Web
  acceptance now requires exactly one accepted direct-tool call/result and
  rejects any prepare, transfer, or other tool activity.
- Each direct Vapi tool, assistant, and temporary phone now writes three
  encrypted, non-secret records: desired-state intent, a separate
  request-authorization marker immediately before `POST`, and exact returned-ID
  ownership after remote verification. Intent without authorization proves
  that no create request was permitted. An authorized request with one exact
  owner-equivalent object can be recovered. An authorized request whose result
  cannot be found remains fail-closed with its stack and journals retained;
  cleanup never converts one empty eventually-consistent list response into a
  false absence claim.
- Normal cleanup and the recovery job both use bounded complete-list checks,
  exact assistant/tool surfaces, and reverse dependency order. They reject
  ambiguity, changed prompts or tools, unknown remote surface, a full result
  page, a foreign relationship, a changed identity binding, or a fetched
  object's ID differing from the exact deletion target. The Vapi API key is
  supplied to recovery through a private mode-0600 curl configuration, never
  through process arguments, and the file and variables are removed by the exit
  trap.
- The direct tool result visible to the model now contains only
  `{accepted:true, spoken:""}`. It no longer exposes the logical route name;
  tests also prove that call, leg, route, idempotency, session, token, and
  correlation identifiers are absent from the serialized result.
- Runtime restoration now recognizes only the exact latched
  `call_runtime=lease_lost` state as eligible for one bounded restart and then
  requires 15 continuous healthy seconds, crossing the lease-renewal cadence.
  Every other degraded state still fails cleanup.
- Local validation after all fixes passed: **291** Python unit/contract tests;
  all 4 rvoip SIP-source tests; all 16 direct-secure-probe tests; Rust format
  and Clippy with warnings denied; Playwright Chromium installation and both
  browser syntax checks; Ruff; ShellCheck; actionlint; deterministic Lambda and
  release packaging; local release validation and `cfn-lint`; and Packer
  1.12.0 initialization/validation.
- AWS CloudFormation `ValidateTemplate` accepted all 13 rendered product,
  nested, qualification, and publisher templates in both `us-west-2` and
  `us-east-1`: **26/26** remote validations under account `225478700523`.
- No template was deployed, no Vapi object was created, and no call, candidate,
  GitHub release run, version reservation, or publication was started by this
  fix pass. The next permitted live action is to rebuild/install these exact
  local bits into the one retained Oregon diagnostic environment and run one
  Web SDK smoke. The SIP-source smoke, Virginia, candidate sealing, and release
  publication remain blocked until that Web smoke passes and cleans up.

### 2026-08-13 — Missing Connect correlation root cause reproduced and fixed

- The most recent retained Web call did reach the available Amazon Connect
  agent. AWS recorded one connected VOICE contact with `AgentInfo` and queue
  ownership. The contact nevertheless contained no `correlation_id`, and the
  lookup Lambda returned the closed result `unavailable`; this was not an agent
  availability failure.
- Source tracing found the exact loss boundary in Bridgefu. The one-use WebRTC
  route durably stored the server-owned correlation and handoff-token context.
  Initial named-route dialing knows how to use that context, but the leg-
  replacement executor looked only for a browser-sent initial-context row. The
  production Web qualification intentionally did not trust the browser to
  restate the correlation. Consequently Amazon Connect started with only the
  route's static attributes.
- Bridgefu commit `cb2eb2d51010ff59f912aa293d255dfeb5ef6a8a`
  now gives the authenticated server-owned named-route context precedence for
  replacements, with the existing signed browser-context row retained as the
  fallback. The Amazon replacement integration now exercises that exact
  server-owned path and proves `correlation_id` plus allowlisted metadata reach
  `StartWebRTCContact`; the original browser-supplied path remains covered.
  The focused end-to-end integration, 37 execution unit tests, formatting,
  Clippy with warnings denied, and diff checks passed. The commit is pushed to
  `origin/codex/vapi-tls-rtp-evidence` and the distribution source lock is
  repinned to it. The same regression also proves the private handoff token is
  sent only to the authenticated Vapi SIP leg and is excluded from Amazon
  Connect contact attributes.
- The live trace also exposed an independent idempotency defect. Vapi retried
  the already accepted direct webhook after the record was `RESERVED`, while
  `prepare_direct` allowed only `MAPPED` or `PREPARED`, producing a misleading
  later `direct_handoff_conflict`. Distribution commit `60c73cb` now admits
  `RESERVED` only when the same token, unexpired record, content hash, and Vapi
  identity hash all match, then replays the exact replacement receipt. Changed
  retries still fail closed. All 291 Python unit tests and Ruff passed.
- The exact Bridgefu commit is building on the retained Oregon ARM instance
  using its preexisting Cargo cache. The prior installed binary remains active
  during the build. The direct Lambda has been atomically updated to the retry-
  safe package and reports Active/Successful. No CloudFormation stack, release
  candidate, GitHub workflow, or publication was started. The only permitted
  next live action is atomic installation of the exact Bridgefu build followed
  by one retained Web SDK smoke and its full cleanup proof.

### 2026-08-13 — Connect delivery passed; SQLite recovery restart root cause isolated

- The retained Web SDK retry did log the disposable Amazon Connect agent into
  Agent Workspace, explicitly selected `Available`, and auto-accepted one
  connected VOICE contact. The contact contained the exact `correlation_id`,
  `context_available=true`, and the four configured screen-pop fields in the
  configured order. This proves Vapi invoked the dedicated direct tool,
  Bridgefu replaced the Vapi leg, Amazon Connect received the call, and the
  lookup path populated the agent screen.
- The media gate did not pass. The source browser observed a remote audio track
  but not the required 880-Hz marker or DTMF. Its earlier reported packet/byte
  numbers were outbound RTP counters, not inbound evidence. The agent observer
  result was then hidden when the controller raised the source failure first.
  The browser probes now separately report inbound/outbound RTP, decoded-audio
  active-frame count and maximum RMS, and the controller retains both browser
  failure reports. No media conclusion will be drawn from the mislabeled
  counters.
- Cleanup intentionally stopped Bridgefu at 23:20:39 UTC. The subsequent
  restart loop was not initiated by a Rust panic. The `durable work claim task
  panicked` message occurred only after systemd had begun stopping the service
  and was a cancelled task mislabeled as a panic.
- The actual restart failure was `durable call execution recovery timed out`.
  The call database contained 260 durable commands: 250 media-deadline refresh
  commands plus normal lifecycle work. Those refreshes produced approximately
  500 schedule/cancel coordination effects. With eight SQLite pool connections
  competing for SQLite's single writer, startup recovery spent seconds waiting
  on the coordination projection lock, exceeded the 15-second startup budget,
  and exited fail-closed. Later attempts could also exhaust the 30-second
  worker lease during recovery and latch `call_runtime=lease_lost`.
- The product fix configures standalone SQLite explicitly as WAL with NORMAL
  synchronization and a one-connection pool. WAL prevents health/read probes
  from blocking the writer; the one connection serializes all mutations before
  SQLite instead of creating a writer thundering herd that can starve lease
  renewal and recovery. The regression proves the WAL/synchronous pragmas and
  that a second pool acquisition cannot proceed until the single connection is
  returned. Repository conformance and Clippy with warnings denied pass.
- The next permitted live action is not another call. Commit and build this
  exact SQLite fix, install it atomically on the retained instance, and prove
  the existing durable database reaches and continuously holds healthy
  readiness without a restart loop. Only after that recovery gate passes may
  one bounded Web SDK media retry run with the corrected two-sided diagnostics.

### 2026-08-13 — WAL fixed contention but exposed unbounded recovery work

- Bridgefu commit `53650d3de2df4be72eb5f7ec8850191dd1599d4e`
  contains the WAL/single-writer change and is pushed to
  `origin/codex/vapi-tls-rtp-evidence`. Distribution commit
  `c2095ec4f26162ff140fccd47eb25a016dd9ed68` pins that exact source and is
  pushed to `origin/codex/staged-vapi-qualification`.
- The exact ARM64 binary was installed on the retained Oregon instance. Its
  SHA-256 is
  `9c3f0b91dc9928b140034dcdbea9194e2741074f03fd760a7f9a20e621b9bb54`.
  The preexisting 4.6-MiB database opened as WAL and held healthy readiness for
  45 seconds without a restart. That proved the original writer-contention
  fix, but not long-term recovery scalability.
- One authorized Web SDK retry then added 116 durable commands, 227 call-
  outbox rows, and 107 media-activity deadline refreshes in roughly one minute.
  Cleanup stopped Bridgefu normally. The next three starts each failed with
  the exact top-level cause `durable call execution recovery timed out`; the
  fourth start succeeded after caches were warm. No Rust panic, OOM, or signal
  crash initiated those restarts. The cancellation message containing the word
  `panicked` was emitted only after systemd stop and is cleanup noise.
- The deeper defect is now source-proven. Every SQLite claim operation rebuilds
  and validates the full backend-neutral event snapshot before asking whether
  work exists. Startup runs restart claims plus four cleanup claim classes
  under the normal 15-second call-setup deadline. In this database both calls
  were terminal and no coordination item was pending, so logically empty
  recovery still re-read all retained calls, commands, outbox rows, deadlines,
  provider state, and service rows several times. Durable media activity also
  appends roughly two commands per second while two legs are active, and there
  is no runtime terminal-history purge, so the cost is unbounded across calls.
- The latest Web call is a separate call-path failure. Vapi used only the
  dedicated direct tool surface and eventually returned one accepted result.
  The source browser decoded non-silent remote audio (`147` active frames,
  maximum RMS `0.255269`) but did not receive the expected marker or DTMF. No
  Amazon Connect contact was found in the call window, and Bridgefu ended its
  outbound leg as `transport_failed`. The exact Amazon-side invocation boundary
  still requires CloudTrail and redacted Bridgefu-log correlation; it must not
  be conflated with the startup-recovery defect.
- CloudTrail and the durable execution timeline have now closed that boundary.
  There were zero `StartWebRTCContact` API calls in the retry window. Bridgefu
  durably queued the Amazon replacement at `00:33:40Z`, but did not finish
  processing that outbox effect until `00:34:57Z`, 77 seconds later and after
  the transfer deadline had already failed the call. The stored replacement
  payload was valid, selected the Amazon Connect endpoint, and contained the
  server-owned Amazon start specification. Amazon Connect, its contact flow,
  and the agent therefore never had a call to accept in this retry.
- This is the same repository starvation defect expressed on the live path:
  ordinary work polling, media-activity mutations, and execution reads all
  contended through one SQLite pool connection while repeatedly reconstructing
  retained history. A second masking defect then classified the never-started
  replacement as succeeded merely because it was finally retired after the
  call was terminal.
- The next permitted product action is an indexed, worker-safe SQLite no-work
  claim path, concurrent WAL readers with one explicit mutation gate, and a
  dedicated durable-recovery deadline. It must prove empty claims do not
  deserialize retained history, stale worker fences still fail closed,
  eligible work is never skipped, active replacement execution is not starved
  by media activity, and repeated cold starts against a database shaped like
  the retained one complete without systemd restarts. Terminal retirement must
  also record an unstarted replacement as failed external work. A longer
  timeout alone is not an acceptable final fix. No further call is permitted
  until this recovery gate passes.

### 2026-08-13 — Durable recovery and live-work starvation fix is locally proven

- Bridgefu commit `9617be494bfe60835afc86235b4cba80b355db6b`
  implements the bounded product fix and is pushed to
  `origin/codex/vapi-tls-rtp-evidence`. The distribution source lock now pins
  that exact commit; its Cargo lock digest remains unchanged and continues to
  resolve exact crates.io rvoip `0.3.7`.
- Standalone SQLite now uses WAL with eight pooled connections so indexed
  reads and health/recovery probes do not queue behind an occupied connection.
  A repository-owned async writer gate serializes mutations before they enter
  SQLite's busy handler. `BEGIN IMMEDIATE` remains the database-level fence,
  including between independently connected repository instances.
- Each of the five durable claim classes first performs a conservative indexed
  emptiness check against materialized state columns. The check validates the
  exact worker fence and database-authoritative lease expiry. It skips retained
  history deserialization only when no eligible work exists; any possible work
  falls back to the complete backend-neutral transition.
- Startup recovery has a separate 120-second minimum process-start budget. This
  is defense in depth, not the starvation fix: empty recovery no longer rebuilds
  settled history in the first place.
- Retiring a queued `StartLegReplacement` after terminal convergence now records
  `call_already_terminal` instead of falsely reporting success. JoinSet task
  cancellations during an intentional stop are logged as cancellation rather
  than mislabeled as panics.
- The complete locked Rust test suite passed, including SQLite independent-
  instance races, repository/runtime restart conformance, and real SIP/SRTP/
  DTMF integration tests. Clippy with warnings denied, formatting, and diff
  checks also passed.
- The next permitted live action remains recovery-only: build and atomically
  install this exact ARM64 commit on the retained Oregon instance, then run
  repeated restarts against the existing retained database and require healthy
  readiness without any automatic restart. No Web SDK call may run until that
  gate passes.
- Capacity is now an explicit live-smoke gate. During the active call window,
  peak aggregate vCPU utilization and peak memory utilization must each remain
  below 60 percent; any sustained sample at or above 60 percent fails capacity
  qualification. Build/compiler load is measured and reported separately and
  is not call-runtime capacity evidence. The next Web smoke will collect a
  one-second CPU, memory, load, disk-I/O, readiness, and restart-count series.
- AWS has no standard six-vCPU Graviton choice in this product family. The
  templates now admit the eight-vCPU `t4g.2xlarge`, `c7g.2xlarge`, and
  `m7g.2xlarge` sizes. The next call qualification will use `c7g.2xlarge`
  (eight vCPUs, 16 GiB RAM) unless the retained-stack update cannot preserve
  the exact customer-template topology. `c7g.2xlarge` is now the documented
  product, Quick Create, and qualification default; smaller Graviton choices
  remain available only when a customer deliberately selects them.

### 2026-08-13 — Recovery gate passed; first c7g.2xlarge Web smoke isolated deterministic-data defect

- The exact ARM64 Bridgefu commit `9617be494bfe60835afc86235b4cba80b355db6b`
  is installed on the retained Oregon instance. Its binary SHA-256 is
  `937f1af87f9cdca7adccf90fd4a170b6b0fe75dfb920dfb80e73e60b5634b9a5`.
  The retained call database was preserved, and five explicit cold recovery
  restarts completed in 2.28–2.34 seconds with zero automatic restarts and
  healthy readiness. This closes the durable-recovery gate.
- The retained instance is now `c7g.2xlarge` (eight vCPUs, 16 GiB). This direct
  diagnostic resize creates known stack drift; a fresh qualification must use
  the customer template whose default now selects the same instance type.
- The first monitored Web SDK smoke on this binary completed Vapi direct
  handoff and Bridgefu leg replacement. Bridgefu durably recorded the Amazon
  replacement as connected, Connect created one `WEBRTC_API` VOICE contact,
  the disposable agent connected, and the lookup Lambda returned `available`
  for the exact correlation fingerprint. There was no Bridgefu panic or
  automatic restart.
- The screen-pop assertion failed because the previous Polly prompt spoke the
  expected field values and Vapi transcribed/modelled two of them differently:
  for example, `Bridgefu Synthetic Caller` became `Bridgefood Synthetic Collar`.
  Connect correctly contained the values Vapi supplied, but an exact release
  test cannot depend on speech-recognition spelling. The early observer failure
  also prevented its later deterministic audio-marker and DTMF emissions, so
  the resulting media failure is downstream of the same screen-pop failure.
- The qualification-only direct tool schema now permits one exact synthetic
  value for each screen-pop field. Its single system prompt explicitly requires
  those schema values and forbids copying or paraphrasing caller speech. Polly
  now says only `Transfer me please.` Customer assistants and product field
  schemas are unchanged.
- The captured call window remained far below the capacity limit: peak host CPU
  was 11.896%, peak Bridgefu-normalized CPU 1.486%, peak host memory 3.828%, and
  peak Bridgefu RSS 0.925%. This is provisional until a fully passing smoke
  captures the complete active-call interval.
- Post-failure checks prove the product runtime restored healthy with its exact
  binary, zero automatic restarts, no qualification drop-ins, both temporary
  Vapi direct resources absent, and the dedicated identity binding unbound.
  The next permitted live action is one bounded retained Web SDK smoke with the
  deterministic schema and continuous capacity monitoring.

### 2026-08-13 — Short trigger exposed fake-microphone startup ordering

- The deterministic-schema retry created one exact Vapi inbound call, but the
  call contained only its system message, invoked no tool, and ended after the
  exact 30-second `silence-timed-out` boundary. Amazon Connect consequently had
  no contact or lookup invocation. Bridgefu remained healthy with zero automatic
  restarts, and cleanup again proved the temporary direct tool/assistant absent
  and the dedicated identity binding unbound.
- This is a harness timing defect, not a Vapi prompt or Bridgefu replacement
  failure. Chromium starts its fixed fake-microphone WAV when Bridgefu requests
  browser capture. The previous long spoken script overlapped later SIP setup;
  the new one-second `Transfer me please.` clip started at one second and could
  finish before Vapi's media leg was consuming browser audio.
- The browser qualification WAV now begins with exactly five seconds of silence
  and then says that same short phrase, before Vapi's 30-second silence deadline.
  Deterministic media markers begin at ten seconds so they cannot overlap the
  spoken trigger. Before publishing source readiness, the harness now requires
  the Bridgefu peer connection and ICE connection to be connected plus observed
  outbound audio RTP packets and bytes. It fails immediately if establishment
  misses the five-second trigger window. Source contract tests pin the timing
  and media gate. The next permitted action is one bounded retained retry with
  a fresh full-window capacity capture.

### 2026-08-13 — Trigger and screen pop passed; reverse-media probe isolated

- The media-gated retry passed its intended boundary. Vapi heard the short
  trigger, invoked the exact direct tool, Bridgefu replaced the leg, Connect
  rendered the exact deterministic screen pop, and the agent observed the
  source-side marker and DTMF. The source received 4,984 audio packets and 527
  KiB of non-silent Connect audio (`max_rms=0.520521`). Bridgefu remained healthy
  with zero automatic restarts.
- The source did not classify the agent's expected 880-Hz marker or DTMF. The
  agent fake-microphone marker was a short 100-ms mixture of 880 Hz plus both
  DTMF frequencies, which is unnecessarily fragile across browser processing,
  Connect audio processing, and transcoding. The source therefore withheld its
  success-path hangup, and the agent's later hangup timeout was consequential.
- The agent probe now uses five-second, higher-level, pure 880-Hz marker tones
  separated by five seconds of silence, plus a separate one-second stronger
  DTMF-six interval. The Web source records bounded maximum
  marker/DTMF spectral powers in failure diagnostics and uses conservative
  thresholds. For the mandatory reverse DTMF event, the agent now sends digit
  six through the real Connect Streams connection, with the real number-pad UI
  as fallback, rather than inferring transmission from WAV timing.
- The next permitted action remains one bounded retained Web SDK retry after
  the exact browser contracts and complete local suite pass.

### 2026-08-13 — Per-scenario database isolation and Vapi SIP propagation gate

- The five-second source and agent media markers are now committed. The short
  browser speech prompt remains exactly `Transfer me please.` after five
  seconds of silence, and the browser proves WebRTC/ICE plus outbound RTP before
  it can publish source readiness.
- Live Vapi evidence proved the speech path: Vapi transcribed the request and
  invoked the dedicated direct tool. The next failure was not missing speech.
  Eight replacement attempts first returned HTTP 409; after the bounded
  Bridgefu version-conflict retry was installed, two attempts reached HTTP 504.
- The 504 boundary was SQLite history amplification. The retained 29.8 MiB
  database contained only 13 calls but thousands of durable commands, outbox
  records, reconciliation results, and deadlines. Replacement mutations spent
  7.9 to 30.0 seconds rebuilding retained state. This remains a production
  retention/scalability defect to fix; qualification isolation must not be used
  as evidence that accumulated production history is healthy.
- The disposable retained database was reset once after proving every call was
  terminal. Bridgefu created a fresh migrated database and remained healthy.
  The following call stopped earlier because Vapi returned HTTP 403 to the SIP
  INVITE even though its API already reported the transient endpoint `active`.
  The endpoint readiness guard now requires 90 continuous seconds of the exact
  active identity before the Web call begins.
- The live `c7g.2xlarge` active window remained within the required capacity:
  host CPU peak 44.994%, Bridgefu-normalized CPU peak 43.634%, host memory peak
  6.536%, and Bridgefu RSS peak 3.209%. The instance has eight vCPUs and 16 GiB;
  automatic systemd restart count remained zero. Compiler load is excluded.
- Qualification now resets SQLite before each of the three independent tests:
  direct secure preflight, Bridgefu Web SDK handoff, and Vapi SIP transfer. Each
  reset requires the CloudFormation `TestDelete` marker, proves all prior calls
  terminal before and after stopping the service, stages the prior database for
  rollback, starts a newly migrated database, proves zero call rows, and stays
  healthy across the lease-renewal interval. A separate idempotent cleanup
  command restores the prior database if reset or cancellation fails.
- All three reset receipts are required in evidence-v2 and independently gated
  when the candidate receipt is sealed. This prevents cross-test history from
  making one smoke affect another while preserving the accumulated-history
  defect as a separate product blocker.
- Local validation is green: 298 unit tests, Ruff, workflow syntax, deterministic
  packaging, release policy checks, and local CloudFormation lint. AWS
  `ValidateTemplate` passed for all ten rendered root/nested templates in both
  `us-west-2` and `us-east-1`; validation created no resources.
- The next permitted AWS action is one retained Oregon Web SDK smoke. It must
  invoke the qualification database reset first, wait through the Vapi endpoint
  stability window, then run with continuous CPU/memory/restart monitoring. No
  GitHub candidate or release workflow is permitted.

### 2026-08-13 — Isolated run 15 proved media but exposed an overlong edge-count gate

- Retained Oregon run 15 passed the new SQLite reset, sustained health, Vapi
  endpoint-stability interval, WebRTC establishment, Vapi direct handoff,
  Bridgefu replacement, Connect delivery, screen-pop lookup, agent availability,
  call acceptance, ordinary audio, source marker, source DTMF, reverse marker,
  and reverse DTMF boundaries. Bridgefu remained healthy with zero automatic
  restarts.
- The agent measured three separate 997-Hz source-marker episodes and 156
  analyzer frames, plus source DTMF. The source-side media wait separately
  passed its agent-marker and agent-DTMF requirements. Both finalizers still
  rejected the call because they retained the older requirement for five
  distinct marker edges after each marker had been lengthened from a short
  pulse to five continuous seconds. The source then ended the call before a
  fifth edge could exist. This is a qualification timing defect, not missing
  media.
- The corrected contract requires one distinct marker episode plus at least 50
  positive 20-ms analyzer frames—one full second of sustained spectral proof.
  The five-second generated tones therefore retain a large margin without
  forcing a 50-second multi-edge handshake before hangup. DTMF remains a
  separate mandatory observation in both directions.
- Cleanup exposed a second Vapi eventual-consistency defect in the harness.
  Vapi returned 404 immediately after DELETE, then made the same exact owned
  assistant and tool visible again. The old cleanup treated the first 404 as
  final. Deletion now requires ten continuous seconds of absence; if the exact
  owned ID reappears, ownership is revalidated and DELETE is retried. Foreign or
  changed resources still fail closed. The run-15 assistant and tool were
  exact-deleted with this rule and remained absent after an additional delay;
  the direct identity binding is unbound and the product runtime is restored.
- Active-call capacity remained far below the 60-percent ceiling on the
  eight-vCPU `c7g.2xlarge`: host CPU peak 12.515%, Bridgefu-normalized CPU peak
  11.308%, host memory peak 4.276%, and Bridgefu RSS peak 1.067%. The full
  capture contained 589 one-second samples and zero automatic restarts.
- The local regression suite now has 299 passing unit tests. The next permitted
  action is one run of this same retained Web gate after committing the marker
  and sustained-Vapi-deletion fixes. No other smoke and no candidate workflow
  may start first.

### 2026-08-13 — Run 16 reached the call but exposed a stale observation schema

- Retained Oregon run 16 reset SQLite before the Web scenario, reached the
  live call, and produced the Connect screen-pop screenshot. The browser
  harness used the corrected sustained-tone gate, but the controller rejected
  its otherwise valid source artifact because the JSON Schema still required
  five separate source marker timestamps. The participant schema retained the
  same stale requirement for five agent-marker timestamps.
- The source and participant schemas now match the executable media contract:
  one scheduled five-second marker episode is required, and the receiving
  browser must prove at least 50 positive 20-ms analyzer frames. The release
  check derives the same thresholds. The rvoip SIP source retains its separate
  frame-based receive threshold, while the Connect browser still requires 50
  analyzer frames for its received source audio.
- Regression coverage proves that one marker episode plus 50 analyzer frames
  is accepted and 49 frames is rejected on each browser side. All 299 Python
  unit tests, both Rust qualification clients, Rust formatting and Clippy,
  browser syntax, pinned Playwright installation, deterministic packaging,
  CloudFormation lint, release policy validation, Ruff, and diff checks pass.
- Before another retained call, run-16 Vapi resources, capacity capture, runtime
  state, identity binding, and database state must be audited and cleaned. Only
  then is one bounded Oregon Web retry permitted; no candidate or release
  workflow is permitted.
- The run-16 capacity capture contained 589 one-second samples. During the exact
  Amazon Connect voice-contact window, host CPU peaked at 5.346%,
  Bridgefu-normalized CPU at 3.688%, host memory at 4.306%, and Bridgefu RSS at
  0.918%. All 20 active-call samples were ready, with zero PID changes and zero
  automatic restarts. Four PID changes in the full capture were the expected
  test-database/runtime setup and restoration operations, not crashes.
- A delayed audit found that Vapi had again exposed the exact assistant and tool
  after the prior cleanup observed ten continuous seconds of 404 responses.
  The official DELETE endpoints document a 200 Deleted response but do not
  document this observed read-after-delete propagation behavior. Qualification
  cleanup now requires 90 continuous seconds of exact-ID absence within a
  bounded 240-second deadline. If the exact owned resource reappears, DELETE is
  reissued only after ownership is proven again. The run-16 assistant and tool
  passed this longer absence gate; the direct identity binding is unbound,
  Bridgefu is healthy with zero restarts, the qualification overlay and pending
  reset directories are absent, and the database contains one terminal call.

### 2026-08-14 — Runs 18–19 closed the call mechanics and isolated two evidence-boundary defects

- Run 18 proved that Vapi's API-level `active` phone status is not a sufficient
  data-plane readiness signal. The real authenticated SIP INVITE still received
  HTTP/SIP 403. Qualification now performs a silent, authenticated SIP probe
  before every Web smoke: receive the Digest challenge, send exactly one
  authenticated retry, require 200, open media, send one second of silence,
  send BYE, and prove cleanup. A failed probe exact-deletes and recreates the
  qualification-owned endpoint, up to the bounded retry limit. No speech or
  handoff tool can be triggered by this probe.
- Run 19 completed the actual Bridgefu Web SDK path: WebRTC media established;
  Vapi invoked only `bridgefu_direct_handoff`; Bridgefu replaced the Vapi leg;
  Connect answered; all four configured screen-pop rows appeared in order;
  both five-second media markers and both DTMF directions were observed; and
  source/agent hangup cleanup completed. Vapi repeated the same idempotent
  direct tool once while media continued. The acceptance rule now permits one
  or more identical accepted retries while continuing to reject any foreign
  tool, failed result, prepare tool, or transfer tool.
- Run 19 did not receive the required
  `bridgefu_vapi_source_security_evidence` event in CloudWatch. This was not a
  CloudWatch delivery failure and not missing TLS media. The product installed
  the observer only on the default rvoip coordinator. The Bridgefu-to-Vapi leg
  is owned by a named SIP egress profile with its own child coordinator, so the
  event could never reach that observer.
- The upstream rvoip fix branch now exposes the named profile's coordinator for
  read-only observation without transferring signaling ownership. Commit
  `34b73100` is pushed on `codex/fix-sips-contact-fallback`; its focused tests
  and Clippy pass. Bridgefu now installs and lifecycle-manages one redacted
  security observer for every SRTP-capable named profile. Local product tests
  prove the child observer is installed and the existing security suite remains
  green. The customer release continues to pin crates.io rvoip 0.3.7; this
  observer change cannot be promoted until the upstream getter is published.

### 2026-08-14 — CloudWatch-first retained smoke is in progress

- Qualification commit `f172cc6` is pushed and contains the authenticated SIP
  endpoint readiness probe plus the idempotent direct-tool result gate. The
  complete local gate passed: 301 Python tests, Rust SIP-client tests, Ruff,
  Rust formatting, deterministic release validation, CloudFormation lint, and
  the local CloudFormation verifier.
- Commits `18f6239` and `c3f441e` are pushed and add ten-second CloudWatch
  Agent collection for host CPU/memory plus `procstat` collection for the exact
  Bridgefu process (`cpu_usage` and `memory_rss`).
  The retained Oregon agent accepted the rendered configuration, and the
  `Bridgefu/Runtime` namespace is receiving both process metrics. Existing
  structured JSON runtime events continue to stream from
  `/var/log/bridgefu/bridgefu.log` to the stack-owned CloudWatch Logs group;
  the controller uses CloudWatch `filter-log-events`, not copied EC2 log files,
  as the authoritative security evidence source.
- The next bounded call uses the retained `c7g.2xlarge` (eight vCPUs, 16 GiB),
  resets the disposable database before the scenario, requires WebRTC media
  establishment before the prompt, plays five seconds of silence followed by
  `Transfer me please.`, and uses sustained five-second media markers. CPU and
  memory are read back from CloudWatch for only the smoke window; compiler load
  is excluded. Host CPU and memory must both remain below 60 percent, and the
  CloudWatch runtime stream must contain no Bridgefu startup event during the
  call.
- A diagnostic ARM64 Bridgefu build is currently compiling from exact hashed
  inputs: Bridgefu base commit `0605edfa` plus the two-file observer patch, and
  rvoip fix commit `34b73100`. The running service has not been replaced during
  compilation. After the binary hashes are recorded, installation must retain
  an exact rollback binary and pass sustained readiness before the one permitted
  retained Web smoke begins.

### 2026-08-14 — The CloudWatch retry stopped at the Vapi readiness observer

- The diagnostic Bridgefu binary with named-profile security observation was
  installed on the retained Oregon instance. Its exact SHA-256 is
  `51d47a767986123cbc91572a51177b0cc161c7dcde0ea01e754e7076be9cdbfe`;
  the prior binary remains available for exact rollback. Installation passed
  sustained readiness with zero automatic restarts.
- The first CloudWatch retry did not reach the browser. Its readiness command
  successfully completed the Vapi SIP dialog, then failed only when the EC2
  gateway role tried to upload the redacted observation to S3. That role is
  intentionally read-only. Commit `298579f` returns the strict observation in
  authenticated SSM output instead; no S3 write permission was added.
- The next bounded retry created three isolated Vapi SIP endpoints in sequence.
  Each waited for 90 continuous seconds of API `active` state. The first two
  probes became real Vapi inbound calls, received an answer, opened media, sent
  silence, and ended because the qualification client sent BYE. Vapi recorded
  both as `ended` with `customer-ended-call`. The wire observer nevertheless
  rejected them under its combined Digest/target/retry-count/answer assertion.
  The third attempt produced the same aggregate readiness failure. The browser,
  Connect call, and Bridgefu replacement were never started.
- Exact cleanup passed. No qualification phone, direct assistant, or direct
  tool remains; the direct identity binding is unbound. The retained AWS stack
  and product assistant remain intentionally available for this single gate.
- Commit `000e157` changes the readiness client to return a machine-readable,
  redacted failure observation after a successfully completed media dialog.
  It records only target-host match, Digest-challenge presence, INVITE count,
  answer presence, bounded final status, transport, media-open/silence, and BYE
  cleanup. The controller persists each observation before classifying the
  failure. It contains no URI, credential, SIP/SDP body, call ID, assistant ID,
  phone ID, media address, or customer data.
- The next permitted action remains this same retained readiness gate with the
  `000e157` client. It must identify the exact observer mismatch before the Web
  smoke may continue. No candidate workflow, fresh stack, SIP-source smoke, or
  release version is permitted first.

### 2026-08-14 — Retained Oregon Web SDK smoke passed with CloudWatch evidence

- The readiness mismatch was in the qualification observer, not Vapi. rvoip's
  safe SIP trace deliberately redacts the Request-URI, so the client could not
  rediscover `sip.vapi.ai` from the trace. Commit `d3a62fd` validates the exact
  US Vapi SIP URI before dialing and uses the redacted trace only for Digest,
  retry count, final response, and dialog facts. Commit `3d533ed` also fixes the
  SSM boundary so the observer returns one JSON document instead of a path line
  followed by JSON. The retained readiness call then passed: exact US target,
  Digest challenge, two INVITEs, SIP 200, media open, 50 silent frames, BYE,
  and cleanup.
- The subsequent Web SDK call reached Vapi, invoked the dedicated direct-only
  handoff tool, replaced the Vapi leg, reached Amazon Connect, populated all
  four configured screen-pop rows in order, and completed source-originated
  hangup. The source and Connect agent each proved the five-second audio marker
  in the opposite direction and both DTMF directions. The Connect agent was
  explicitly made Available before the browser trigger.
- The first CloudWatch classification correctly emitted only an incomplete
  source-leg event even though every other call boundary passed. The Bridgefu
  tracker marked outbound UAC calls answered only on `CallEstablished`, an UAS
  lifecycle event. rvoip publishes outbound `CallAnswered` only after the 2xx
  path successfully writes ACK. Bridgefu now marks the UAC leg answered on that
  typed event. The focused security suite passed 18/18 and the patched ARM64
  diagnostic binary SHA-256 is
  `3a8b4b677d16ffe9151f1f3e308278ae8aae46dda024ca37fe6a06d52b5f08a1`.
- The repeated retained call passed the authoritative CloudWatch event gate:
  `bridgefu_vapi_source_security_evidence`, leg `bridgefu-to-vapi`, URI scheme
  `sip`, signaling transport `tls`, media profile `RTP/SAVP`, keying
  `SDES-SRTP`, suite `AES_CM_128_HMAC_SHA1_80`, both SRTP contexts installed,
  answered true, and redacted true. This proves Vapi negotiates TLS/SDES-SRTP
  on its inbound assistant leg when Bridgefu is the caller.
- Capacity for the exact 18.83-second active-call window came only from
  CloudWatch Logs and Metrics. On the eight-vCPU, 16-GiB `c7g.2xlarge`, host
  CPU peaked at 3.646%, host memory at 3.015%, Bridgefu-normalized CPU at
  3.725%, and Bridgefu RSS at 0.854%. There were zero Bridgefu startup events
  during the call. Compiler activity was outside the window and excluded.
- Cleanup exact-deleted the temporary Vapi phone, direct assistant, and direct
  tool; restored the Web runtime; and left the direct identity binding unbound.
  The retained stack remains intentionally available for the next isolated
  SIP-source smoke.
- The retained wrapper then misreported the passing call because it read the
  session/source/agent files from `args.output`; the controller intentionally
  stores them in its private `controller.work` directory. The wrapper now reads
  that private directory after the scenario gate passes and persists redacted
  copies. This finalizer-only defect did not affect the call or the controller's
  passing scenario evidence.
- The next permitted gate is the retained Oregon rvoip SIP-source smoke against
  this same environment, sequentially and with the database reset first. No
  GitHub candidate or release workflow is permitted before it passes.

### 2026-08-14 — Retained Oregon SIP-source smoke passed

- The initial SIP-source attempts exposed qualification-harness defects rather
  than a Bridgefu transfer failure. The client originally treated a sustained
  return marker as five required tone edges, sent short DTMF before the Connect
  leg existed, and stopped without requiring a fresh source probe after agent
  media became observable. The corrected client accepts one sustained return
  marker, sends five-second marker and DTMF probes repeatedly, and cannot finish
  until both have been sent after the first received agent marker.
- The Web and SIP smokes now share one exact spoken request,
  `Transfer me please.`, and one authenticated Vapi SIP data-plane readiness
  gate. That gate requires the Digest challenge, exactly one authenticated
  retry, SIP 200, open media, silence, BYE, and cleanup. A control-plane-active
  endpoint that fails this gate is exact-deleted and replaced within the same
  three-attempt bound already proven by the Web smoke.
- The passing retained run reset the disposable database before dialing. Vapi
  transferred the rvoip 0.3.7 SIP source to Bridgefu, Bridgefu admitted exactly
  one correlation header over TLS signaling, optional-SRTP mode accepted the
  Vapi `RTP/AVP` offer, Amazon Connect accepted the contact, and DynamoDB lookup
  rendered all four configured screen-pop rows. Audio passed in both
  directions, source-to-agent DTMF was observed, and source BYE produced clean
  remote hangup and resource cleanup.
- The exact call window was 22.304 seconds. CloudWatch reported 2.706% peak host
  CPU, 2.99% peak host memory, 2.513% Bridgefu CPU as a percentage of the
  eight-vCPU host, and 0.724% Bridgefu memory on the 16-GiB `c7g.2xlarge`.
  There were zero Bridgefu startup events during the call. Compilation was
  outside the measured window.
- Both required retained Oregon sources have now passed. The subsequent local
  gate passed 303 Python tests, both Rust qualification clients, browser
  syntax, lint, deterministic Lambda/release packaging, CloudFormation lint,
  local release validation, and checksum-verified Packer 1.12.0 validation.
  All ten rendered root and nested templates then
  passed the real AWS CloudFormation `ValidateTemplate` API in both
  `us-west-2` and `us-east-1`. No candidate or publication workflow is
  authorized by this result; the retained diagnostic stack remains available
  for review.

### 2026-08-14 — Release dependency gate identified

- The exact Bridgefu source used by the passing retained Web and SIP smokes is
  commit `53ef1c767f0c29bf8a6ca78f673a4a76122681c5` on
  `codex/vapi-tls-rtp-evidence`.
- That commit cannot be repinned as-is for a reproducible AMI build. It calls
  `SipEgressProfileRegistration::coordinator()`, which is supplied by rvoip
  fix commit `34b73100` but is absent from the published crates.io rvoip
  `0.3.7`. Bridgefu PR 4 therefore fails its clean-clone test and image jobs.
  The passing retained binary used the local rvoip fix branch; it did not prove
  that commit `53ef1c7` compiles against the declared crates.io graph.
- No AWS distribution repin or candidate run is permitted until the rvoip fix
  is published from the isolated `codex/fix-sips-contact-fallback` lineage and
  the smoke-tested Bridgefu source is updated to exact published versions. The
  recommended release is the next unused rvoip patch version, followed by a
  Bridgefu commit whose only release-enablement change is the exact dependency
  repin and regenerated lockfile.
- Required order:
  1. Merge and release the two rvoip fix-branch commits after its complete
     release gate passes: secure fallback Contact `023c0642` and profiled SIP
     coordinator observer `34b73100`.
  2. Update every Bridgefu rvoip dependency from exact `0.3.7` to that exact
     published patch version, regenerate `Cargo.lock`, and prove the registry
     sources and checksums contain no path or git overrides.
  3. Run Bridgefu tests plus both ARM64 and x86_64 image jobs from a clean clone;
     merge PR 4 only after all checks pass. The resulting main commit must
     retain the tested `53ef1c7` call-path changes.
  4. Repin `bridgefu.lock.json` to that remotely reachable Bridgefu main commit,
     its exact `Cargo.lock` SHA-256, and the new exact crates.io rvoip version.
  5. Rerun the AWS distribution local contract gate and remote
     `ValidateTemplate` gate, merge the distribution PR to `main`, and remove
     the retained Oregon diagnostic environment with zero-resource evidence.
  6. Only then create the next unused private candidate. GitHub builds the
     ARM64 AMI in `us-west-2`, copies it privately to `us-east-1`, qualifies
     Oregon and then Virginia sequentially, and seals the exact private bits.
  7. After receipt review, tag the exact qualified distribution commit. The
     release workflow makes both AMIs and snapshots public, publishes the
     immutable S3 objects, and updates `latest` last.
- Current publication readiness is **blocked** at step 1. The GitHub AWS
  build/copy/qualify/publish topology is present, but running it before this
  dependency gate passes would use the release pipeline as a debugger again.

### 2026-08-16 — rvoip 0.3.8 dependency and distribution validation gates passed

- rvoip `0.3.8` is published on crates.io with the secure fallback Contact and
  profiled SIP coordinator fixes required by the smoke-tested Bridgefu source.
- Bridgefu commit `71558b26987ac4e24e30c77c49c5cdc8037b09aa`
  preserves the passing `53ef1c7` call-path implementation and pins all 25
  rvoip packages exactly to registry version `0.3.8`. Its committed
  `Cargo.lock` SHA-256 is
  `8bd0c889cc121076cd6d31bfa9058c763744f0c96022f5bb88b8f1d707a16ba9`.
- The Bridgefu local gate passed registry-source verification, strict Clippy,
  all-target tests, credential-free runtime smoke, release-image policy tests,
  config and Compose validation, shell checks, and an optimized release build.
- The first Linux CI pass exposed a platform-dependent test defect rather than
  a runtime defect: the metric-inventory test concatenated Rust files in
  filesystem iteration order before scanning them. Bridgefu now scans each
  source file independently and includes an order-independence regression.
  The previously failing release-image assertion was also updated from the
  stale `0.3.7` label to `0.3.8`.
- The AWS distribution now pins that exact remotely reachable Bridgefu commit
  and lock digest. Its SIP smoke client, SDP observer, and direct secure probe
  are also repinned to exact crates.io rvoip `0.3.8`; their machine-readable
  source contracts and workflow assertions were updated together.
- The AWS distribution gate passed all 303 Python unit tests, both Rust smoke
  clients, the SDP observer, browser syntax, Ruff, deterministic Lambda and
  release packaging, local CloudFormation validation, and Packer 1.12.0
  validation. The AWS CloudFormation `ValidateTemplate` API then accepted all
  ten exact rendered root and nested templates in both `us-west-2` and
  `us-east-1`.
- The next permitted work is GitHub CI and review for both pull requests. No
  candidate or publication is authorized until those checks pass, Bridgefu is
  merged, and the distribution lock is repinned to the final Bridgefu `main`
  commit.
