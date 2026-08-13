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
| Active stage | **Stage 1 — Local contract gate** |
| Overall qualification | **IN PROGRESS** |
| New Oregon diagnostic environment | **NOT STARTED** |
| New Virginia qualification | **NOT STARTED** |
| Release candidate | **NOT CREATED** |
| Reserved release version | **NONE** |
| Customer-visible `latest` pointer | **NOT CREATED** |
| Publication | **NOT STARTED** |
| Next permitted live deployment | One retained Oregon diagnostic environment for Stage 3 |

## Source under evaluation

### Bridgefu runtime

| Field | Value |
|---|---|
| Repository | `eisenzopf/bridgefu` |
| Local worktree | `/Users/jonathan/Developer/bridgefu-main-clean` |
| Branch | `codex/vapi-tls-rtp-evidence` |
| Commit | `2f6cf2f6dec72856479cd74b5f23af702ae1dffa` |
| Pull request | [bridgefu#4](https://github.com/eisenzopf/bridgefu/pull/4) |
| PR state at last update | Open, not merged |
| Dependency posture | Exact crates.io `rvoip = 0.3.7`; no local rvoip dependency |

The Bridgefu change is an implementation candidate for scheme-aware security
evidence. It is not qualified product behavior until the Oregon Vapi A/B test
selects the correct URI contract.

### AWS distribution

| Field | Value |
|---|---|
| Repository | `eisenzopf/bridgefu-vapi-awsconnect` |
| Local worktree | `/Users/jonathan/Developer/bridgefu-vapi-awsconnect` |
| Branch | `codex/staged-vapi-qualification` |
| Implementation commit | `40c175b` (status-only follow-up `97a0e9a`) |
| Pull request | [bridgefu-vapi-awsconnect#26](https://github.com/eisenzopf/bridgefu-vapi-awsconnect/pull/26) |
| PR state at last update | Draft, open, not merged |

The distribution branch contains the candidate optional-mode URI behavior,
scheme-aware qualification checks, Vapi retry/reconciliation diagnostics, and
sequential Oregon-then-Virginia workflow structure. These changes remain under
evaluation until Stage 3 proves the live contract.

## Stage status

### Stage 1 — Local contract gate: PARTIAL

Completed against the source commits above:

- [x] Distribution Python unit suite: **226 passed**.
- [x] Bridgefu scheme-aware security-evidence suite: **13 passed**.
- [x] Bridgefu full local Rust suite completed without failures.
- [x] Direct secure probe suite: **16 passed**.
- [x] Qualification SIP-client suite: **4 passed**.
- [x] Rust formatting and Clippy passed for the changed Bridgefu code.
- [x] Ruff and Python compilation checks passed.
- [x] Browser driver JavaScript syntax checks passed.
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
- [ ] Complete all GitHub checks for distribution PR #26.
- [ ] Run pinned Packer validation in an environment where Packer is installed.
- [ ] Rerun the complete Stage 1 gate after Stage 3 selects the URI contract and
  the implementation is finalized.

### Stage 2 — Remote CloudFormation validation: PARTIAL

Completed against distribution commit
`1b2c22025949ea7f76a28ef55f296da7a2edab80`:

- [x] Rendered product, nested, qualification, and publisher templates.
- [x] AWS `ValidateTemplate` accepted every rendered template in `us-west-2`.
- [x] AWS `ValidateTemplate` accepted every rendered template in `us-east-1`.
- [x] No CloudFormation stack was created by this validation.

Still required before Stage 2 is `PASSED`:

- [ ] Upload private immutable diagnostic artifacts with exact S3 VersionIds.
- [ ] Validate exact S3 template URLs, not only local template bodies.
- [ ] Repeat all remote validation against the final source selected after the
  Oregon A/B test.

Stage 2 preflight evidence gathered without writing AWS resources:

- [x] AWS identity reverified as account `225478700523` using the authorized
  `vapi-admin` profile.
- [x] The Oregon and Virginia artifact buckets both have S3 versioning enabled.
- [x] Bucket policy inspection confirms that an untagged unique
  `diagnostics/...` prefix remains private; public reads are scoped to
  publication-tagged `releases/...` and `latest/...` objects.

### Stage 3 — Retained Oregon diagnostic: NOT STARTED

- [ ] Zero-state audit immediately before deployment.
- [ ] Deploy one retained `TestDelete` Oregon diagnostic environment.
- [ ] Run direct Bridgefu secure control.
- [ ] Run Vapi `sips:` versus `sip:...;transport=tls` A/B trace.
- [ ] Select the URI and media contract from observed evidence.
- [ ] Run rvoip SIP-source end-to-end smoke.
- [ ] Run Bridgefu Web SDK end-to-end smoke.
- [ ] Run Vapi create/delete/recreate resilience cycle.
- [ ] Tear down and produce zero-resource evidence.

### Stage 4 — Finalize product behavior: NOT STARTED

Blocked on Stage 3 A/B evidence.

### Stage 5 — Fresh Oregon release qualification: NOT STARTED

Blocked on Stages 3 and 4.

### Stage 6 — Fresh Virginia release qualification: NOT STARTED

Blocked on a passing fresh Oregon release qualification.

### Stage 7 — Seal candidate: NOT STARTED

Blocked on passing qualifications in both regions.

### Stage 8 — Publish customer release: NOT STARTED

Blocked on a signed, sealed candidate.

## Current CI state

Last observed on 2026-08-12 against status follow-up commit `97a0e9a`:

### Bridgefu PR #4

- `infrastructure`: passed.
- `image (arm64)`: passed.
- `image (amd64)`: passed.
- `test`: passed.
- `Trivy`: passed.

### Distribution PR #26

- `validate`: passed.
- `sdp-diagnostics`: passed.
- `qualification-client`: running.

Authoritative CI run: `31661852590`. All three checks must pass before Stage 1
can pass.

CI monitors are not running locally. CI completion must be read explicitly
before updating these states.

## Evidence inventory

| Evidence | Location or identity | State |
|---|---|---|
| Qualification plan | `docs/maintainers/CLOUDFORMATION_RELEASE_QUALIFICATION_PLAN.md` | Committed and pushed |
| Status ledger | `docs/maintainers/CLOUDFORMATION_RELEASE_QUALIFICATION_STATUS.md` | Committed and pushed; this update is local pending the next implementation commit |
| Bridgefu implementation commit | `2f6cf2f6dec72856479cd74b5f23af702ae1dffa` | Pushed, unmerged |
| Distribution implementation commit | `1b2c22025949ea7f76a28ef55f296da7a2edab80` | Pushed, unmerged |
| Local test results | Current task execution logs | Passed as listed above |
| Remote template-body validation | AWS account `225478700523`, both supported regions | Passed against current branch render |
| Oregon A/B SIP/SDP traces | — | Not created |
| Oregon end-to-end smoke evidence | — | Not created |
| Oregon zero-resource receipt | — | Not created |
| Virginia qualification evidence | — | Not created |
| Signed candidate receipt | — | Not created |

## Blockers and decisions required

1. Stage 3 must determine whether Vapi requires `sips:` or
   `sip:...;transport=tls`; current implementation branches are hypotheses.
2. Neither implementation PR should be treated as qualified until Stage 3.
3. Distribution CI run `31661852590` must finish successfully before Stage 2.
4. A fresh AWS/Vapi zero-state audit is required immediately before Stage 3.

## Next actions

The next actions, in order, are:

1. Require distribution CI run `31661852590` to pass.
2. Build/upload private diagnostic artifacts without reserving a release
   version or publishing `latest`.
3. Run AWS `ValidateTemplate` against the exact versioned diagnostic URLs.
4. Run the fresh read-only AWS and Vapi zero-state audit.
5. Deploy the single retained Oregon diagnostic environment.
6. Run the direct secure control and Vapi URI/SDP A/B test before merging or
   finalizing product behavior.

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
