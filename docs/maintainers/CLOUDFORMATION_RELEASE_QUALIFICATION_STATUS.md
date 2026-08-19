# CloudFormation Release Qualification Status

This is the current maintainer ledger for the Bridgefu Vapi → Amazon Connect
release. It intentionally contains no live AWS account numbers, resource ARNs,
stack names, call identifiers, Vapi object identifiers, signed URLs, or retained
diagnostic payloads. Exact operational evidence belongs in the private,
execution-scoped evidence store and signed candidate receipt.

Last updated: 2026-08-19 (America/Los_Angeles)

## Status rules

- A gate is `PASSED` only when its required evidence exists for the exact source
  and immutable artifacts under evaluation.
- A later gate cannot compensate for an earlier failed or skipped gate.
- A failed gate is debugged in isolation. The full release pipeline is not used
  as a debugger.
- No new release version is reserved while a lower gate is unresolved.
- Qualification mutation workflows are serialized. Maintainers must not run the
  controller or a retained diagnostic that mutates the same AWS account or Vapi
  organization while a candidate, remote qualification, or recovery run is
  active.
- This file records outcomes and safe hashes only. It must never become a dump
  of live infrastructure or call evidence.

## Current summary

No candidate has created a new Git tag, GitHub Release, public AMI, or
customer-visible `latest` pointer. Candidate `0.1.29` passed protected-main CI,
the accelerated private AMI build/copy, deterministic immutable staging, all 20
two-region remote template validations, the exact Oregon customer-stack deploy,
runtime/AMI binding, authenticated Vapi SIP readiness, and the mandatory direct
SIPS/TLS/SDES-SRTP preflight.

The Bridgefu Web SDK scenario passed through Vapi, Bridgefu, and Amazon Connect.
After its exact cleanup and fresh database reset, the SIP-source scenario also
reached Vapi, transferred through Bridgefu, and reached the available Connect
agent. It retained inbound RTP, sustained active audio, and 187 independently
classified in-band DTMF analyser frames, but failed solely because the redundant
997 Hz single-frequency marker was not detected. Virginia did not start and the
candidate was not sealed or published.

The Oregon stack, temporary Vapi resources, and qualification objects were
deleted. Three stable zero-resource observations spanning more than 60 seconds
reported all 26 resource classes absent. The local correction replaces the SIP
source's two sequential five-second signals with one five-second in-band PCM
DTMF probe after reverse media establishment. Audio presence requires that
probe's two browser-observed frequencies plus inbound RTP bytes and active-audio
frames. The Web marker contract and direct SRTP preflight remain unchanged.

The correction is on `codex/fix-sip-audio-presence-probe`. The complete local
preflight passes: 458 Python tests; all SIP, SDP, and direct-secure Rust tests;
Clippy/format checks; browser syntax and pinned SDK tests; Ruff, ShellCheck, and
actionlint; deterministic packaging; CloudFormation validation; and immutable
Packer validation. Protected review, exact-main CI, and a fresh Oregon candidate
are still required.
Virginia, sealing, and publication remain blocked behind a complete Oregon pass.

## Exact source under evaluation

### Bridgefu runtime

- Repository: public Bridgefu repository
- Release: `v0.9.0`
- Commit: `e00db3289480f93c2783c57440a324e4438e29de`
- SIP/media dependency: exact crates.io `rvoip = 0.3.8`
- The runtime release already contains or supersedes the applicable SIP,
  Contact, media-bind, durable-recovery, replacement, and redacted-evidence
  fixes from the recipe-first branch.

### AWS distribution

- Repository: `bridgefu-vapi-awsconnect`
- Current protected-main release-control commit:
  `73397423add39a3eb849590a1939202832138754`
- Target branch: `origin/main`
- Next eligible version: `0.1.30`, only after every pre-candidate gate below
  passes and the exact audited commit is merged to `origin/main`.

## Gate status

| Gate | Status | Required outcome |
| --- | --- | --- |
| Recipe-first reconciliation | PASSED | Applicable safeguards are preserved and obsolete branch scope is explicitly rejected |
| Secret and repository hygiene | PASSED | History, working-tree, and exact staged-source scans pass with only reviewed synthetic test fixtures |
| Local contract and static gates | PASSED | Complete fail-closed preflight passed on the SIP audio-presence correction worktree |
| Exact merged-main CI | BLOCKED | The SIP correction must pass protected review and all required checks on the resulting exact main commit |
| Retained diagnostic cleanup | PASSED | The exact Oregon `TestDelete` root is absent and its Vapi, ACM, S3, and direct resource checks pass |
| Persistent IAM control plane | PASSED | Reviewed, no-replacement role-stack changes deployed and reverified |
| Exact remote template validation | PASSED | All ten exact rendered templates passed AWS validation in both supported regions (20/20) |
| Private candidate AMI build | PASSED | Exact private cache reuse, fresh two-region copies, immutable staging, and 20/20 remote template validation passed |
| Fresh Oregon qualification | FAILED | Candidate `0.1.29` passed direct SRTP and Web SDK; SIP media reached Connect but the redundant 997 Hz proxy failed. A fresh candidate must pass both paths and teardown with the corrected one-probe contract |
| Fresh Virginia qualification | NOT STARTED | Same immutable bits and checks pass only after Oregon |
| Candidate sealing | NOT STARTED | Signed dual-region evidence and zero-resource receipts |
| Customer publication | NOT STARTED | Public AMIs/snapshots, immutable objects, and `latest` updated last |

Local gate evidence on 2026-08-17:

- deterministic complete-release packaging and `cfn-lint` passed for all ten
  rendered deployable templates plus both publisher templates;
- Packer 1.12.0 validation passed on macOS ARM64 after SHA-256 verification and
  isolated installation of the reviewed Amazon plugin 1.3.9 archive;
- the SIP client, SDP observer, and direct secure probe tests passed, including
  formatting and Clippy for the two security probes;
- the exact pinned Bridgefu Web SDK passed all 20 tests under Node 22/npm 10;
- focused repository-hygiene and AMI-input regression tests passed;
- ShellCheck and actionlint passed;
- the final combined `make preflight` passed with 416 Python unit tests, the
  complete Rust and Node suites, Ruff, ShellCheck, actionlint, deterministic
  release packaging, `cfn-lint`, and Packer validation.
- AWS CloudFormation `ValidateTemplate` accepted all ten exact rendered
  templates in `us-west-2` and all ten in `us-east-1` (20/20), using the same
  bytes produced by the passing deterministic package gate.
- push-triggered CI passed all four required checks on exact merged-main commit
  `c542e3f7edb9be706c316b318b9ac14be21ba138`.
- the retained Oregon diagnostic root and its companion direct-handoff stack
  were deleted; direct service inventory proved zero CloudFormation, Vapi,
  Connect, EC2/VPC, EBS, Lambda, API Gateway, DynamoDB, Secrets Manager, IAM,
  log, alarm, dashboard, ACM, DNS, and qualification S3 resources;
- the persistent publisher and qualification stacks were updated through
  reviewed in-place change sets with zero replacement or removal, their exact
  v5/v4 templates and critical policies passed verification, all expected
  GitHub environment bindings matched, and both stacks report `IN_SYNC`.
- private candidate `0.1.22` stopped before AMI creation or qualification when
  its release-control self-audit proved that `CandidateBuilderRole` could not
  call read-only `iam:GetRole` on itself. CloudFormation had truncated the
  generated physical role name to the canonical `...-publi-CandidateBuilderRole-*`
  family while the v5 policy predicted the untruncated stack-name family. The
  v6 contract corrects only that read-only resource ARN and adds a regression;
  no candidate or smoke infrastructure was created by the failed attempt.
- the v6 correction was merged, exact-main CI passed, the publisher stack was
  updated without replacement, its Original template matched source, drift was
  `IN_SYNC`, and live IAM simulation plus the next candidate proved the formerly
  denied CandidateBuilder self-audit now passes;
- that next candidate compiled the exact runtime and then stopped at the pinned
  CloudWatch Agent public-key import. Reproduction on the exact build OS proved
  the missing `gpg-agent`/exit-2 behavior and proved that dearmor plus an explicit
  no-autostart keyring validates the same key fingerprint and detached signature.
  Packer created no AMI and cleaned its source instance, temporary security
  group, and key pair; the release reaper completed successfully.
- the CloudWatch Agent correction subsequently passed exact-main CI and a fresh
  candidate produced available private AMIs in both regions, proving the image
  build and regional copy boundary;
- Oregon then stopped in read-only DNS preflight before creating a qualification
  stack. The vacancy query requested 100 Route 53 records and applied the strict
  ordinary-hostname parser to every later record before comparing its name.
  Valid unrelated ACM validation labels beginning with `_` and Route 53's
  escaped wildcard labels therefore caused the generic `DNS name is invalid`
  failure. The corrected query reads only the first ordered record and compares
  its bounded raw Route 53 name with the already-validated target before strict
  parsing. Exact-match, ACM-label, escaped-wildcard, and pagination regressions
  cover the boundary;
- failed-candidate recovery removed the two private AMIs and candidate objects.
  Its qualification no-op job independently exposed a transient CloudFormation
  drift-detection handoff: a preceding control-plane inspection temporarily made
  the stack unavailable for another resource drift request. The verifier now
  retries that bounded AWS state rather than treating its first occurrence as a
  permanent cleanup failure.
- the temporary Packer builder is increased from the minimum eight-vCPU
  `m7g.2xlarge` to a pinned 16-vCPU/64-GiB `m7g.4xlarge`, with eight bounded Cargo
  jobs. This affects build time only; the customer runtime remains the reviewed
  `c7g.2xlarge`.
- the first cache-backed candidate exposed an exact snapshot-tag modeling defect:
  Packer propagates the deterministic AMI `Name` tag to the backing snapshot,
  while the verifier expected only the six explicit snapshot tags. The corrected
  verifier requires the full seven-tag AWS shape and rejects a missing or changed
  name. It passed against the actual private cache AMI/snapshot response, merged
  through protected main, and the next candidate reused that cache without a
  compiler instance;
- that cache-backed candidate completed both regional AMI copies, immutable
  staging, and 20/20 remote template validation. Oregon then failed before stack
  creation because the new change-set path used AWS CLI shorthand for a
  JSON-valued CloudFormation parameter. Local mocks inspected argv strings but
  did not exercise the CLI parser. The correction replaces all root change-set
  shorthand fields with one canonical `--cli-input-json` document, parses the
  identical document with the installed AWS CLI and
  `--generate-cli-skeleton output` before setting the stack-created state, and
  submits only after that parser gate passes. Focused tests prove parser-before-
  mutation ordering and exact nested JSON preservation; the full 432-test Python
  suite, Ruff, deterministic packaging, and CloudFormation validation pass.

## Audit safeguards incorporated in the worktree

The following controls are implemented in the current audit delta. They are not
reported as release-passing until the final combined suite succeeds.

### Source and CI binding

- Candidate creation requires a successful `push` CI run for the exact commit on
  `main` before AWS authentication.
- The exact Bridgefu commit and Cargo lock digest are checked out and verified
  before any AWS mutation.
- Customer publication consumes the signed qualified candidate; it does not
  rebuild release bits.

### Shared mutation boundary

- Candidate qualification, manual remote qualification, and qualification
  recovery share one repository-wide, non-cancelling concurrency mutex.
- Publication and publication recovery retain their separate serialization
  boundary.
- Local or retained mutation during a release is prohibited operationally. An
  AWS-side lease is future hardening if concurrent local execution becomes a
  supported workflow; it is not being improvised into this release.

### Credential lifetime

- Oregon and Virginia are separate, ordered jobs.
- Virginia cannot begin until Oregon succeeds.
- Each regional job obtains a fresh AWS session immediately before its single
  regional qualification and has a timeout shorter than the session lifetime.
- Candidate build credentials are refreshed after the AMI build before release
  artifacts are staged.

### Deployed control-plane proof

- The protected AWS account is compared with an exact configured account at
  candidate, publication, and recovery boundaries.
- The deployed publisher and qualification templates must equal the reviewed
  repository templates.
- The qualification and recovery roles must have the exact expected inline
  policy names and no attached policies.
- Security-critical inline statements are compared by exact action, resource,
  and condition contracts.
- The recovery and qualification IAM resources must report `IN_SYNC` through
  CloudFormation resource drift detection before candidate mutation.

### Immutable AMI inputs

- Packer core and the Amazon plugin are exact versions.
- The exact Amazon plugin archive is SHA-256 verified before local installation;
  implicit unverified plugin resolution is not accepted.
- The Amazon Linux source is an exact public AMI identity with reviewed owner,
  name, architecture, state, and region.
- The CloudWatch Agent package, signature, signing key, fingerprint, and version
  are exact and verified before installation.
- The package inventory and immutable build-input document are embedded in the
  AMI/release evidence.
- The signed manifest copy of the AMI inputs must exactly match the inventoried
  `ami-build-inputs.json` artifact.

### Immutable template validation

- Exactly ten deployable templates are expected.
- Each exact S3 object version is HEAD-checked and downloaded.
- Candidate metadata, byte length, and SHA-256 must match the ownership journal.
- All ten objects must pass before any remote validation begins.
- Each exact versioned template is validated in both supported US regions.

### Qualification safeguards incorporated

- Read-only preflight proves account, role/secret account-region binding, public
  DNS delegation and name vacancy, exact candidate AMI, instance offering, and
  bounded service-quota reserve before stack creation.
- The product template is reviewed through an exact change set and the created
  root/nested stack identities are bound to the reviewed execution.
- Active-call telemetry for each smoke must prove CPU and memory are each
  strictly below 60 percent, with compilation excluded, adequate sample
  coverage, and no Bridgefu restart during the call window.
- Cleanup seals the exact owned resource inventory before deletion and requires
  three empty observations spanning at least 60 seconds.
- Resource-tag results are discovery hints only; service APIs must prove whether
  a resource is actually live so stale tag-index entries cannot cause a false
  failure or a false absence.
- The stable observation must keep checking deterministic Vapi ownership
  surfaces so an eventually visible resource cannot appear after a one-time
  cleanup check.

## Repository-hygiene status

The complete-history and current-working-tree scans found no private-key block,
AWS access key, bearer token, JWT, Vapi API key, or signed AWS request URL. The
retained diagnostic evidence was moved outside the repository. Root diagnostic
and failure-evidence directories, browser storage, packet/media captures, build
output, and local credentials are now ignored, with `git check-ignore`
regression coverage.

The exact staged tree was scanned before commit. Eight findings were the exact
reviewed synthetic unit-test fixtures; there were zero unreviewed findings.
Ignored evidence roots were not force-added.

The exact public Amazon Linux AMI identifier and Amazon public owner identifier
in `image/build-inputs.json` are intentional, non-secret supply-chain inputs.
The customer Quick Create link likewise names the intentionally public publisher
bucket; that public routing coordinate is required for deployment and grants no
AWS authority.

## Remaining path to the customer template

1. Complete the local gate for the SIP audio-presence correction, merge it through
   protected `main` and require exact-main CI.
2. Verify recovery removed the failed private candidate, then start one new
   private candidate from that exact protected-main commit using future release
   version input `0.1.30`. This is not yet a Git tag or GitHub Release.
3. Qualify Oregon, destroy it, and prove stable zero resources.
4. Qualify Virginia with the same immutable bits, destroy it, and prove stable
   zero resources.
5. Seal and review the signed receipt.
6. Only after both regions pass, create Git tag `v0.1.30` on the exact qualified
   commit and approve publication. The newest existing Git tag remains
   `v0.1.13`; the repository currently has no GitHub Release objects.
7. Publish public AMI/snapshot permissions and immutable release objects, then
   update `latest` pointers last.

## Historical conclusions retained without live identifiers

- Direct Bridgefu SIPS/TLS with mandatory SDES-SRTP passed.
- Vapi inbound secure media and Bridgefu optional-SRTP transfer behavior were
  isolated and documented.
- The Web smoke now uses Bridgefu's Web SDK and a qualification-owned direct-only
  assistant rather than modifying the product assistant.
- The SIP-source smoke and Web-source smoke both passed in the retained Oregon
  diagnostic environment on the selected runtime.
- CloudWatch-first evidence collection, database reset per scenario, deterministic
  speech input, agent availability, screen pop, bidirectional audio, DTMF, and
  hangup checks were established during retained debugging.
- The recent candidate failures occurred at release-control boundaries,
  before a fresh customer-stack smoke qualification could disprove the product.
- Recovery completed and independent checks found no resources from those failed
  candidates. Exact proof remains in private evidence, not this public ledger.

## Historical control-plane and screen-pop gates

Protected main contains the complete qualification API-intent contract. The
persistent qualification role was updated through a reviewed non-replacing
change set; its exact deployed template, inline policies, RoleId, simulations,
and CloudFormation drift check all passed. A subsequent private candidate
reused the verified AMI cache and passed source, IAM, bucket,
immutable-artifact, all two-region remote `ValidateTemplate` calls, and Oregon
nested-change-set review gates. The complete Oregon customer-product stack
reached `CREATE_COMPLETE`; public and private DNS and ACM validation completed.
The exact candidate AMI/runtime binding passed, the Connect agent was
authenticated and Available, and the direct mandatory-SRTP probe proved
SIPS/TLS, `RTP/SAVP`, SDES-SRTP contexts, audio, DTMF, ACK/BYE, and clean
runtime restoration.

The earlier direct observer failure was corrected by extending the deterministic
marker window from 12 to 32 seconds. The next Oregon run passed the complete
direct mandatory-SRTP preflight and advanced into the Web scenario, proving the
timing correction and secure product path.

Cleanup deleted the full stack and all owned resources, but stable zero proof
then hit a second qualification defect. The vacancy helper applied ordinary
hostname-label syntax to the already-sealed ACM validation CNAME owners. ACM
correctly uses a leading underscore label, so the verifier raised `DNS name is
invalid` even though the records were absent. The local correction permits one
narrow leading-underscore Route53 record label while leaving hosted-zone and
hostname validation strict. A replay of the complete deleted Oregon inventory,
including all CloudFormation-owned resources, Vapi, S3 versions, Route53, and
tagged-resource checks, now returns exactly zero live resources. Future stable
proof failures also report only a fixed non-sensitive subsystem category.

That later Oregon run failed at the exact Agent Workspace screen-pop assertion.
The complete customer stack was `CREATE_COMPLETE`, the direct secure preflight
passed, and cleanup plus three stable zero-resource observations passed; no
candidate resources were retained. The failure artifact did not preserve which
heading/context/field assertion was missing, which is itself a qualification
observability defect.

The pre-deployment source audit found that Configuration embedded dynamic
`$.Attributes.screen_pop_label_N` references inside HTML `TemplateString`
markup even though field labels are immutable deployment configuration. The
existing unit test explicitly required that risky token, so it approved source
syntax rather than the rendered Agent Workspace contract. The local correction
renders HTML-escaped configured labels literally, retains dynamic references
only for per-contact values, and validates the full generated Connect flow.
The browser observer now preserves a private screenshot and fixed booleans for
heading, context-true/context-false, and each ordered field on failure, without
logging field values. Focused Python, Node syntax, Ruff, and diff checks pass;
the complete gate and protected-main merge remain pending.

At that point the next permitted action was the local pre-deployment gate and a
new Oregon-first candidate. The later dated sections below supersede that state.

## 2026-08-18 dual-region candidate result and audio-presence correction

The screen-pop correction passed the complete local gate, protected review,
exact-main CI, and a new private candidate build. Oregon then passed the exact
customer-template deployment, direct mandatory-SRTP preflight, Bridgefu Web SDK
scenario, rvoip SIP-source scenario, Vapi provisioning resilience, active-call
capacity/restart checks, teardown, and three-observation zero-resource proof.
Both configured Agent Workspace screen pops rendered successfully. Active-call
CPU and memory remained far below the strict 60 percent ceiling and Bridgefu
recorded no restart during either scenario.

Virginia deployed the same immutable customer template to `CREATE_COMPLETE`.
Its direct mandatory-SRTP preflight and Bridgefu Web SDK scenario passed. The
SIP-source call also reached Vapi, Bridgefu, and Amazon Connect; the independent
browser observer recorded a real remote audio track, bidirectional RTP, active
audio, one 997 Hz marker episode, and source-to-agent DTMF. It nevertheless
failed because the qualification harness required 50 positive 20 ms analyser
samples and observed 24. Cleanup and the complete stable zero-resource proof
passed. The candidate was correctly not sealed or published.

That failed assertion measured sustained tone duration rather than the intended
binary audio-presence property. The local correction keeps the existing single
five-second transmitted marker and requires one marker episode plus five
positive 20 ms analyser samples. RTP counters, active audio, DTMF, and reverse
media remain independent mandatory evidence. No second five-second probe was
added, and no call-quality claim is derived from this gate.

The next permitted actions are the complete local gate, protected review/merge,
and a fresh Oregon-first candidate using future tag version `0.1.23`. The AMI
cache identity is release-version-bound, so that candidate must compile one new
AMI even though the source inputs are otherwise unchanged. No public Git tag,
AMI permission, release object, or `latest` pointer is permitted until both
regions pass and the signed receipt is reviewed.

## 2026-08-18 v0.1.23 Oregon DTMF-presence result

The audio-presence correction passed the complete local gate, protected review,
merge, and exact-main CI. Candidate `0.1.23` compiled its version-bound AMI on
the 16-vCPU builder, staged and remotely validated every exact template, and
deployed the Oregon customer template to `CREATE_COMPLETE`.

The Oregon Bridgefu Web SDK call reached Amazon Connect with a remote audio
track, bidirectional RTP, active audio, one source marker episode, and 52
positive marker samples. The Agent Workspace analyser did not classify the
separate 350 ms in-band DTMF-5 probe, so the Web scenario failed closed and
Virginia did not start. Teardown succeeded and all three stable zero-resource
observations reported every resource class absent. The candidate was not sealed
or published.

The local correction keeps one five-second audio marker and changes only the
independent DTMF presence probe: its duration is one second, the Agent Workspace
detector uses the same bounded two-frequency power-and-purity criteria as the
already-proven reverse detector, and three consecutive 20 ms observations are
still mandatory. Closed numeric maximums are included only in failure output so
a future miss is diagnosable without audio, SIP targets, or customer data. This
does not measure audio fidelity or call quality.

## 2026-08-18 v0.1.24 Oregon Agent Workspace keypad regression

The DTMF-presence correction passed the complete local gate, protected review,
merge, exact-main CI, candidate build, immutable template staging, and both-region
remote template validation. Oregon deployed the exact customer template to
`CREATE_COMPLETE`, passed the direct mandatory-SRTP preflight, and entered the
Bridgefu Web SDK scenario. Before attempting the reverse DTMF control, the Agent
Workspace observer had already proved a remote audio track, bidirectional RTP,
the single five-second source marker, active audio, and source-to-agent DTMF.

The run then failed only while sending agent-to-source DTMF. The current harness
called the Connect Streams API first and, after that failed, searched for a
number-pad iframe that Agent Workspace does not attach until its keypad control
is opened. The earlier recipe-first live harness contained the proven sequence:
open the keypad, click the nested digit, then use Streams only as a fallback.
That operational learning was not preserved when the stricter reverse-DTMF gate
was added to this repository. Cleanup succeeded and all three stable
zero-resource observations reported every resource class absent.

The local correction restores the proven keypad-first sequence before the media
wait. The Streams fallback now reports only a closed non-sensitive result
category (`unavailable`, connection state, rejection, timeout, throw, or sent)
instead of discarding every failure reason. The media gate remains presence-only:
one five-second marker, one one-second source DTMF interval, RTP in both
directions, and no audio-quality claim.

## 2026-08-18 v0.1.25 Oregon media-ordering regression

The keypad correction passed protected review, exact-main CI, accelerated AMI
creation, immutable staging, and both-region remote template validation. Oregon
deployed the exact customer template to `CREATE_COMPLETE`; the instance emitted
its expected runtime success signal and every nested stack completed. The Web
call reached Amazon Connect with a remote audio track, bidirectional RTP, active
audio, and one 997 Hz marker episode. The source-to-agent DTMF observation did
not converge, so Virginia and sealing were correctly blocked. Cleanup succeeded
and three stable observations spanning more than 60 seconds reported every
owned resource class absent.

The regression was introduced by the keypad correction itself. Candidate
`0.1.24` had already proved the required ordering: wait for incoming media, the
source marker, and source-to-agent DTMF before operating the agent keypad. The
correction restored the older keypad-open sequence but also moved that keypad
operation before the current media-establishment wait. That contradicted the
proven candidate behavior and the explicit media-first qualification contract.

The combined correction preserves the `0.1.24` ordering and the keypad fix:
first require the transferred media path and source probes to converge; then
open the lazily attached Agent Workspace keypad, click digit `6`, and use
Connect Streams only as a bounded fallback. The Web source remains responsible
for observing the reverse DTMF before hangup. A source-level regression now
requires the media convergence gate to precede keypad operation and requires
keypad operation to precede the final media snapshot.

## 2026-08-19 v0.1.26 Oregon reverse-DTMF UI overreach

The media-ordering correction passed protected-main CI, accelerated private AMI
creation, exact immutable staging, and both-region remote template validation.
Oregon deployed the complete customer template to `CREATE_COMPLETE`, bound the
running `c7g.2xlarge` instance to the exact candidate AMI, and passed the direct
mandatory-SRTP preflight. The Bridgefu Web SDK scenario then reached Vapi,
Bridgefu, and Amazon Connect. Agent Workspace was authenticated and Available;
the transferred call had a remote audio track, bidirectional RTP, active audio,
the deterministic marker, and source-to-agent DTMF. The SIP-source scenario did
not start because scenarios remain intentionally serialized around one agent,
database reset, telemetry window, and transient Vapi resources.

The Web scenario failed only on the additional Agent Workspace keypad action:
the keypad-open control succeeded, the lazily attached digit control was not
found in that immediate DOM snapshot, and the one-shot Streams fallback did not
see a contact. That action was not needed to prove the release requirement. The
agent's deterministic fake microphone already emits one one-second in-band DTMF
`6` interval after media establishment, and the independent Bridgefu Web SDK
browser analyser already requires the corresponding 770/1477 Hz pair after it
traverses the complete reverse media path. Requiring a separate Agent Workspace
keypad click therefore tested transient AWS UI automation rather than SIP/media
interoperability or audio presence.

The local correction removes the keypad/Streams UI gate. It derives the bounded
agent DTMF send timestamp from the deterministic microphone schedule and keeps
the independent source-side two-frequency observation mandatory. The existing
single five-second marker, RTP counters in both directions, active-audio checks,
source-to-agent DTMF, screen pop, hangup, and cleanup gates are unchanged. This
remains an audio-presence and DTMF-traversal test; it does not claim to qualify
Amazon Connect's keypad UI or measure call quality.

The failed candidate was not sealed or published. CloudFormation teardown
completed, temporary Vapi resources were absent, the exact versioned
qualification prefix was empty, and three exhaustive zero-resource observations
spanning more than 60 seconds found all 26 resource classes empty. The trusted
reaper then completed successfully. The next permitted actions are the complete
local gate, protected review/merge, and one new Oregon-first candidate. Virginia
and publication remain blocked until Oregon passes both serialized scenarios.

## 2026-08-19 v0.1.27 Oregon cross-browser hangup race

The reverse-DTMF UI correction passed the full local gate, protected review,
exact-main CI, version-bound private AMI build, immutable staging, and all 20
two-region remote template validations. Oregon deployed the customer template
to `CREATE_COMPLETE`, proved the exact candidate AMI on a running
`c7g.2xlarge`, and passed the mandatory direct SIPS/TLS/SDES-SRTP preflight.
The Bridgefu Web SDK call reached Vapi, Bridgefu, and Amazon Connect. The agent
observer proved a real remote track, bidirectional RTP, active audio, and one
source marker episode; the Connect contact completed normally.

The Web scenario failed before the SIP-source scenario because the agent did
not observe the source's separate one-second in-band DTMF interval. This was a
cross-browser completion race, not missing media or a detector threshold miss.
The source browser and agent browser each waited for their own incoming marker
and DTMF, but the source browser originated hangup immediately after its reverse
direction passed. Their repeating fake-microphone schedules have independent
phases, so the source could hang up after the agent marker/DTMF arrived but
before the source microphone reached its next DTMF interval. The agent recorded
53 source-marker samples and zero DTMF-positive samples, which matches that
ordering.

The local correction adds a private, execution-bound peer-media readiness
handshake. After the agent has observed the source marker and DTMF and captured
the screen-pop evidence, it writes a mode-0600 closed-vocabulary readiness file.
The source must validate the exact execution, scenario, and source-call
fingerprint in that file before it may hang up. This retains the single
five-second marker and one-second DTMF presence probe; it does not add a second
five-second test or a call-quality assertion. Focused controller and browser
regressions require this ordering and reject a missing, foreign, or premature
handshake.

The failed candidate was not sealed or published. The wrapper and customer
stacks deleted completely, temporary Vapi resources were absent, and three
stable zero-resource observations found all 26 resource classes empty. The next
permitted action is the complete local gate for the handshake correction,
followed by protected review and a fresh Oregon-first candidate. Virginia and
publication remain blocked until Oregon passes both serialized scenarios.

## 2026-08-19 v0.1.28 Oregon DTMF timestamp-bookkeeping defect

The peer-media handshake correction passed the full local gate, protected
review, exact-main CI, accelerated private AMI build, immutable staging, and all
20 two-region remote template validations. Oregon deployed to
`CREATE_COMPLETE`, the running `c7g.2xlarge` was bound to the exact candidate
AMI, and the direct mandatory-SRTP preflight passed every SIPS/TLS,
RTP/SAVP/SDES-SRTP, media, DTMF, ACK, and cleanup assertion.

The Bridgefu Web SDK call reached and completed through Amazon Connect. The new
handshake did its job: the agent's media convergence passed, including the
source marker and source-to-agent DTMF, and the Web source did not hang up until
the agent wrote its bound media-ready receipt. The scenario then failed only in
the agent observer's final bookkeeping with `Agent Workspace final media
evidence is incomplete`.

The final timestamp calculation incorrectly selected only agent DTMF intervals
that began after the independently observed source marker plus 500 ms. The two
microphone schedules are intentionally asynchronous, so the source browser can
correctly observe the agent's DTMF before the agent observes the source marker.
That filter could therefore erase a real transmitted interval after both
browsers had already proved it. It was not a media or detector failure.

The local correction derives the deterministic agent DTMF send timestamps from
the agent microphone's actual `getUserMedia` capture-resolution time. That is
the real media-establishment boundary. The independent Bridgefu Web browser
must still observe the corresponding two-frequency tone, the peer-media
handshake remains mandatory, and the one-second DTMF presence probe is
unchanged. A regression rejects any return to source-marker-relative DTMF
bookkeeping.

The failed candidate was not sealed or published. Both stacks deleted
completely and three exhaustive zero-resource observations spanning more than
60 seconds found all 26 resource classes empty. Virginia and publication remain
blocked until a fresh Oregon candidate passes both serialized scenarios.

## 2026-08-19 v0.1.29 Oregon SIP audio-presence proxy failure

The timestamp-bookkeeping correction passed the full local gate, protected
review, exact-main CI, accelerated private AMI creation, immutable staging, and
all 20 two-region remote template validations. Oregon deployed the customer
template to `CREATE_COMPLETE`, bound the running `c7g.2xlarge` instance to the
exact candidate AMI, and passed the direct mandatory SIPS/TLS/SDES-SRTP
preflight. The Bridgefu Web SDK scenario then passed through Vapi, Bridgefu,
and Amazon Connect with its screen pop, bidirectional media, DTMF, hangup,
runtime restoration, and active-call telemetry gates. The database was reset
before the independently provisioned SIP-source scenario began.

The SIP source also reached Vapi, transferred through Bridgefu, and reached the
available Amazon Connect agent. The agent browser retained one remote audio
track, 660 inbound RTP packets / 79,303 bytes, 557 active-audio analyser frames,
and 187 positive in-band DTMF-5 frames. Both DTMF frequencies passed the bounded
power and purity classifier. The scenario nevertheless failed because a second,
single-frequency 997 Hz marker had zero positive frames.

This was a qualification-proxy failure, not missing media. The SIP client was
unchanged apart from its rvoip version label since the last retained SIP pass;
the standalone marker had previously passed only as a timing-sensitive proxy.
Vapi/Connect speech processing may suppress a stationary non-speech tone while
preserving real audio and in-band DTMF. Requiring that tone after independently
observing the generated PCM DTMF, inbound RTP bytes, and sustained active audio
made the gate stricter without proving another release property.

The local correction uses one five-second in-band PCM DTMF-5 probe after reverse
agent media is established. The SIP source cannot finish until one complete
probe begins after its first received agent marker. The Agent Workspace browser
must independently observe both DTMF frequencies for consecutive analyser
frames and must retain inbound RTP packets, inbound RTP bytes, a remote audio
track, and active-audio frames. That same bounded signal proves source-to-agent
audio presence and DTMF traversal; it does not claim audio fidelity or reuse an
out-of-band SIP telephone-event indication. The Web SDK scenario retains its
already-proven 997 Hz marker contract, and the mandatory direct SRTP preflight
is unchanged.

The failed candidate was not sealed or published. The complete customer stack,
temporary Vapi resources, and qualification objects were removed, and all three
stable zero-resource observations reported all 26 resource classes absent.
Virginia did not start. The next permitted action is the complete local gate,
protected review/merge, and one fresh Oregon-first candidate. Virginia, sealing,
and publication remain blocked until Oregon passes both serialized scenarios.

## 2026-08-19 v0.1.30 Oregon Vapi rate-window failure

The single-signal SIP correction passed the complete local gate, protected
review, exact-main CI, accelerated private AMI build, immutable staging, and
all two-region remote template validations. Oregon deployed successfully and
the controller advanced through the direct secure preflight, Bridgefu Web SDK
smoke, and rvoip SIP-source smoke. Because the controller invokes the Vapi
provisioning-resilience gate only after both serialized smoke methods return,
this run is the first live confirmation that both corrected source paths
completed on the same immutable candidate.

The candidate failed afterward in the deliberate Vapi delete/reconcile/create/
delete/recreate resilience test. The second recreation completed, but its next
credential ownership read received HTTP 429 on all four attempts. Cleanup then
encountered the same organization-wide rate window. The safe diagnostics show
three retries followed by rejection for each exhausted read; no ambiguous write
was blindly repeated and no response body or credential was retained.

The precise client-policy defect was a five-second cap on `Retry-After` and only
three read retries. That bound is adequate for isolated CloudFormation
provisioning but not for the qualification sequence after two full calls and
multiple intentional resource lifecycle cycles. The local correction keeps the
production Lambda defaults unchanged, gives only live qualification six read
retries with a maximum 30-second `Retry-After`, and inserts two bounded
10-second cooling intervals between destructive lifecycle cycles. POST, PATCH,
and DELETE ambiguity handling and exact ownership reconciliation remain
fail-closed. Regression coverage reproduces the prior four consecutive 429s and
requires the fifth read to succeed without exposing the response body.

The failed candidate was not sealed or published, and Virginia did not start.
Trusted recovery is currently responsible for the failed candidate and Oregon
environment; a replacement candidate is forbidden until that recovery
completes and independent zero-resource verification passes. The next permitted
actions are the complete local gate, protected review/merge, and a fresh
Oregon-first candidate using a new version.
