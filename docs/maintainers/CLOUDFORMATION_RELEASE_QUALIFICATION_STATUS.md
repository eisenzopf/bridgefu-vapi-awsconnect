# CloudFormation Release Qualification Status

This is the current maintainer ledger for the Bridgefu Vapi → Amazon Connect
release. It intentionally contains no live AWS account numbers, resource ARNs,
stack names, call identifiers, Vapi object identifiers, signed URLs, or retained
diagnostic payloads. Exact operational evidence belongs in the private,
execution-scoped evidence store and signed candidate receipt.

Last updated: 2026-08-17 (America/Los_Angeles)

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

The prior private candidates are retired; none created a `v0.1.22` Git tag or a
GitHub Release. The latest candidate `0.1.22` attempt reused the verified private
Bridgefu v0.9.0/rvoip 0.3.8 AMI content cache without recompiling, produced fresh
private AMIs in both regions, staged the immutable release objects, and passed
all 20 remote template validations. Oregon then stopped before creating a
qualification stack because the controller encoded the JSON-valued
`ScreenPopFieldsJson` parameter with AWS CLI shorthand syntax. The AWS CLI
rejected the request before CloudFormation received it. Recovery removed both
candidate AMIs and every candidate object version; the verified private content
cache remains available for the next attempt.

Both retained Oregon smoke paths had already passed on the Bridgefu/rvoip 0.3.8
runtime before those candidate-control failures:

```text
rvoip SIP client → Vapi → Bridgefu → Amazon Connect
Bridgefu Web SDK → Vapi → Bridgefu → Amazon Connect
```

Those retained passes are diagnostic evidence, not a substitute for fresh,
immutable, two-region release qualification.

The DNS-vacancy defect, bounded CloudFormation drift-detection handoff, 16-vCPU
immutable builder, exact Rust caches, private content-addressed AMI cache, and
cache snapshot verifier correction are merged through protected `main`.
Exact-main CI passed all four checks. The CloudFormation invocation correction
is currently under local validation: it constructs the complete
`CreateChangeSet` request as one canonical JSON document, runs that exact
document through the installed AWS CLI service-model parser before mutation,
and submits the identical document with `--cli-input-json`. Candidate version
`0.1.22` is vacant, no qualification mutation is active, and recovery proved the
failed candidate absent. The release is therefore at the pre-candidate boundary,
not yet at a release or publication boundary.

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
  `6184a7c023bb38c3d1bce97ddade3bf991fb9eca`
- Target branch: `origin/main`
- Next eligible version: `0.1.22`, only after every pre-candidate gate below
  passes and the exact audited commit is merged to `origin/main`.

## Gate status

| Gate | Status | Required outcome |
| --- | --- | --- |
| Recipe-first reconciliation | PASSED | Applicable safeguards are preserved and obsolete branch scope is explicitly rejected |
| Secret and repository hygiene | PASSED | History, working-tree, and exact staged-source scans pass with only reviewed synthetic test fixtures |
| Local contract and static gates | PASSED | Complete fail-closed preflight passed on the final combined worktree |
| Exact merged-main CI | PASSED | All four required checks passed on current protected-main commit `6184a7c023bb38c3d1bce97ddade3bf991fb9eca` |
| Retained diagnostic cleanup | PASSED | The exact Oregon `TestDelete` root is absent and its Vapi, ACM, S3, and direct resource checks pass |
| Persistent IAM control plane | PASSED | Reviewed, no-replacement role-stack changes deployed and reverified |
| Exact remote template validation | PASSED | All ten exact rendered templates passed AWS validation in both supported regions (20/20) |
| Private candidate AMI build | PASSED | Exact private cache reuse, fresh two-region copies, immutable staging, and 20/20 remote template validation passed |
| Fresh Oregon qualification | FAILED | Merge the canonical JSON `CreateChangeSet` request and real AWS CLI parser gate, then reach direct secure preflight and both Vapi smoke paths before zero proof |
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

1. Merge the live-AWS review-normalization and unexecuted-review cleanup
   corrections through protected `main`, then update the persistent publisher
   role stack to the exact v7 policy contract.
2. Start one new private candidate from that exact protected-main commit using
   future tag version input `0.1.22`. This is not a Git tag or GitHub Release.
3. Qualify Oregon, destroy it, and prove stable zero resources.
4. Qualify Virginia with the same immutable bits, destroy it, and prove stable
   zero resources.
5. Seal and review the signed receipt.
6. Only after both regions pass, create Git tag `v0.1.22` on the exact qualified
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

## Current live gate and next permitted action

The current protected-main revision passed all exact-main CI jobs. Its private
candidate then reused the verified private AMI cache, created fresh private AMIs
in both regions, staged exact-version assets, and passed all twenty remote
`ValidateTemplate` calls in eight minutes.

Oregon passed the prior AWS CLI serialization failure: AWS accepted the
canonical `CreateChangeSet` JSON and constructed the complete root/nested review
hierarchy. The fail-closed reviewer stopped before execution because AWS
normalizes an omitted false `ImportExistingResources` request to JSON `null` in
`DescribeChangeSet`, while the new comparator accepted only literal `false`.
A separate resource-empty live change set reproduced the exact response. The
corrected contract accepts only `null` or literal `false` and continues to
reject true, numeric, string, collection, or otherwise malformed values.

The same live reproduction proved that `DeleteChangeSet` removes nested review
change sets but retains the root `REVIEW_IN_PROGRESS` stack shell. Controller
cleanup now waits for the exact change set hierarchy to disappear, verifies the
exact root stack contains zero resources, deletes that full StackId, and proves
all reviewed stack identities absent. Recovery receives the same exact bounded
path and no longer waits for an ACM certificate that cannot exist in an
unexecuted review. The two observed root review shells were explicitly verified
empty and deleted; the failed candidate's private AMIs and object versions were
removed, while the verified private compile cache remains.

The next permitted actions are: merge these corrections through protected main,
deploy publisher policy contract
`2026-08-18-review-normalization-and-cleanup-v7`, verify it exactly, and launch
one new Oregon-first private candidate using future tag version `0.1.22`. No Git
tag, customer-visible object, or publication is permitted until Oregon and
Virginia both pass, zero-resource proof is sealed, and the signed receipt is
reviewed.
