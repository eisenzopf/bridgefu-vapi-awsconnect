# Recipe-first production reconciliation

## Purpose and authority

This document reconciles the useful production lessons from Bridgefu branch
`origin/codex/recipe-first-production` with the current
`bridgefu-vapi-awsconnect` release path. It is an audit guide, not an execution
ledger, release receipt, or authorization to deploy.

Audit basis:

- Bridgefu recipe-first tip: `4dcb8af01328d7a2e68403eea4b5d9aedc0612f4`.
- Bridgefu recipe-first merge base: `f34a35c1c6ed65e2c371c6bedbf6f301f2b72055`.
- Current Bridgefu main: `e00db3289480f93c2783c57440a324e4438e29de`
  (`v0.9.0`).
- Current distribution main: `9bf6e85a7b82ba140cc7177ff419c51d786b6306`.
- Current distribution audit delta: the uncommitted release-control,
  supply-chain, workflow-serialization, and credential-lifetime changes in the
  working tree. Those changes are not release evidence until reviewed, merged,
  and exercised from the exact merged commit.

The recipe-first branch should not be merged wholesale. It contains a large
AWS product, local live controller, setup application, HA implementation,
Terraform wrappers, and qualification system that predate or conflict with the
current two-repository boundary. A wholesale merge would also regress later
Bridgefu main fixes described below.

## Reconciled product boundary

The durable lesson from the recipe-first work is separation of concerns:

- `bridgefu` owns the provider-neutral runtime: recipe compilation, SIP call
  admission, one-use routes, context projection, media bridging, Amazon Connect
  call execution, and redacted security evidence.
- `bridgefu-vapi-awsconnect` owns this product distribution: the single-server
  AMI, CloudFormation, Lambda functions, Connect wrapper/guide, Vapi template
  resources, disposable qualification, recovery, release signing, and public
  Quick Create artifacts.

The Vapi-to-Amazon-Connect CloudFormation product therefore remains in this
repository. The copy under the old Bridgefu `recipes/` tree is historical
design input, not a second source of deployable customer infrastructure.

## Runtime and SIP behavior

| Recipe-first lesson | Current disposition | Evidence |
|---|---|---|
| Use a data-only recipe to project a Vapi SIP ingress and Amazon Connect destination. | Preserved in Bridgefu main. The distribution renders the built-in `vapi-amazon-connect-screen-pop@1` recipe rather than carrying another runtime implementation. | `bridgefu@e00db32:src/recipes/`, `bridgefu@e00db32:src/recipe_admission.rs`, and this repository's `image/runtime/bridgefu.yaml.tmpl` and `image/runtime/render.py`. |
| Admit only the server-owned route and correlation context; reject malformed or duplicate correlation headers without spending an unrelated route. | Preserved. The current distribution derives and stores bounded context in Lambda, passes exactly `X-Correlation-Id`, and Bridgefu consumes the one-use route. | `lambda/common/bridgefu_handoff.py`, `lambda/prepare_handoff/handler.py`, `lambda/transfer_destination/handler.py`, `tests/unit/test_handoff.py`, and Bridgefu's recipe-admission and call-supervisor tests. |
| Production signaling must use TLS and secure media must remain independently observable. | Preserved and strengthened. `sips_srtp` requires SIPS/TLS plus `RTP/SAVP` and SDES-SRTP. A direct qualification probe proves this without Vapi before either end-to-end smoke. | `qualification/direct-secure-probe/`, `qualification/direct_secure_preflight.py`, `qualification/schemas/evidence-v2.schema.json`, `tests/unit/test_secure_preflight_gate.py`, and `tests/unit/test_scenario_security_and_readiness.py`. |
| Interoperate when Vapi transfers with TLS signaling but offers only clear RTP. | Superseded by the evidence-based optional mode merged after the recipe-first branch diverged. `sips_optional_srtp` returns a `sip:` URI with `;transport=tls`, requires observed TLS, accepts `RTP/SAVP` when offered, and permits `RTP/AVP` only in optional mode. The URI text alone is never TLS evidence. | Bridgefu main commits `2f6cf2f`, `2fb2eae`, `53ef1c7`; `cloudformation/template.yaml`; `image/runtime/render.py`; `qualification/controller.py`; `tests/unit/test_handoff.py`; and `tests/unit/test_scenario_security_and_readiness.py`. |
| Keep the clear SIP listener separate from public media binding and advertise a usable secure Contact. | Superseded by later Bridgefu main fixes. Current main preserves the public RTP bind for isolated egress profiles, normalizes empty trickle ICE MIDs, retries replacement version races, and emits closed redacted security evidence. The older branch predates those final forms. | Bridgefu main commits `7c80890`, `22424d2`, `1fa3b36`, `f350cd7`, and `71558b2`; the distribution lock is `bridgefu.lock.json`. |
| Use published rvoip crates, not an unpublished local fork. | Preserved with a newer exact release. Recipe-first's `0.3.7` finding is historical; current runtime and qualification clients require exact crates.io `rvoip = 0.3.8`. | `bridgefu.lock.json`, `release/verify_bridgefu.py`, `qualification/direct-secure-probe/Cargo.lock`, `qualification/sip-client/Cargo.lock`, `.github/workflows/ci.yml`, and `.github/workflows/candidate.yml`. |
| Customer Connect resources are references; Bridgefu owns only its wrapper, guide, Lambda association, and transfer integration. | Preserved. | `cloudformation/nested/connect.yaml`, `cloudformation/nested/configuration.yaml`, `connect/agent-guide-flow.json.tmpl`, `connect/inbound-flow.json.tmpl`, and `tests/unit/test_connect_flow.py`. |
| Browser qualification must exercise the actual Bridgefu browser SDK. | Superseded. The former CloudFront/Vapi-Web-SDK proof is not release evidence. The current deterministic site builds `@bridgefu/webrtc-browser`; the browser attaches to Bridgefu, and qualification uses an execution-owned direct-only Vapi assistant. | `qualification/build_demo_site.py`, `qualification/demo-site/`, `qualification/browser/bridgefu-web-playwright.mjs`, `qualification/bridgefu_web_handoff.py`, `qualification/controller.py`, `tests/unit/test_bridgefu_web_handoff.py`, and `tests/unit/test_qualification_controller.py`. |

The default customer posture is `sips_optional_srtp`, because it keeps SIP
signaling on TLS while interoperating with Vapi's observed `RTP/AVP` transfer
offer. This does not convert RTP into SRTP. Operators requiring encrypted media
must select `sips_srtp` and accept that the call fails if the peer does not
offer SRTP. `sip_rtp` remains restricted by CloudFormation to disposable
`TestDelete` diagnostics and cannot qualify a production release.

## Release safeguards carried forward

The following are source-level controls currently present in main or the audit
delta. Their presence is not a claim that the current uncommitted delta, a
`0.1.22` candidate, or either live regional qualification has passed.

| Safeguard | Current implementation | Contract or regression coverage |
|---|---|---|
| Exact runtime source and dependency graph | `bridgefu.lock.json`; detached source checkout and Cargo.lock digest verification in `.github/workflows/candidate.yml`; `release/verify_bridgefu.py` | `tests/unit/test_release.py`, `tests/unit/test_qualification_assets.py` |
| Reviewed AMI inputs instead of `most_recent` or `latest` | `image/build-inputs.json`, `release/ami_build_inputs.py`, `image/bridgefu.pkr.hcl`, signed-and-hashed CloudWatch Agent installation in `image/install.sh`, and release-manifest inclusion in `release/build_release.py` | `tests/unit/test_ami_build_inputs.py`, `tests/unit/test_candidate_release_preflight.py` |
| Successful CI on the exact main commit before AWS authentication | `Require successful exact-main CI before AWS authentication` in `.github/workflows/candidate.yml` | `tests/unit/test_candidate_release_preflight.py` |
| Exact AWS account before release or recovery mutation | `AWS_ACCOUNT_ID` checks in `.github/workflows/candidate.yml`, `.github/workflows/release.yml`, and every mutation job in `.github/workflows/release-reaper.yml` | `tests/unit/test_candidate_release_preflight.py`, `tests/unit/test_aws_account_boundary.py` |
| Exact deployed release-control plane, not merely desired templates | The candidate compares deployed original templates, policy-contract outputs, role drift, inline-policy inventories, absence of attached policies, and critical deployed statement bodies before its first candidate mutation. | `.github/workflows/candidate.yml`, `publisher/oidc-role.yaml`, `publisher/qualification-role.yaml`, `release/verify_deployed_iam.py`, `tests/unit/test_deployed_iam_contract.py`, `tests/unit/test_qualification_assets.py` |
| Exact versioned CloudFormation validation | All ten root/nested templates are journaled with VersionId, hash, size, and candidate metadata, downloaded and rehashed, then each exact URL is validated in both regions. | `release/validate_staged_templates.py`, `tests/unit/test_staged_template_validation.py`, `release/build_release.py` |
| Immutable workflow dependencies and exact tool versions | GitHub actions are pinned to full commit SHAs; Packer, its Amazon plugin, Ruff, cfn-lint, Session Manager plugin, source AMI, and CloudWatch Agent inputs are bounded. | `.github/workflows/*.yml`, `image/build-inputs.json`, `tests/unit/test_workflow_mutation_contract.py`, `tests/unit/test_qualification_assets.py` |
| Fresh, ordered regional credentials | Oregon and Virginia are separate jobs; Virginia depends on Oregon. Each obtains one 10,800-second role session immediately before its single-region AWS run and has a 165-minute job timeout. Candidate credentials are refreshed after the AMI build before packaging/staging. | `.github/workflows/candidate.yml`, `tests/unit/test_candidate_credential_lifetime.py` |
| Qualification cannot modify the product assistant | The controller records only a GET/digest of the stack-created product assistant, creates an execution-owned direct tool and direct-only assistant, binds the qualification identity secret, and proves the product digest unchanged during cleanup. | `qualification/bridgefu_web_handoff.py`, `qualification/controller.py`, `lambda/common/bridgefu_handoff.py`, `tests/unit/test_bridgefu_web_handoff.py`, `tests/unit/test_qualification_controller.py` |
| Crash-safe ownership and narrow recovery | Vapi phone/direct-tool/direct-assistant intents and ownership are journaled before and after creation. Reaping requires exact ownership and removes only recorded Vapi, CloudFormation, ACM, S3, AMI, and snapshot resources. | `qualification/controller.py`, `release/reap_qualification.sh`, `publisher/qualification-role.yaml`, `publisher/oidc-role.yaml`, `tests/unit/test_recovery_policy_contract.py`, `tests/unit/test_qualification_cleanup_contract.py` |
| Qualification before publication | The candidate remains private, qualifies Oregon then Virginia, verifies teardown, and seals a signed receipt bound to exact AMIs, S3 versions, evidence, source commits, and manifest. Tag publication rebuilds nothing and updates `latest` last. | `.github/workflows/candidate.yml`, `.github/workflows/release.yml`, `tests/unit/test_release.py`, `tests/unit/test_secure_preflight_gate.py` |

## Mutation serialization policy

All GitHub workflows that can mutate the shared qualification Vapi
organization or AWS qualification control plane use the repository-wide mutex
`bridgefu-vapi-awsconnect-qualification-mutation`:

- **Build and qualify private candidate** (`.github/workflows/candidate.yml`);
- **Remote live qualification** (`.github/workflows/remote-qualification.yml`);
- qualification cleanup triggered by **Reap incomplete release work**
  (`.github/workflows/release-reaper.yml`).

The mutex is deliberately constant; it is not scoped by version, region,
execution ID, or workflow run. Publication and interrupted-publication recovery
remain on their separate release mutex because they consume an already sealed
candidate and do not create qualification Vapi resources.

The GitHub mutex does not serialize a developer workstation. Therefore the v1
operator policy is:

1. Do not start `qualification/controller.py`, a retained-environment helper,
   or any local AWS/Vapi mutating diagnostic while a candidate, remote
   qualification, qualification recovery, publication, or publication recovery
   run is queued or active.
2. Do not dispatch any of those GitHub workflows while a local controller or
   retained diagnostic has mutation authority or owned resources in progress.
3. Read-only inspection is allowed only when it cannot refresh, bind, reconcile,
   delete, or otherwise change AWS or Vapi state.
4. Treat the release window as active from candidate dispatch until successful
   sealing and publication, or until failed-run recovery and independent cleanup
   review finish.

There is no AWS-side distributed lease in v1. This procedural exclusion is a
release requirement, not an implementation detail. An AWS-side lease is future
hardening if concurrent local execution is ever supported; local/GitHub
concurrency must not be enabled merely because the GitHub mutex exists.

## Intentionally obsolete or outside v1

The following recipe-first artifacts are not inputs to `v0.1.22`:

- AWS CloudFormation, Lambda, runtime, and qualification assets beneath the old
  Bridgefu `recipes/vapi-amazon-connect-screen-pop/` directory. Their maintained
  equivalents live in this repository.
- The monolithic local `scripts/aws-recipe-live-test.py` release authority and
  its repository-local/private ledger model. The current release uses bounded
  GitHub jobs, S3 ownership journals, a separate recovery role, and signed
  receipts. Local retained diagnostics remain debugging-only and are prohibited
  during a release.
- HA runtime, HA observability, RDS/Valkey, bounded worker autoscaling, HA
  Terraform, and HA runbooks. v1 is one ARM64 EC2 Bridgefu gateway.
- Terraform parity, account-governance/foundation automation, Control Tower
  integration, and two-account production administration. They may inform a
  future administrator product but are not customer-template dependencies.
- The Dioxus setup application, `bridgefu-setup-core`, and embedded Vapire
  overlay. v1 is CloudFormation plus documented Secrets Manager and Vapi
  template-assistant configuration.
- Modifying an existing customer Vapi assistant. The customer stack creates a
  new Bridgefu template assistant; qualification creates another temporary
  direct-only assistant and proves the product assistant unchanged.
- CloudFront as a required product component and stock `@vapi-ai/web` as a
  qualification source. The current browser bundle is an immutable
  qualification artifact using Bridgefu's SDK.
- IP-only SIP/RTP as production evidence, rvoip `0.3.7`, and the earlier
  assumption that a `sips:` URI alone proves TLS/SRTP.
- Other recipes, a general recipe marketplace, Genesys, Google Infrastructure
  Manager, and a general administration UI.

These exclusions do not declare the old work incorrect. They keep the first
supported release bounded to the product customers are waiting for.

## Remaining gates before a `v0.1.22` customer release

No item below is recorded as passed by this reconciliation.

### 1. Close the source and local audit delta

1. Review the current working-tree delta as release-control code, not as a
   live-fix scratchpad. Commit only the intended workflow, IAM, AMI-input,
   staged-template, release, and test files.
2. Run the complete local gate from the final clean commit: Python/Rust/Node
   tests, Ruff, actionlint, shell parsing, deterministic Lambda/release builds,
   Packer validation, and CloudFormation lint.
3. Merge through review and require a successful push-triggered `ci.yml` run on
   the exact resulting `main` commit. The candidate workflow rejects a PR-only,
   feature-branch, failed, or different-SHA result.
4. Reconfirm that `bridgefu.lock.json` names reachable Bridgefu commit
   `e00db3289480f93c2783c57440a324e4438e29de`, its exact Cargo.lock digest, and
   crates.io rvoip `0.3.8`. If Bridgefu changes, repeat the source and runtime
   audit rather than editing the digest alone.
5. Review `image/build-inputs.json` as release material: exact AL2023 ARM64 AMI,
   owner/name/region, exact Packer and Amazon plugin versions/hashes, and exact
   CloudWatch Agent package, signature, key, fingerprint, and hashes.

### 2. Deploy and configure the persistent release control plane

1. Add the exact 12-digit `AWS_ACCOUNT_ID` variable to the
   `production-release`, `live-qualification`, and `release-recovery` GitHub
   environments. Recheck every existing role ARN, signing-key ARN, regional
   Vapi secret ARN, and public hosted-zone value against that account.
2. Update `publisher/oidc-role.yaml` and `publisher/qualification-role.yaml`
   through reviewed in-place CloudFormation change sets from the exact merged
   commit. Do not hand-edit role policies.
3. Verify the deployed original templates equal the repository bytes, the
   publisher output is
   `PublisherPolicyContractVersion=2026-08-17-bound-release-control-plane-v5`,
   and the qualification output is
   `QualificationPolicyContractVersion=2026-08-17-bound-qualification-control-plane-v4`.
4. Verify `RecoveryRole` and `QualificationRunnerRole` are `IN_SYNC`, each has
   exactly its expected inline policy, neither has an attached managed policy,
   and `release/verify_deployed_iam.py` accepts their deployed critical
   statements.
5. Recheck environment controls: `production-release` and
   `live-qualification` require the intended approvals; `release-recovery` has
   no required reviewer and is restricted to the default branch and checked-in
   reaper workflow. Keep credentials and Vapi keys out of variables, artifacts,
   arguments, and repository files.
6. Verify both regional artifact buckets remain versioned and private before
   publication, the signing key is the configured receipt key, the reviewed
   source AMI is still exactly available, and `0.1.22` has no existing release
   objects, AMIs, snapshots, candidate receipt, or Git tag.

### 3. Run one immutable private candidate

1. Prove no local controller or retained run is active, no local diagnostic
   owns mutable resources, and no qualification/recovery workflow is queued or
   running.
2. Dispatch **Build and qualify private candidate** from the exact green `main`
   commit with version `0.1.22`.
3. Review the candidate build and its exact source/AMI-input/control-plane
   preflight. Do not bypass a source, account, drift, policy, template, or
   supply-chain rejection.
4. Allow Oregon to run first. It must deploy the immutable customer template,
   pass the independent mandatory-SRTP control, then pass both required sources:

   ```text
   rvoip SIP client -> Vapi -> Bridgefu -> Amazon Connect
   Bridgefu Web SDK -> Vapi -> Bridgefu -> Amazon Connect
   ```

   Both scenarios must satisfy the evidence-v2 contract and Oregon teardown
   must prove zero owned resources.
5. Virginia may start only after Oregon succeeds. It must use the same candidate
   artifacts and pass the identical controls, calls, and zero-state proof.
6. Any failure stops at that gate. Let the ownership-bound reaper finish,
   independently review cleanup, add a regression, and choose a new version;
   never reuse `0.1.22` after a candidate failure.

### 4. Seal, review, and publish

1. Require the candidate workflow to produce a signed receipt bound to the
   exact distribution commit, Bridgefu commit, AMIs, manifest, S3 VersionIds,
   regional evidence, scenarios, and zero-state proofs.
2. Review that receipt before creating a tag. No customer-visible `latest`
   pointer exists at this point.
3. Create `v0.1.22` on the exact qualified distribution commit and approve
   **Publish qualified release**.
4. Publication must verify every recorded object version and AMI, publish those
   exact qualified objects without rebuilding, make the exact AMIs/snapshots
   public, publish the qualification receipt, and update `latest` last.
5. Verify the public Quick Create template and both supported US region paths
   resolve to the signed immutable release. Record the final evidence in the
   qualification status ledger; this reconciliation document remains unchanged
   unless the product or release policy changes.

## Decision

The recipe-first branch supplied valuable architecture, ownership, safety, and
operational lessons. The current Bridgefu main and this distribution preserve
the relevant single-server runtime and handoff behavior while superseding the
branch's older SIP assumptions and moving AWS release ownership to the correct
repository. The remaining work is release-control deployment, configuration,
and immutable live qualification—not reintroducing the old recipe directory or
expanding v1 scope.
