# Maintainer release guide

## Prerequisites

Deploy `publisher/bucket.yaml` once in every region listed in
`release/regions.json`. Use the bucket name
`bridgefu-vapi-awsconnect-ACCOUNT_ID-REGION`. Deploy
`publisher/oidc-role.yaml` once with the GitHub OIDC provider and the immutable
GitHub owner/repository IDs shown by the protected OIDC diagnostic, plus the
exact regional qualification Vapi secret ARNs used only for orphan recovery.
Do not use the mutable repository name as the IAM subject. Configure the
GitHub `production-release` environment variables:

- `AWS_CANDIDATE_ROLE_ARN`
- `AWS_PUBLISH_ROLE_ARN`
- `RELEASE_SIGNING_KEY_ARN`

Deploy `publisher/qualification-role.yaml` once with that exact signing-key
ARN and both regional qualification Vapi secret ARNs. Use its two role outputs
for the protected qualification environment below.

Configure the protected `live-qualification` environment with:

- `AWS_QUALIFICATION_ROLE_ARN`
- `AWS_QUALIFICATION_CLOUDFORMATION_ROLE_ARN`
- `RELEASE_SIGNING_KEY_ARN`
- `VAPI_API_KEY_SECRET_ARN_US_WEST_2`
- `VAPI_API_KEY_SECRET_ARN_US_EAST_1`
- `PUBLIC_HOSTED_ZONE_ID`
- `PUBLIC_HOSTED_ZONE_NAME`
- `VAPI_PUBLIC_KEY` as an environment secret

Create a separate GitHub environment named `release-recovery` with these
non-secret variables:

- `AWS_RECOVERY_ROLE_ARN`
- `VAPI_API_KEY_SECRET_ARN_US_WEST_2`
- `VAPI_API_KEY_SECRET_ARN_US_EAST_1`

It must have **no required reviewers**, because it is used only by the
`workflow_run` reaper after a failed or cancelled attempt.
Restrict the environment to the repository's protected default branch and the
checked-in **Reap incomplete release work** workflow. Never put release or Vapi
credential values in this environment; the recovery role can read only the two
exact regional Secrets Manager ARNs.

Build in a dedicated publisher account with EBS encryption-by-default disabled.
AWS does not allow an encrypted EBS snapshot to back a public AMI. The release
workflow verifies that every regional snapshot is unencrypted and grants public
snapshot permission before it grants public AMI launch permission.

Before any AMI can be built, `bridgefu.lock.json` must name a remotely reachable
Bridgefu commit containing the exact crates.io rvoip 0.3.7 graph and its
Cargo.lock digest. A private candidate may intentionally use
`release_ready: false`; final publication then requires the immutable signed
dual-region qualification receipt as the explicit release gate.

## Release flow

1. Run `make test qualification-test validate package`.
2. From `main`, manually run **Build and qualify private candidate** with the
   exact intended tag version without the leading `v` (for `v0.1.14`, enter
   `0.1.14`). The run-specific candidate ID is the RC identity; do not add an
   `-rc` suffix unless that suffix is also intended in the published tag.
3. Approve the private build in `production-release`.
4. Approve both disposable regional runs in `live-qualification`.
5. Review the signed qualified-candidate receipt, then create the matching
   `vMAJOR.MINOR.PATCH` tag on that exact commit.
6. Approve final publication in `production-release`.

The candidate workflow builds from the pinned Bridgefu commit, produces private AMIs,
copies them to every supported region, packages deterministic Lambda ZIPs, uploads
versioned artifacts behind an S3 publication-tag gate, and remotely validates
CloudFormation in both US regions. It then creates a fresh disposable Connect
instance in each supported region and runs exactly two calls in each: a real
SIP call into Vapi and a Bridgefu Web SDK call. Both must
transfer through Bridgefu, render the configured Connect screen pop, and prove
audio in both directions. Teardown must prove zero test-owned state. Only then
does it sign a receipt bound to the repository commit, release manifest, exact
S3 object versions, AMI IDs, and both regional evidence files. The later tag
workflow rebuilds nothing: it verifies that receipt, makes those exact AMIs
public, publishes those exact object versions, and updates `latest` last.

If qualification or publication fails or is cancelled, the unreviewed
`release-recovery` environment runs a separate reaper. It removes only resources
bound to that run's ownership journal, or revokes partial publication while
preserving an already-qualified candidate. The manual **Remote live
qualification** workflow can repeat either regional qualification without
publishing.

The AWS account-level S3 Block Public Access policy must permit the regional
release buckets' read-only public bucket policies. Versioning remains enabled, uploads
require TLS, and only `releases/*` and `latest/*` objects are public.

Never reuse a versioned path or AMI name. To withdraw a release, remove its
public AMI launch permissions and move the mutable `latest` pointer back to the
last qualified version; do not change versioned objects.

`release/build_release.py` also generates URL-encoded Quick Create links using
the [AWS Quick Create URL format](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stacks-quick-create-links.html).
