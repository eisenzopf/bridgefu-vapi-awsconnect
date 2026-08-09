# Maintainer release guide

## Prerequisites

Deploy `publisher/bucket.yaml` once in every region listed in
`release/regions.json`. Use the bucket name
`bridgefu-vapi-awsconnect-ACCOUNT_ID-REGION`. Deploy
`publisher/oidc-role.yaml` once with the GitHub OIDC provider. Configure the
GitHub `production-release` environment variables:

- `AWS_PUBLISH_ROLE_ARN`
- `RELEASE_SIGNING_KEY_ARN`

Configure the protected `live-qualification` environment with:

- `AWS_QUALIFICATION_ROLE_ARN`
- `AWS_QUALIFICATION_CLOUDFORMATION_ROLE_ARN`
- `VAPI_API_KEY_SECRET_ARN`
- `PUBLIC_HOSTED_ZONE_ID`
- `PUBLIC_HOSTED_ZONE_NAME`
- `VAPI_PUBLIC_KEY` as an environment secret

Build in a dedicated publisher account with EBS encryption-by-default disabled.
AWS does not allow an encrypted EBS snapshot to back a public AMI. The release
workflow verifies that every regional snapshot is unencrypted and grants public
snapshot permission before it grants public AMI launch permission.

Before any AMI can be built, `bridgefu.lock.json` must name a remotely reachable
Bridgefu commit containing the exact crates.io rvoip 0.3.7 graph, its Cargo.lock
digest, and `release_ready: true`.

## Release flow

1. Run `make test qualification-test validate package`.
2. Tag `vMAJOR.MINOR.PATCH`.
3. Approve the private candidate build in `production-release`.
4. Approve the disposable live run in `live-qualification`.
5. Approve final publication in `production-release` after reviewing evidence.

The workflow builds from the pinned Bridgefu commit, produces private AMIs,
copies them to every supported region, packages deterministic Lambda ZIPs, uploads
versioned artifacts, and remotely validates CloudFormation in both US regions.
It then creates a fresh disposable Connect instance in Oregon and runs exactly
two calls: a real SIP call into Vapi and a Bridgefu Web SDK call. Both must
transfer through Bridgefu, render the configured Connect screen pop, and prove
audio in both directions. Teardown must prove zero test-owned state. Only then
does the workflow sign the manifest and evidence, make AMIs public, and update
`latest`.

If qualification or publication fails, the workflow revokes any partial public
permissions and removes only that new version's candidate AMIs, snapshots, and
staged S3 objects. The manual **Remote live qualification** workflow can repeat
the same qualification in `us-east-1` without publishing.

The AWS account-level S3 Block Public Access policy must permit the regional
release buckets' read-only public bucket policies. Versioning remains enabled, uploads
require TLS, and only `releases/*` and `latest/*` objects are public.

Never reuse a versioned path or AMI name. To withdraw a release, remove its
public AMI launch permissions and move the mutable `latest` pointer back to the
last qualified version; do not change versioned objects.

`release/build_release.py` also generates URL-encoded Quick Create links using
the [AWS Quick Create URL format](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stacks-quick-create-links.html).
