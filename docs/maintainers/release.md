# Maintainer release guide

## Prerequisites

Deploy `publisher/bucket.yaml` in `us-east-1` and `us-west-2`. Deploy
`publisher/oidc-role.yaml` once with the GitHub OIDC provider and both bucket
ARNs. Configure the GitHub `production-release` environment variables:

- `AWS_PUBLISH_ROLE_ARN`
- `ARTIFACT_BUCKET_US_EAST_1`
- `ARTIFACT_BUCKET_US_WEST_2`
- `RELEASE_SIGNING_KEY_ARN`

Build in a dedicated publisher account with EBS encryption-by-default disabled.
AWS does not allow an encrypted EBS snapshot to back a public AMI. The release
workflow verifies that both regional snapshots are unencrypted and grants public
snapshot permission before it grants public AMI launch permission.

Before any AMI can be built, `bridgefu.lock.json` must name a remotely reachable
Bridgefu commit containing the exact crates.io rvoip 0.3.7 graph, its Cargo.lock
digest, and `release_ready: true`.

## Release flow

1. Run `make test validate package`.
2. Run Packer against a private AMI and complete the AMI smoke checks.
3. Run remote CloudFormation and live-call qualification in both supported
   regions with fresh execution IDs.
4. Record the signed qualification evidence.
5. Tag `vMAJOR.MINOR.PATCH`.
6. Approve the protected `production-release` GitHub environment.

The workflow builds from the pinned Bridgefu commit, produces private AMIs,
copies them to both regions, packages deterministic Lambda ZIPs, uploads
versioned artifacts, remotely validates CloudFormation, signs the manifest,
and makes AMIs public last.

The AWS account-level S3 Block Public Access policy must permit the two release
buckets' read-only public bucket policies. Versioning remains enabled, uploads
require TLS, and only `releases/*` and `latest/*` objects are public.

Never reuse a versioned path or AMI name. To withdraw a release, remove its
public AMI launch permissions and move the mutable `latest` pointer back to the
last qualified version; do not change versioned objects.

`release/build_release.py` also generates URL-encoded Quick Create links using
the [AWS Quick Create URL format](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stacks-quick-create-links.html).
