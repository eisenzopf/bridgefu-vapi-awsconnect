# Deployment and runtime readiness

## Impact

CloudFormation is incomplete, Bridgefu reports not ready, or new transfers
cannot be admitted. Do not replace the host until active calls and cleanup state
are known.

## Safe checks

1. Read root and nested CloudFormation events and identify the first failed
   logical resource, not the final cascading failure.
2. Check EC2 system/instance status and Systems Manager managed-node state.
3. Inspect the Bridgefu runtime log group, metrics, and bootstrap console output.
   Search bounded result categories only; do not enable request or SDP logging.
4. Through SSM, inspect `systemctl status bridgefu haproxy
   amazon-cloudwatch-agent` and the relevant unit journal.
5. Check the dedicated encrypted data-volume mount, certificate files, installed
   AMI identity, and loopback `/livez` and `/readyz` endpoints.

## Decision and remediation

- Artifact failure: verify the exact S3 object VersionId and SHA-256 plus the
  runtime role's narrow access. Never substitute a mutable `latest` object.
- Data-volume failure: verify exactly one non-root volume is attached in the
  expected Availability Zone. Do not format a volume with an unexpected
  filesystem.
- Configuration failure: render in a clean directory and run Bridgefu's real
  validator. Fix source configuration, not the generated host file.
- Certificate failure: follow [DNS and certificates](dns-certificate.md).
- Service crash: preserve the exit status and bounded CloudWatch/journal events,
  then use a reviewed parallel deployment if the immutable AMI is defective.
- EC2 system failure with no active calls: allow the recovery alarm. With active
  calls, drain if possible before intervention.

Never add SSH, expose the control API, disable IMDSv2, or broaden security groups
as a diagnostic shortcut.

## Verify

Confirm `/livez`, `/readyz`, hostname-verified TLS signaling,
`RuntimeReady=1`, zero cleanup backlog, the expected AMI/release identity, and a
synthetic prepare/transfer/lookup. Record the logical resource, cause, revision,
action, and times without customer data or correlation IDs.
