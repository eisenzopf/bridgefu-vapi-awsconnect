# Starter recovery, backup, and disaster recovery

## Impact

The single Bridgefu host or Availability Zone is unavailable. New calls stop and
active calls on that host end; DynamoDB context remains independent. This v1
topology provides recovery, not seamless failover.

## Safe checks

1. Distinguish EC2 system failure from instance/application failure and check
   volume health, Elastic IP association, DNS, SSM, alarms, and the last bounded
   active-call/cleanup evidence.
2. Identify the latest encrypted data-volume recovery point and DynamoDB PITR
   window before changing resources.
3. Preserve failed-host CloudWatch events and console output without customer
   payloads.

## Remediation

- For a system-status failure, use EC2 recovery when no active-call evidence
  makes that unsafe. The logical instance retains its EIP and volumes.
- For an application failure, use a reviewed parallel deployment of the last
  qualified release after draining or explicitly accepting active-call loss.
- For instance loss, recover through reviewed CloudFormation operations, attach
  or restore the encrypted data volume, confirm the EIP/DNS, and validate
  readiness before admitting calls.
- Restore volume corruption to a new volume from AWS Backup; never overwrite the
  only retained volume.
- Restore DynamoDB accidental writes to a new table at a selected PITR time and
  cut over only through a reviewed deployment.

Do not improvise multi-host SIP/RTP load balancing. A separate qualified
architecture is required when the recovery objective demands continued calls
through host or Availability Zone loss.

## Verify

Prove the data mount, readiness, certificate, EIP/DNS, synthetic handoff,
durable cleanup reconciliation, and one controlled real call. Record recovery
point/time, expected data-loss window, revision, and RTO/RPO without PII.
