# Alarm runbooks

These runbooks cover the single-gateway Bridgefu CloudFormation product. Start
with the alarm's named runbook and the stack `DashboardUrl`. Use
`SsmStartSessionCommand` for host inspection; the product has no SSH access.

Never paste customer fields, correlation IDs, SIP messages, SDP, credentials,
private keys, signed URLs, or Vapi response bodies into tickets or public logs.
Keep exact contact and resource identifiers only in the restricted operational
evidence store.

- [Amazon Connect and Agent Workspace](amazon-connect.md)
- [Capacity, throttling, and CPU](capacity.md)
- [Cleanup backlog](cleanup-backlog.md)
- [Deployment and runtime readiness](deployment-readiness.md)
- [DNS and certificates](dns-certificate.md)
- [Handoff API and context](handoff-context.md)
- [Starter recovery](starter-recovery.md)
- [Vapi provisioning](vapi-provisioning.md)

This release is one ARM64 EC2 gateway. It does not claim seamless high
availability or safe generic load-balancer failover for stateful SIP/RTP calls.
