# Operate the deployment

## Monitor

Use the stack outputs:

- `DashboardUrl` shows API latency, Lambda errors, DynamoDB health, active
  Bridgefu calls, host health, and certificate expiry.
- `SsmStartSessionCommand` opens an audited SSM session. The stack opens no SSH
  port and creates no key pair.
- `BridgefuInstanceId`, `BridgefuAmiId`, `ReleaseVersion`, and
  `ScreenPopSchemaHash` identify the running release.

Application logs contain result categories, durations, and opaque hashes—not
screen-pop field values, Vapi responses, bearer values, or API keys.

## Update

Update the stack with a newer immutable template URL. Review the change set
before executing it. An AMI change replaces the single EC2 gateway and briefly
interrupts new transfers, so use a maintenance window.

Changing `ScreenPopFieldsJson` updates the Bridgefu-owned Vapi tool, DynamoDB
schema hash, lookup behavior, and Connect screen-pop rendering. It never
rewrites the Vapi assistant after initial creation.

## Rotate credentials

- Rotate the Vapi private key by replacing the value of the existing Secrets
  Manager secret, then run a no-op stack update to revalidate provisioning.
- Stack-owned webhook, correlation, and control credentials are isolated in
  Secrets Manager. Replacing one requires a reviewed stack change because both
  sides of the integration must change together.

## Delete

Deleting the stack removes Bridgefu EC2, its VPC, Lambdas, API Gateway, alarms,
and Bridgefu-owned Connect flows. It never modifies or deletes the customer
destination flow.

Production defaults retain:

- The DynamoDB context table and Bridgefu data volume.
- The new Vapi assistant, preparation tool, and webhook credential.

This prevents stack deletion from destroying a developer-customized assistant
or retained caller context. Remove those objects separately only after checking
their IDs against the deleted stack outputs. Disable DynamoDB deletion
protection before deliberately purging the retained table.

