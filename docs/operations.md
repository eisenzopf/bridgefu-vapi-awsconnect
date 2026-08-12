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

## Update configuration

Create and review a CloudFormation change set before every update. Within the
same released template, v1 supports reviewed customer-configuration changes
such as the screen-pop schema, routing, context TTL, alarms, log retention, and
EC2 instance size.

Changing `ScreenPopFieldsJson` updates the Bridgefu-owned Vapi tool, DynamoDB
schema hash, lookup behavior, and Connect screen-pop rendering. It never
rewrites the Vapi assistant after initial creation.

The settings written into the gateway at first boot are immutable in v1:
`DeploymentId`, `ConnectInstanceArn`, `PublicHostedZoneId`, `SipHostname`,
`SipSecurity`, `MaxConcurrentCalls`, `DataRetentionMode`, and the release AMI.
CloudFormation rejects changes to them before dependent infrastructure updates.
Use the parallel-deployment procedure below when any of these settings must
change. This prevents a stack update from claiming success while the running
gateway still has its launch-time configuration.

## Upgrade the Bridgefu release

Do not update an existing v1 stack to a template containing a different AMI or
change any other launch-bound setting listed above.
The single gateway uses a stable network interface and data volume, which
cannot be attached to CloudFormation's create-before-delete EC2 replacement.
The stack rejects that unsafe update before replacing the instance.

Use a parallel deployment for a release upgrade:

1. Launch the new qualified release with a new `DeploymentId` and SIP hostname.
2. Configure its new Vapi template assistant and place a complete verification
   call through Amazon Connect.
3. Move callers to the verified assistant.
4. Monitor the old and new stacks during the cutover.
5. Retire the old stack using the deletion procedure below.

v1 does not migrate the old stack's DynamoDB records or runtime data volume.
Production retention keeps them with the old deployment for their configured
retention lifecycle.

## Rotate credentials

- Validate a replacement Vapi private key against Vapi, then replace the value
  of the existing Secrets Manager secret. The provisioning Lambda reads it on
  the next Vapi-owning stack update or deletion. Calls use the separate
  stack-owned webhook credential, so rotating this provisioning key does not
  by itself change the live call path. v1 has no no-op key-validation action.
- Stack-owned webhook, correlation, and control credentials are isolated in
  Secrets Manager. v1 has no independent safe rotation workflow for these
  coupled values. Do not edit only one side; replace the deployment using the
  release-upgrade procedure.

## Delete

Deleting the stack removes Bridgefu EC2, its VPC, Lambdas, API Gateway, alarms,
and Bridgefu-owned Connect flows. It never modifies or deletes the customer
destination flow.

Production defaults retain:

- The DynamoDB context table and Bridgefu data volume.
- The AWS Backup vault and its recovery points.
- The new Vapi assistant, preparation tool, and webhook credential.

This prevents stack deletion from destroying a developer-customized assistant
or retained caller context. The retained Vapi objects no longer have a working
Bridgefu AWS endpoint after stack deletion, so record the stack outputs and
remove or detach those exact objects in Vapi as part of a planned retirement.
Disable DynamoDB deletion protection before deliberately purging the retained
table.

Bridgefu-owned CloudWatch log groups are deleted with the stack. Their
`LogRetentionDays` setting controls log lifetime only while the stack exists;
export any required operational records before deletion. Production retention
does not retain CloudWatch logs.
