# Vapi provisioning and authentication

## Impact

The Vapi nested stack fails, prepare/transfer webhooks return `401`/`403`, or
the assistant does not request a dynamic transfer destination.

## Safe checks

1. Read the provisioner Lambda's safe operation, resource type, HTTP status,
   attempt, result category, and ownership-reconciliation count. Response bodies
   and keys must remain absent from logs.
2. Verify the supplied Secrets Manager ARN exists in the stack account and
   region and only the exact provisioner role can read it.
3. In Vapi, confirm deterministic Bridgefu names/ownership metadata,
   prepare/transfer URLs, one stack-owned webhook credential, no static transfer
   destinations, and the `transfer-destination-request` server message.
4. Send an authenticated synthetic prepare event. A wrong credential must return
   `401` without a DynamoDB write.
5. Check Vapi/API throttling before classifying `429` as authentication failure.

## Remediation

- Correct the Vapi private-key secret value and update the stack. Never put the
  value in CloudFormation parameters, command arguments, or terminal history.
- Resolve an ownership collision manually. Never rename or delete a same-named
  Vapi object unless its metadata proves this stack owns it.
- Let the provisioner reconcile an ambiguous create/update by deterministic
  ownership. Do not blindly repeat writes.
- Restore the exact stack-owned webhook credential association if an
  administrator edited the template assistant.
- For a production credential transition, create and verify a parallel
  deployment, move callers after a controlled call, then retire the old stack.

## Verify

Run create/update/no-op and test-owned delete/recreate checks. Prepare context,
request transfer, and confirm exactly one `X-Correlation-Id`. In optional mode,
the destination is `sip:<one-use-route>@<host>:5061;transport=tls` and actual TLS
must be observed independently; strict mode uses `sips:` and must negotiate
SRTP. Confirm no-op updates preserve owned Vapi IDs and disposable teardown
removes only the execution-owned objects.
