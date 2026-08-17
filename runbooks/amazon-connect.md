# Amazon Connect and Agent Workspace

## Impact

No agent receives the call, Bridgefu cannot start the Connect contact, the call
arrives without the guide, or the screen pop is blank while audio continues.

## Safe checks

1. Confirm the customer-supplied Connect instance and destination-flow ARNs are
   unchanged and in the stack region.
2. In CloudFormation, verify the Bridgefu-owned wrapper flow and agent guide are
   complete and that the lookup Lambda association exists.
3. Use the dashboard and bounded CloudWatch result events to distinguish a
   contact-start failure, context lookup failure, screen-pop failure, or audio
   failure. Do not enable payload logging.
4. Confirm the receiving agent is logged in, assigned to the expected routing
   profile/queue, and `Available`. The stack deliberately does not edit customer
   users, routing profiles, queues, or security profiles.
5. Test missing synthetic context. Voice routing must continue with safe generic
   values instead of disconnecting the caller.

## Remediation

- Restore the exact Connect/Lambda permissions through a reviewed CloudFormation
  change set; do not attach broad policies manually.
- Republish only Bridgefu-owned wrapper/guide resources if they drift. Never
  modify the customer destination flow as part of Bridgefu repair.
- Restore the lookup Lambda association through the stack and avoid duplicate
  manual associations.
- Correct agent availability and permissions through the customer's normal
  access-review process.
- If audio routes while the guide fails, preserve the call and repair the view
  separately.

## Verify

Place one controlled call. Confirm the Connect contact, configured screen-pop
fields in order, destination-flow transfer, agent connection, both audio
directions, and fail-open missing-context behavior. Keep contact identifiers only
in restricted evidence.
