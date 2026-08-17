# Cleanup backlog or orphan Amazon Connect contact

## Impact

An Amazon Connect contact, Bridgefu call, one-use route reservation, or capacity
slot remains after hangup. Continued backlog can consume capacity and incur
unexpected Connect charges.

## Safe checks

1. Stop new admissions if the backlog is increasing; keep established calls
   running where possible.
2. Read the bounded cleanup-pending, age, retry, active-call, and readiness
   metrics in CloudWatch.
3. For one restricted operational contact reference, compare Bridgefu state with
   Connect `DescribeContact`. Never enumerate and bulk-stop unrelated contacts.
4. Verify the runtime's exact `StopContact` permission and AWS service health.
5. Confirm whether the source or destination already ended before intervening.

## Remediation

- Restore the failed dependency and allow Bridgefu's durable reconciliation to
  retry first.
- Drain before restarting or replacing the gateway so durable cleanup effects
  can be replayed.
- Manually stop a contact only after proving Bridgefu created it, it remains
  active, and automatic reconciliation cannot complete. Record approval and the
  exact target in restricted evidence.
- Never delete the Bridgefu data volume or state database to clear an alarm.

## Verify

Require active calls, pending cleanups, reservations, and consumed capacity to
return to zero. Repeat controlled Vapi-led and agent-led hangups before closing
an implementation-related incident.
