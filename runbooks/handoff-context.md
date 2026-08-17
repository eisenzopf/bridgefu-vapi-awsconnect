# Handoff API, DynamoDB, and context availability

## Impact

Prepare or transfer fails, DynamoDB throttles, or an agent receives a call with
generic context-unavailable fields. Voice routing intentionally fails open when
lookup context is absent.

## Safe checks

1. Use the dashboard to identify prepare, transfer, lookup, API, or DynamoDB as
   the failing hop.
2. Inspect bounded Lambda categories/duration, API status, DynamoDB throttles,
   TTL/PITR state, and transfer Lambda VPC networking.
3. Reproduce with synthetic values only.
4. For one known synthetic call, derive the correlation locally and use
   `GetItem`; never scan the table or paste the key into a ticket.
5. Check record state, expiry, content hash, deployment ownership, and Vapi call
   fingerprint without logging their values.
6. Verify private DNS resolves `control.<sip-hostname>` to the gateway private
   IP and port 443 is reachable only from the transfer Lambda security group.

## Remediation

- `401`: restore the stack-owned Vapi webhook credential association.
- `409`: do not alter fields and replay under the same Vapi call identity; start
  a new synthetic call.
- `410`: prepare a new handoff.
- `429`: stop abusive retries, then adjust reviewed limits only if measured
  legitimate demand requires it.
- Reservation failure: restore Bridgefu readiness, private DNS/TLS, the fixed
  route, and exact control credential. Never expose the control route publicly.
- DynamoDB failure: restore availability, PITR/TTL, and exact Lambda role
  permissions. Do not disable encryption or broaden table access.

## Verify

Prove idempotent prepare, conflicting replay rejection, one reservation, exactly
one correlation header, bounded lookup fields, missing/expired fail-open
behavior, and no correlation or customer values in retained logs.
