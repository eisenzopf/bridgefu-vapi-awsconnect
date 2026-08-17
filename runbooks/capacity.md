# Capacity, throttling, and CPU

## Impact

New calls are rejected or slow, Lambda or DynamoDB throttles, CPU remains high,
or media queues drop packets. Protect established audio before changing limits.

## Safe checks

1. Compare active sessions with `MaxConcurrentCalls`, CPU, memory, network,
   media queue drops, transcode errors, Lambda concurrency, API throttles, and
   DynamoDB throttles.
2. Exclude AMI compilation/build activity from runtime sizing evidence.
3. Separate legitimate call concurrency from retry storms or unauthenticated
   traffic.
4. Check codec/transcode mix, recent AMI/config changes, and pending cleanup.
5. Treat 60 percent CPU and memory during active-call qualification as the
   release headroom ceiling, not an alarm threshold for ordinary operation.

## Remediation

- Stop abusive or retrying traffic at the authenticated source while retaining
  CIDR admission and rate limits.
- Drain the single gateway and deploy a reviewed larger allowed ARM64 instance
  type when measured runtime utilization is the constraint. Do not resize during
  active calls without accepting call loss.
- Raise API or Lambda limits only with corresponding runtime capacity and budget.
- Do not place an unqualified generic load balancer in front of stateful SIP/RTP
  and call it high availability.

## Verify

Repeat the approved call shape. Require zero media queue drops and transcode
errors, no cleanup backlog, acceptable setup/audio latency, and CPU and memory
below the release ceiling throughout the active-call window. Record only the
duration, concurrency, codec mix, instance type, and release revision.
