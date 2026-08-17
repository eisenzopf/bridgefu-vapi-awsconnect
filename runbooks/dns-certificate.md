# DNS and certificate failure or rotation

## Impact

TLS SIP connections fail, the stack waits for ACM validation, or certificate
age is below the alarm threshold. Plain SIP is not a production workaround.

## Safe checks

1. Confirm the SIP A record resolves publicly to the stack Elastic IP.
2. Compare public `NS` answers with the Route53 hosted-zone delegation.
3. Inspect ACM status and every DNS validation CNAME.
4. Through SSM, inspect `bridgefu-cert-refresh.service`, its timer, certificate
   `notAfter`, SANs, key/certificate match, and file modes.
5. Use `openssl s_client` with SNI against TCP 5061 and verify the chain and
   hostname. Never print the private key or export passphrase.
6. Check `CertificateDaysToExpiry` and active-call metrics.

## Remediation

- Fix delegation or validation records at the authoritative parent and wait for
  public propagation. Do not repeatedly replace the ACM certificate.
- Restore the runtime role's exact `acm:ExportCertificate` and passphrase-secret
  access through CloudFormation if drift removed them.
- Run the refresh unit once. It validates SANs, expiry, and key match before an
  atomic HAProxy reload.
- Certificate activation restarts Bridgefu only after the active-call count is
  zero. Drain first and use a maintenance window if calls never reach zero.
- If issuance cannot complete, preserve the last known-good deployment. Never
  place private key material in user data, S3, logs, or tickets.

## Verify

Confirm ACM is `ISSUED`, refresh/reload timers are active, SNI validation
succeeds, certificate-expiry metrics are healthy, and a controlled transfer
proves actual TLS. Strict mode must additionally prove `RTP/SAVP` with
SDES-SRTP; optional mode may accurately report `RTP/AVP` without calling it SRTP.
