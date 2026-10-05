# PENYLI v10.0 MVP — Launch Checklist

## Product flow
PAYMENT → CREATION → GENE → REALM → STATE → HISTORY → REPLAY →
GENOME → IDENTITY → SIGNATURE → PUBLIC VERIFICATION → CERTIFICATE

## Launch gates
1. Deploy behind HTTPS.
2. Configure Stripe LIVE secret and signed webhook.
3. Protect the Ed25519 private key outside source control.
4. Configure production DB and backups.
5. Set exact production Origin allowlist.
6. Run a real $1 payment in production.
7. Confirm webhook creates exactly one Creation.
8. Confirm Creation applies exactly once to Realm.
9. Confirm State/Genome/Identity/Signature/Certificate update.
10. Verify the public signature.
11. Export and archive the Realm Certificate.
12. Monitor `/health` and `/api/mvp/readiness`.

## Definition of MVP
A real participant can pay $1, receive a server-authoritative Creation,
cause a verified Realm mutation, and obtain cryptographic evidence of the
result.

No visual redesign is required for MVP.
