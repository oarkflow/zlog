# Security policy and deployment requirements

## Reporting vulnerabilities

Report suspected vulnerabilities privately to the project maintainers. Include the affected version, configuration, reproducible input, expected security property, and observed behavior. Do not include production secrets or unredacted customer records.

## Required production controls

- Keep data-encryption, checkpoint, witness, forensic, and archive keys separate.
- Store private signing keys in an HSM or KMS where available.
- Place at least one witness and one retained copy in an independently administered security domain.
- Use `SyncAlways` for strict audit acknowledgement.
- Use TLS 1.3 and mTLS for non-local ingestion.
- Restrict API credentials to the minimum permission set and rotate them regularly.
- Use provider-enforced immutable storage for regulatory WORM requirements.
- Back up key registries and public verification keys separately from private keys.
- Test store, witness, forensic, and archive verification during disaster-recovery exercises.

## Non-goals

zlog does not certify regulatory compliance, establish that logged statements are true, or prevent a compromised application from omitting events before they reach the store.
