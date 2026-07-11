# zlog secure audit subsystem

## Purpose

The ordinary logger is optimized for diagnostics and observability. `SecureAuditStore` is the authoritative path for events whose integrity, ordering, confidentiality, retention, and evidentiary provenance matter.

The subsystem is stdlib-only and stores one ordered stream per store directory. Separate streams should use separate directories and, preferably, separate data-encryption keys.

## Security model

Each append performs the following operations in order:

1. Validate the record identity, event name, field sizes, nesting depth, and supported values.
2. Assign a cryptographically random record ID and the next stream sequence.
3. Serialize the complete record using deterministic canonical JSON.
4. Hash the canonical plaintext with SHA-256.
5. Compute a domain-separated chain hash over the stream ID, sequence, previous chain hash, and content hash.
6. Compute a domain-separated Merkle leaf binding the record ID, stream ID, sequence, and chain hash.
7. Encrypt the canonical record with AES-256-GCM. The envelope metadata is authenticated as AEAD additional data.
8. Append and, under `SyncAlways`, fsync the record before acknowledging it.
9. Add the leaf to the append-only Merkle tree.
10. At the configured interval, sign a global checkpoint and collect the required witness quorum.

Segments are length-bounded append-only JSONL containers with a header, encrypted record envelopes, and a signed trailer. Every trailer binds the canonical header hash, its segment root, and the preceding segment root. Checkpoints sign the global tree size/root and the previous checkpoint hash.

## Cryptography

| Purpose | Implemented profiles |
|---|---|
| Record encryption | AES-256-GCM |
| Content digest | SHA-256 |
| Chain and Merkle domain hashes | SHA-256 |
| Public checkpoint signatures | Ed25519, ECDSA P-256/SHA-256, RSA-PSS/SHA-256 |
| Symmetric checkpoint profile | HMAC-SHA-256 |
| Passphrase derivation | PBKDF2-HMAC-SHA-256, minimum 100,000 iterations, default 600,000 |

Public-key signatures are recommended for independently verifiable checkpoints and forensic exports. HMAC is appropriate only where every verifier is trusted with signing capability.

## Canonicalization

`CanonicalJSON` sorts object keys, emits deterministic primitive representations, normalizes `time.Time` to UTC RFC3339 nanoseconds, and rejects:

- Duplicate JSON keys
- Trailing JSON values or malformed trailing input
- NaN and infinity
- Non-string map keys
- Cyclic values
- Unsupported Go values
- More than 64 canonicalization levels

Audit records additionally enforce bounded attribute depth, count, string size, byte size, and total canonical record size.

## Checkpoint and witness verification

`InclusionProof` proves that a record leaf belongs to a specific signed tree root. `ConsistencyProof` proves that a later tree is an append-only extension of an earlier tree.

`FileCheckpointWitness` verifies the source checkpoint and the Merkle consistency proof from its previously witnessed tree before signing a growing tree. Its append-only receipt log rejects:

- Tree-size rollback
- Same-size checkpoints with different roots
- Broken receipt chains
- Duplicate or malformed signatures
- Unknown signer keys

Use witnesses in a separate account, host, region, or security domain from the primary collector.

## Key management

Use independent keys for:

- Record encryption
- Audit checkpoint signing
- Witness signing
- Forensic export signing
- Archive receipt signing

`GenerateAuditDataKey`, `SaveAuditDataKey`, `GenerateEd25519CheckpointSigner`, `SavePrivateSigner`, and `LoadPrivateSigner` provide strict local key files. Generated CLI configuration keeps a separate public-key path, so read-only verification does not need access to the private signing key. Production deployments should implement `CheckpointSigner` using an HSM or cloud KMS and keep historical public keys registered in `PublicKeyRegistry`.

Never delete historical public keys while records or checkpoints signed by them remain retained.

## Crash and corruption behavior

Opening a store scans every segment and verifies encryption, content hashes, sequence continuity, chain continuity, leaf hashes, segment roots, trailer signatures, checkpoint roots, checkpoint signatures, and witness receipts.

When `RecoverPartial` is enabled, only an incomplete final line in the final active segment is truncated. Complete malformed, unauthenticated, reordered, duplicated, or inconsistent records cause opening to fail. Read-only verification never repairs or modifies data.

## Legal holds

`LegalHoldLedger` stores hold placement and release as a separately sequenced, hash-linked, signed append-only log. A hold may cover an entire stream or selected record IDs. `IsHeld` can be used by retention and archival workflows before any destructive action.

## Forensic bundles

`ExportForensicBundle` creates a deterministic `tar.gz` containing:

- A signed manifest
- The signed global checkpoint
- Required public keys
- Each selected canonical record
- Its original encrypted envelope
- Its Merkle inclusion proof
- A SHA-256 manifest entry for every evidence file

`VerifyForensicBundle` rejects duplicate archive names, path traversal, unmanifested content, oversized entries, changed records, invalid envelope hashes, invalid leaf binding, invalid inclusion proofs, invalid checkpoints, and invalid manifest signatures.

## HTTP API

`SecureAuditHandler` exposes:

- `POST /v1/audit`
- `POST /v1/query`
- `GET /v1/records/{record_id}`
- `GET /v1/proofs/{record_id}`
- `GET /v1/checkpoints/latest`
- `GET /v1/verify`
- `GET /v1/stats`
- `POST /v1/forensic/export`
- `GET|POST /v1/legal-holds`
- `POST /v1/legal-holds/{hold_id}/release`

Permissions are independent: `audit:write`, `audit:read`, `audit:verify`, `audit:export`, `legal_hold:read`, and `legal_hold:write`.

The handler enforces bounded JSON, unknown-field rejection, bearer credentials, CIDR policies, per-principal/source rate limits, no-store responses, anti-framing headers, and optional TLS presence. `NewSecureHTTPServer` configures TLS 1.3 and optional mandatory client-certificate verification.

## Write-once archival

`LocalWriteOnceArchive` uses create-only object names, atomic writes, fsync, read-only permissions, SHA-256 verification, and signed receipts. It can safely recover the narrow crash window where the immutable object exists but its receipt was not completed, provided the caller supplies byte-identical intended content. It protects against accidental overwrite but is not a substitute for provider-enforced Object Lock or hardware WORM storage. `ArchiveSealedSegments` archives only segments with valid trailer placement.

## Guarantees and limitations

The subsystem can demonstrate that retained records are ordered, encrypted, hash-bound, included in signed checkpoints, and unchanged relative to those checkpoints and witnesses.

It cannot prove that the originating application told the truth, that every required event was emitted, or that data was correct before logging. A compromised application may still submit false records. A deployment also loses independent-verification value if the same actor controls the collector, all signing keys, all witnesses, and all retained copies.

Use the wording **tamper-evident and cryptographically verifiable**, not “tamper-proof.”

## Validation commands

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/zlog
go run ./examples/secure_audit -dir /tmp/zlog-secure-example
```
