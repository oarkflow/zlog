# Validation

The delivered source was validated from a clean working tree with:

```bash
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/zlog
go run ./examples/secure_audit -dir /tmp/zlog-secure-example-validation
git diff --check
```

The secure example completed record append, checkpoint creation, independent witness receipt, inclusion-proof verification, full store verification, signed legal hold creation, forensic bundle generation, and independent forensic bundle verification.

The CLI was exercised end to end for secure initialization, append, public-key-only verification, proof generation, checkpoint retrieval, forensic export and verification, and legal-hold placement/release/verification.
