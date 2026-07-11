# Secure audit example

Run the complete persistent workflow:

```bash
go run ./examples/secure_audit -dir ./.example-audit
```

It creates persistent AES-256 data keys and independent Ed25519 audit, witness, and forensic-signing keys; appends a catalog-validated audit event; verifies a Merkle proof and the full store; places a signed legal hold; exports a signed forensic bundle; and independently verifies that bundle.

Start the authenticated local HTTP API:

```bash
ZLOG_API_TOKEN='replace-with-at-least-24-random-characters' \
  go run ./examples/secure_audit -dir ./.example-audit -serve
```

For an Internet-facing deployment, use `zlog.NewSecureHTTPServer` with TLS 1.3 and mTLS instead of plain local HTTP.
