package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/oarkflow/zlog"
)

func main() {
	var dir string
	var serve bool
	var addr string
	flag.StringVar(&dir, "dir", ".zlog-secure-example", "persistent audit directory")
	flag.BoolVar(&serve, "serve", false, "serve the authenticated audit API")
	flag.StringVar(&addr, "addr", "127.0.0.1:8089", "HTTP address used with -serve")
	flag.Parse()

	ctx := context.Background()
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatal(err)
	}
	dataKey := mustDataKey(filepath.Join(dir, "data.key"))
	auditSigner := mustSigner(filepath.Join(dir, "audit-signer.pem"), "audit-signing-1")
	witnessSigner := mustSigner(filepath.Join(dir, "witness-signer.pem"), "witness-signing-1")
	forensicSigner := mustSigner(filepath.Join(dir, "forensic-signer.pem"), "forensic-signing-1")

	registry := zlog.NewPublicKeyRegistry()
	register(registry, auditSigner)
	register(registry, witnessSigner)
	register(registry, forensicSigner)
	witness, err := zlog.OpenFileCheckpointWitness(filepath.Join(dir, "witness"), "security-office", witnessSigner, registry)
	must(err)
	store, err := zlog.OpenSecureAuditStore(zlog.SecureAuditOptions{Dir: filepath.Join(dir, "store"), StreamID: "security-audit", TenantID: "tenant-example", EncryptionKey: dataKey, EncryptionKeyID: "data-key-1", Signer: auditSigner, Verifier: registry, CheckpointEvery: 2, SegmentMaxRecords: 1000, SegmentMaxBytes: 16 << 20, MaxRecordBytes: 1 << 20, SyncPolicy: zlog.SyncAlways, RecoverPartial: true, Witnesses: []zlog.CheckpointWitness{witness}, WitnessQuorum: 1})
	must(err)
	defer store.Close()

	catalog := zlog.NewEventCatalog(zlog.EventDefinition{Name: "user.role.changed", Version: "1", DefaultKind: "audit", Retention: "7-years", Classification: "confidential", Required: []string{"actor.id", "event.action", "resource.id", "event.outcome"}, Rules: []zlog.AttributeRule{{Name: "actor.id", Type: "string", Required: true}, {Name: "event.action", Type: "string", Required: true, Allowed: []string{"role.assign", "role.remove"}}, {Name: "resource.id", Type: "string", Required: true}, {Name: "event.outcome", Type: "string", Required: true, Allowed: []string{"success", "failure"}}}, Compliance: []string{"SOC2", "ISO27001"}})
	manifest, err := catalog.Sign(ctx, auditSigner)
	must(err)
	fmt.Printf("catalog_signature=%s definitions=%d\n", manifest.SignerKeyID, len(manifest.Definitions))

	receipt, err := zlog.NewAuditEvent(store, "user.role.changed").Catalog(catalog).Actor("admin-42").Action("role.assign").Resource("user", "user-100").Outcome("success").Reason("approved access request AR-921").Correlation("req-100", "corr-100", "trace-100", "span-100").Attr("role", "billing-reviewer").Attr("approved_by", "security-manager").Commit(ctx)
	must(err)
	fmt.Printf("record_id=%s sequence=%d chain=%s\n", receipt.RecordID, receipt.Sequence, receipt.ChainHash)

	proof, err := store.InclusionProof(ctx, receipt.RecordID)
	must(err)
	must(zlog.VerifyInclusionProof(proof))
	fmt.Printf("proof_verified=true tree_size=%d path_nodes=%d\n", proof.TreeSize, len(proof.AuditPath))
	report, err := store.Verify(ctx, zlog.VerifyOptions{DecryptContent: true, Strict: true})
	must(err)
	printJSON("verification", report)

	holdLedger, err := zlog.OpenLegalHoldLedger(filepath.Join(dir, "legal-holds.jsonl"), auditSigner, registry)
	must(err)
	hold, err := holdLedger.Place(ctx, zlog.ActiveLegalHold{StreamID: "security-audit", RecordIDs: []string{receipt.RecordID}, CaseID: "CASE-2026-001", Reason: "preserve evidence during investigation", ActorID: "auditor-7"})
	must(err)
	fmt.Printf("legal_hold=%s active=true\n", hold.HoldID)

	var bundle bytes.Buffer
	_, err = zlog.ExportForensicBundle(ctx, store, &bundle, zlog.ForensicExportOptions{RecordIDs: []string{receipt.RecordID}, CaseID: "CASE-2026-001", Reason: "incident evidence package", ExporterID: "auditor-7", Signer: forensicSigner, ExtraKeys: []zlog.ForensicKey{publicKey(witnessSigner)}})
	must(err)
	bundlePath := filepath.Join(dir, "forensic.tar.gz")
	must(os.WriteFile(bundlePath, bundle.Bytes(), 0600))
	bundleReport, err := zlog.VerifyForensicBundle(ctx, bytes.NewReader(bundle.Bytes()), 64<<20)
	must(err)
	printJSON("forensic_verification", bundleReport)

	if !serve {
		fmt.Printf("bundle=%s\n", bundlePath)
		return
	}
	token := os.Getenv("ZLOG_API_TOKEN")
	if len(token) < 24 {
		token = randomToken()
		fmt.Printf("generated_api_token=%s\n", token)
	}
	handler, err := zlog.NewSecureAuditHandler(zlog.SecureAuditHTTPOptions{Store: store, ForensicSigner: forensicSigner, LegalHolds: holdLedger, Credentials: []zlog.SecureAPICredential{{ID: "example-admin", Secret: token, Permissions: []string{"audit:write", "audit:read", "audit:verify", "audit:export", "legal_hold:read", "legal_hold:write"}}}, AllowedCIDRs: []string{"127.0.0.0/8", "::1/128"}, RequestsPerMinute: 600, AuditAdministrative: true})
	must(err)
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		fmt.Printf("audit_api=http://%s\n", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	must(srv.Shutdown(shutdown))
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
func mustDataKey(path string) []byte {
	if k, err := zlog.LoadAuditDataKey(path); err == nil {
		return k
	}
	k, err := zlog.GenerateAuditDataKey()
	must(err)
	must(zlog.SaveAuditDataKey(path, k))
	return k
}
func mustSigner(path, id string) zlog.CheckpointSigner {
	if s, err := zlog.LoadPrivateSigner(path, id); err == nil {
		return s
	}
	s, err := zlog.GenerateEd25519CheckpointSigner(id)
	must(err)
	must(zlog.SavePrivateSigner(path, s, 0600))
	return s
}
func register(r *zlog.PublicKeyRegistry, s zlog.CheckpointSigner) {
	p, err := s.PublicKeyPEM()
	must(err)
	must(r.RegisterPEM(s.KeyID(), s.Algorithm(), p))
}
func publicKey(s zlog.CheckpointSigner) zlog.ForensicKey {
	p, err := s.PublicKeyPEM()
	must(err)
	return zlog.ForensicKey{KeyID: s.KeyID(), Algorithm: s.Algorithm(), PublicPEM: string(p)}
}
func printJSON(label string, v any) { b, _ := json.Marshal(v); fmt.Printf("%s=%s\n", label, b) }
func randomToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	must(err)
	return hex.EncodeToString(b)
}
