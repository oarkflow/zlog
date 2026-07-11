package zlog

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testSecureOptions(t *testing.T, dir string) SecureAuditOptions {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	signer, err := GenerateEd25519CheckpointSigner("audit-signing-1")
	if err != nil {
		t.Fatal(err)
	}
	return SecureAuditOptions{Dir: dir, StreamID: "security", TenantID: "tenant-a", EncryptionKey: key, EncryptionKeyID: "data-1", Signer: signer, CheckpointEvery: 3, SegmentMaxRecords: 4, SyncPolicy: SyncAlways, RecoverPartial: true}
}

func TestCanonicalJSONStableAndStrict(t *testing.T) {
	a, err := CanonicalJSON(map[string]any{"b": 2, "a": 1, "nested": map[string]any{"z": true, "x": "ok"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalJSON(map[string]any{"nested": map[string]any{"x": "ok", "z": true}, "a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("canonical JSON differs:\n%s\n%s", a, b)
	}
	if _, err := CanonicalizeJSON([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("expected duplicate key rejection")
	}
	if _, err := CanonicalizeJSON([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("expected trailing value rejection")
	}
}

func TestSecureAuditStoreEndToEnd(t *testing.T) {
	dir := t.TempDir()
	opts := testSecureOptions(t, dir)
	reg := NewPublicKeyRegistry()
	pub, err := opts.Signer.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err = reg.RegisterPEM(opts.Signer.KeyID(), opts.Signer.Algorithm(), pub); err != nil {
		t.Fatal(err)
	}
	wSigner, err := GenerateEd25519CheckpointSigner("witness-1")
	if err != nil {
		t.Fatal(err)
	}
	wpub, _ := wSigner.PublicKeyPEM()
	if err = reg.RegisterPEM(wSigner.KeyID(), wSigner.Algorithm(), wpub); err != nil {
		t.Fatal(err)
	}
	w, err := OpenFileCheckpointWitness(filepath.Join(dir, "witness"), "independent-a", wSigner, reg)
	if err != nil {
		t.Fatal(err)
	}
	opts.Verifier = reg
	opts.Witnesses = []CheckpointWitness{w}
	opts.WitnessQuorum = 1
	store, err := OpenSecureAuditStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		r, err := store.Append(context.Background(), AuditRecord{Name: "user.role.changed", Action: "role.assign", Outcome: "success", ActorID: "admin", ResourceType: "user", ResourceID: "u1", Attributes: map[string]any{"index": i, "roles": []any{"coder", "qa"}}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.RecordID)
	}
	cp, err := store.LatestCheckpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cp.TreeSize != 10 {
		t.Fatalf("tree size=%d", cp.TreeSize)
	}
	proof, err := store.InclusionProof(context.Background(), ids[4])
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyInclusionProof(proof); err != nil {
		t.Fatal(err)
	}
	consistency, err := store.ConsistencyProof(context.Background(), 3, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyConsistencyProof(consistency); err != nil {
		t.Fatal(err)
	}
	rec, env, err := store.Get(context.Background(), ids[4])
	if err != nil {
		t.Fatal(err)
	}
	if rec.Sequence != 5 || env.Sequence != 5 {
		t.Fatalf("bad sequence %d/%d", rec.Sequence, env.Sequence)
	}
	if err = VerifyRecordAgainstEnvelope(rec, env); err != nil {
		t.Fatal(err)
	}
	report, err := store.Verify(context.Background(), VerifyOptions{DecryptContent: true, Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid {
		b, _ := json.Marshal(report)
		t.Fatalf("invalid report: %s", b)
	}
	if report.Segments < 3 {
		t.Fatalf("expected rotations, segments=%d", report.Segments)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenSecureAuditStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Stats().Sequence != 10 {
		t.Fatalf("recovered sequence=%d", reopened.Stats().Sequence)
	}
	r, err := reopened.Append(context.Background(), AuditRecord{Name: "login", Outcome: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Sequence != 11 {
		t.Fatalf("sequence after restart=%d", r.Sequence)
	}
}

func TestSecureAuditTamperDetected(t *testing.T) {
	dir := t.TempDir()
	opts := testSecureOptions(t, dir)
	opts.CheckpointEvery = 1
	opts.SegmentMaxRecords = 100
	s, err := OpenSecureAuditStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Append(context.Background(), AuditRecord{Name: "critical.change", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := segmentFiles(dir)
	if err != nil || len(files) == 0 {
		t.Fatal(err)
	}
	b, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	idx := bytes.Index(b, []byte(`"ciphertext":"`))
	if idx < 0 {
		t.Fatal("ciphertext not found")
	}
	idx += len(`"ciphertext":"`)
	if b[idx] == 'A' {
		b[idx] = 'B'
	} else {
		b[idx] = 'A'
	}
	if err = os.WriteFile(files[0], b, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenSecureAuditStore(opts); err == nil {
		t.Fatal("expected tamper detection")
	}
}

func TestPartialRecovery(t *testing.T) {
	dir := t.TempDir()
	opts := testSecureOptions(t, dir)
	opts.SegmentMaxRecords = 100
	s, err := OpenSecureAuditStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Append(context.Background(), AuditRecord{Name: "one"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Flush(); err != nil {
		t.Fatal(err)
	}
	path := s.segment.path
	if err = s.segment.file.Close(); err != nil {
		t.Fatal(err)
	}
	s.segment.file = nil
	s.closed = true
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"type":"record"`)
	_ = f.Close()
	r, err := OpenSecureAuditStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Stats().Sequence != 1 {
		t.Fatalf("sequence=%d", r.Stats().Sequence)
	}
}

func TestWitnessEquivocation(t *testing.T) {
	dir := t.TempDir()
	signer, err := GenerateEd25519CheckpointSigner("source")
	if err != nil {
		t.Fatal(err)
	}
	wsigner, err := GenerateEd25519CheckpointSigner("witness")
	if err != nil {
		t.Fatal(err)
	}
	reg := NewPublicKeyRegistry()
	p, _ := signer.PublicKeyPEM()
	_ = reg.RegisterPEM(signer.KeyID(), signer.Algorithm(), p)
	wp, _ := wsigner.PublicKeyPEM()
	_ = reg.RegisterPEM(wsigner.KeyID(), wsigner.Algorithm(), wp)
	w, err := OpenFileCheckpointWitness(dir, "w1", wsigner, reg)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(root string) Checkpoint {
		cp := Checkpoint{Version: SecureCheckpointVersion, TreeID: "t", TreeSize: 1, RootHash: root, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), SignerKeyID: signer.KeyID(), SignatureAlgorithm: signer.Algorithm()}
		b, _ := CanonicalJSON(cp.signingPayload())
		sig, _ := signer.Sign(context.Background(), b)
		cp.Signature = signatureB64(sig)
		return cp
	}
	r1 := [32]byte{1}
	if _, err = w.Observe(context.Background(), mk(hexString(r1[:])), reg); err != nil {
		t.Fatal(err)
	}
	r2 := [32]byte{2}
	if _, err = w.Observe(context.Background(), mk(hexString(r2[:])), reg); err == nil {
		t.Fatal("expected equivocation")
	}
}

func hexString(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = h[v>>4]
		out[i*2+1] = h[v&15]
	}
	return string(out)
}

func TestMerkleProofsExhaustive(t *testing.T) {
	for n := 1; n <= 64; n++ {
		tree := NewMerkleTree()
		leaves := make([][32]byte, n)
		for i := 0; i < n; i++ {
			leaves[i] = domainHash("test-leaf", []byte{byte(i)})
			tree.Append(leaves[i])
		}
		root := tree.Root()
		for i := 0; i < n; i++ {
			path, err := tree.Inclusion(uint64(i), uint64(n))
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			p := InclusionProof{TreeSize: uint64(n), LeafIndex: uint64(i), LeafHash: hexString(leaves[i][:]), RootHash: hexString(root[:]), AuditPath: hashesToStrings(path)}
			if err := VerifyInclusionProof(p); err != nil {
				t.Fatalf("inclusion n=%d i=%d: %v", n, i, err)
			}
		}
		for first := 1; first <= n; first++ {
			path, err := tree.Consistency(uint64(first), uint64(n))
			if err != nil {
				t.Fatalf("consistency path %d->%d: %v", first, n, err)
			}
			fr, _ := tree.RootAt(uint64(first))
			p := ConsistencyProof{FirstSize: uint64(first), SecondSize: uint64(n), FirstRoot: hexString(fr[:]), SecondRoot: hexString(root[:]), Path: hashesToStrings(path)}
			if err := VerifyConsistencyProof(p); err != nil {
				t.Fatalf("consistency %d->%d: %v path=%d", first, n, err, len(path))
			}
		}
	}
}

func TestForensicBundleSelfVerification(t *testing.T) {
	dir := t.TempDir()
	opts := testSecureOptions(t, dir)
	store, err := OpenSecureAuditStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < 5; i++ {
		r, err := store.Append(context.Background(), AuditRecord{Name: "evidence.event", Outcome: "success", Attributes: map[string]any{"i": i}})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.RecordID)
	}
	exportSigner, err := GenerateEd25519CheckpointSigner("forensic-export")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	manifest, err := ExportForensicBundle(context.Background(), store, &buf, ForensicExportOptions{RecordIDs: []string{ids[1], ids[3]}, CaseID: "CASE-1", Reason: "incident review", ExporterID: "auditor-1", Signer: exportSigner})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ExportID == "" {
		t.Fatal("missing export id")
	}
	rep, err := VerifyForensicBundle(context.Background(), bytes.NewReader(buf.Bytes()), 10<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Valid || rep.Records != 2 || !rep.ManifestVerified || !rep.CheckpointVerified {
		t.Fatalf("bad report: %+v", rep)
	}
	_ = store.Close()
}

func TestLegalHoldLedger(t *testing.T) {
	dir := t.TempDir()
	signer, err := GenerateEd25519CheckpointSigner("hold-signer")
	if err != nil {
		t.Fatal(err)
	}
	reg := NewPublicKeyRegistry()
	pub, _ := signer.PublicKeyPEM()
	if err = reg.RegisterPEM(signer.KeyID(), signer.Algorithm(), pub); err != nil {
		t.Fatal(err)
	}
	ledger, err := OpenLegalHoldLedger(filepath.Join(dir, "holds.jsonl"), signer, reg)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ledger.Place(context.Background(), ActiveLegalHold{StreamID: "security", RecordIDs: []string{"r2", "r1", "r1"}, CaseID: "case", Reason: "investigation", ActorID: "auditor"})
	if err != nil {
		t.Fatal(err)
	}
	held, holds := ledger.IsHeld("security", "r1")
	if !held || len(holds) != 1 {
		t.Fatal("record should be held")
	}
	if _, err = ledger.Release(context.Background(), entry.HoldID, "supervisor", "case closed"); err != nil {
		t.Fatal(err)
	}
	if held, _ = ledger.IsHeld("security", "r1"); held {
		t.Fatal("record should be released")
	}
	if n, err := ledger.Verify(context.Background()); err != nil || n != 2 {
		t.Fatalf("verify n=%d err=%v", n, err)
	}
}

func TestSecureAuditHTTP(t *testing.T) {
	dir := t.TempDir()
	opts := testSecureOptions(t, dir)
	store, err := OpenSecureAuditStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h, err := NewSecureAuditHandler(SecureAuditHTTPOptions{Store: store, Credentials: []SecureAPICredential{{ID: "service-a", Secret: "01234567890123456789012345678901", Permissions: []string{"audit:write", "audit:read", "audit:verify"}}}, AllowedCIDRs: []string{"127.0.0.0/8"}, RequestsPerMinute: 100})
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"name":"auth.login","outcome":"success","actor_id":"u1"}`)
	req := httptest.NewRequest(http.MethodPost, "http://zlog/v1/audit", body)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 201 {
		t.Fatalf("append status=%d body=%s", rr.Code, rr.Body.String())
	}
	var receipt AppendReceipt
	if err = json.Unmarshal(rr.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "http://zlog/v1/proofs/"+receipt.RecordID, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("proof status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "http://zlog/v1/stats", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("expected unauthorized, got %d", rr.Code)
	}
}

func TestEncryptedFileV2RawAndPassphrase(t *testing.T) {
	for _, tc := range []struct {
		name   string
		opts   EncryptedFileOptions
		secret []byte
	}{{name: "raw", opts: EncryptedFileOptions{Key: bytes.Repeat([]byte{7}, 32)}, secret: bytes.Repeat([]byte{7}, 32)}, {name: "passphrase", opts: EncryptedFileOptions{Passphrase: []byte("correct horse battery staple")}, secret: []byte("correct horse battery staple")}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "enc.log")
			tc.opts.Path = path
			tc.opts.SyncWrite = true
			s, err := NewEncryptedFileSink(tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.WriteRecord(Record{Time: time.Now(), Level: InfoLevel, Message: "secure", Attrs: [4]Attr{String("k", "v")}, AttrCount: 1}, nil); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err = DecryptEncryptedLogFile(f, &out, tc.secret); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
			if !bytes.Contains(out.Bytes(), []byte("secure")) {
				t.Fatalf("plaintext missing: %s", out.String())
			}
		})
	}
}

func TestWriteOnceArchive(t *testing.T) {
	dir := t.TempDir()
	opts := testSecureOptions(t, filepath.Join(dir, "store"))
	opts.SegmentMaxRecords = 1
	s, err := OpenSecureAuditStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Append(context.Background(), AuditRecord{Name: "archive.me"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Append(context.Background(), AuditRecord{Name: "archive.me.too"}); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reg := NewPublicKeyRegistry()
	pub, _ := opts.Signer.PublicKeyPEM()
	if err = reg.RegisterPEM(opts.Signer.KeyID(), opts.Signer.Algorithm(), pub); err != nil {
		t.Fatal(err)
	}
	archive, err := OpenLocalWriteOnceArchive(filepath.Join(dir, "archive"), opts.Signer, reg, 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	results, err := ArchiveSealedSegments(context.Background(), s, archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) < 2 {
		t.Fatalf("archived=%d", len(results))
	}
	for _, r := range results {
		if _, err = archive.Verify(context.Background(), r.ObjectName); err != nil {
			t.Fatal(err)
		}
	}
}

type rejectingWitness struct{}

func (rejectingWitness) ID() string { return "rejecting" }
func (rejectingWitness) Observe(context.Context, Checkpoint, SignatureVerifier) (WitnessReceipt, error) {
	return WitnessReceipt{}, errors.New("witness unavailable")
}

func TestAppendCommittedErrorPreventsBlindRetry(t *testing.T) {
	opts := testSecureOptions(t, t.TempDir())
	opts.CheckpointEvery = 1
	opts.Witnesses = []CheckpointWitness{rejectingWitness{}}
	opts.WitnessQuorum = 1
	store, err := OpenSecureAuditStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.Append(context.Background(), AuditRecord{Name: "critical.commit"})
	var committed *AppendCommittedError
	if !errors.As(err, &committed) {
		t.Fatalf("expected AppendCommittedError, got %v", err)
	}
	if receipt.RecordID == "" || committed.Receipt.RecordID != receipt.RecordID {
		t.Fatalf("missing committed receipt: %+v %+v", receipt, committed.Receipt)
	}
	if _, _, err = store.Get(context.Background(), receipt.RecordID); err != nil {
		t.Fatalf("durable record unavailable: %v", err)
	}
	store.opts.WitnessQuorum = 0
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyStoreDoesNotCreateSegment(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenSecureAuditStore(testSecureOptions(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := segmentFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("empty store created %d segments", len(files))
	}
}

func TestReadOnlyConfigUsesPublicKeyOnly(t *testing.T) {
	base := t.TempDir()
	key, err := GenerateAuditDataKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(base, "data.key")
	if err = SaveAuditDataKey(keyPath, key); err != nil {
		t.Fatal(err)
	}
	signer, err := GenerateEd25519CheckpointSigner("config-signer")
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(base, "private.pem")
	publicPath := filepath.Join(base, "public.pem")
	if err = SavePrivateSigner(privatePath, signer, 0600); err != nil {
		t.Fatal(err)
	}
	pub, _ := signer.PublicKeyPEM()
	if err = os.WriteFile(publicPath, pub, 0644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(base, "secure.json")
	cfg := SecureStoreConfig{Dir: "store", StreamID: "audit", DataKeyFile: "data.key", DataKeyID: "data-1", SignerPrivateKeyFile: "private.pem", SignerPublicKeyFile: "public.pem", SignerKeyID: signer.KeyID(), SignatureAlgorithm: signer.Algorithm(), CheckpointEvery: 1, SyncPolicy: SyncAlways, RecoverPartial: true}
	if err = SaveSecureStoreConfig(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSecureStoreConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := loaded.Open(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Append(context.Background(), AuditRecord{Name: "public.verify"}); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(privatePath); err != nil {
		t.Fatal(err)
	}
	reader, err := loaded.Open(true)
	if err != nil {
		t.Fatalf("read-only open required private key: %v", err)
	}
	defer reader.Close()
	report, err := reader.Verify(context.Background(), VerifyOptions{DecryptContent: true, Strict: true})
	if err != nil || !report.Valid {
		t.Fatalf("read-only verify failed: report=%+v err=%v", report, err)
	}
}

func TestSegmentHeaderTamperDetected(t *testing.T) {
	dir := t.TempDir()
	opts := testSecureOptions(t, dir)
	store, err := OpenSecureAuditStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Append(context.Background(), AuditRecord{Name: "header.bound"}); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	files, _ := segmentFiles(dir)
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(data, []byte("\n"))
	var disk segmentDiskLine
	if err = json.Unmarshal(lines[0], &disk); err != nil {
		t.Fatal(err)
	}
	disk.Header.CreatedAt = "2000-01-01T00:00:00Z"
	lines[0], err = json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(files[0], bytes.Join(lines, []byte("\n")), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenSecureAuditStore(opts); err == nil {
		t.Fatal("expected signed header tamper detection")
	}
}

func TestPublicKeyRegistryRejectsKeyIDReuse(t *testing.T) {
	a, _ := GenerateEd25519CheckpointSigner("same-id")
	b, _ := GenerateEd25519CheckpointSigner("same-id")
	ap, _ := a.PublicKeyPEM()
	bp, _ := b.PublicKeyPEM()
	reg := NewPublicKeyRegistry()
	if err := reg.RegisterPEM(a.KeyID(), a.Algorithm(), ap); err != nil {
		t.Fatal(err)
	}
	if err := reg.RegisterPEM(b.KeyID(), b.Algorithm(), bp); err == nil {
		t.Fatal("expected key id collision rejection")
	}
}

func TestEventCatalogRuleNormalizationAndRequiredString(t *testing.T) {
	catalog := NewEventCatalog()
	if err := catalog.RegisterChecked(EventDefinition{Name: "role.change", Rules: []AttributeRule{{Name: "actor", Required: true}}}); err != nil {
		t.Fatal(err)
	}
	def, ok := catalog.Get("role.change")
	if !ok || def.Rules[0].Type != "any" {
		t.Fatalf("rule default type not retained: %+v", def)
	}
	if err := catalog.RegisterChecked(EventDefinition{Name: "login", Rules: []AttributeRule{{Name: "username", Type: "string", Required: true}}}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Validate("login", []Attr{String("username", "   ")}); err == nil {
		t.Fatal("expected empty required string rejection")
	}
}

func TestCanonicalJSONRejectsInvalidUTF8(t *testing.T) {
	if _, err := CanonicalJSON(string([]byte{0xff, 0xfe})); err == nil {
		t.Fatal("expected invalid UTF-8 rejection")
	}
}

func TestWriteOnceArchiveRecoversMissingReceipt(t *testing.T) {
	dir := t.TempDir()
	signer, _ := GenerateEd25519CheckpointSigner("archive-recovery")
	reg := NewPublicKeyRegistry()
	pub, _ := signer.PublicKeyPEM()
	if err := reg.RegisterPEM(signer.KeyID(), signer.Algorithm(), pub); err != nil {
		t.Fatal(err)
	}
	archive, err := OpenLocalWriteOnceArchive(dir, signer, reg, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	name := "audit/segment.zseg"
	objectPath := filepath.Join(dir, "objects", filepath.FromSlash(name))
	if err = os.MkdirAll(filepath.Dir(objectPath), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("durable object before receipt")
	if err = os.WriteFile(objectPath, content, 0400); err != nil {
		t.Fatal(err)
	}
	receipt, err := archive.Put(context.Background(), name, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Size != int64(len(content)) {
		t.Fatalf("size=%d", receipt.Size)
	}
	if _, err = archive.Verify(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "receipts", filepath.FromSlash(name)+".json")); err != nil {
		t.Fatal(err)
	}
}
