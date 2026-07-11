package zlog

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

const ForensicBundleVersion = "zlog.forensic.bundle.v1"

type ForensicKey struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicPEM string `json:"public_pem"`
}

type ForensicEntry struct {
	RecordID string `json:"record_id"`
	Sequence uint64 `json:"sequence"`
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
}

type ForensicManifest struct {
	Version            string          `json:"version"`
	ExportID           string          `json:"export_id"`
	CreatedAt          string          `json:"created_at"`
	CaseID             string          `json:"case_id,omitempty"`
	Reason             string          `json:"reason"`
	ExporterID         string          `json:"exporter_id"`
	StreamID           string          `json:"stream_id"`
	Checkpoint         Checkpoint      `json:"checkpoint"`
	Entries            []ForensicEntry `json:"entries"`
	Keys               []ForensicKey   `json:"keys"`
	SignerKeyID        string          `json:"signer_key_id"`
	SignatureAlgorithm string          `json:"signature_algorithm"`
	Signature          string          `json:"signature"`
}

func (m ForensicManifest) signingPayload() ForensicManifest { m.Signature = ""; return m }

type ForensicEvidence struct {
	Version  string         `json:"version"`
	Record   AuditRecord    `json:"record"`
	Envelope AuditEnvelope  `json:"envelope"`
	Proof    InclusionProof `json:"proof"`
}

type ForensicExportOptions struct {
	RecordIDs  []string
	CaseID     string
	Reason     string
	ExporterID string
	Signer     CheckpointSigner
	ExtraKeys  []ForensicKey
}

type ForensicVerifyReport struct {
	Valid              bool          `json:"valid"`
	ExportID           string        `json:"export_id,omitempty"`
	Records            uint64        `json:"records"`
	CheckpointVerified bool          `json:"checkpoint_verified"`
	ManifestVerified   bool          `json:"manifest_verified"`
	Issues             []VerifyIssue `json:"issues,omitempty"`
}

func ExportForensicBundle(ctx context.Context, store *SecureAuditStore, w io.Writer, opts ForensicExportOptions) (ForensicManifest, error) {
	if store == nil || w == nil || opts.Signer == nil {
		return ForensicManifest{}, errors.New("zlog: forensic store, writer and signer are required")
	}
	if opts.Reason == "" || opts.ExporterID == "" {
		return ForensicManifest{}, errors.New("zlog: forensic reason and exporter id are required")
	}
	ids := uniqueSorted(opts.RecordIDs)
	if len(ids) == 0 {
		return ForensicManifest{}, errors.New("zlog: forensic export requires at least one record id")
	}
	cp, err := store.LatestCheckpoint(ctx)
	if err != nil {
		return ForensicManifest{}, err
	}
	exportID, err := newSecureID()
	if err != nil {
		return ForensicManifest{}, err
	}
	type evidenceFile struct {
		name  string
		data  []byte
		entry ForensicEntry
	}
	files := make([]evidenceFile, 0, len(ids))
	for _, id := range ids {
		rec, env, err := store.Get(ctx, id)
		if err != nil {
			return ForensicManifest{}, err
		}
		proof, err := store.InclusionProof(ctx, id)
		if err != nil {
			return ForensicManifest{}, err
		}
		ev := ForensicEvidence{Version: "zlog.forensic.evidence.v1", Record: rec, Envelope: env, Proof: proof}
		data, err := CanonicalJSON(ev)
		if err != nil {
			return ForensicManifest{}, err
		}
		data = append(data, '\n')
		sum := sha256.Sum256(data)
		name := fmt.Sprintf("records/%020d-%s.json", rec.Sequence, sanitizeFilePart(id))
		files = append(files, evidenceFile{name: name, data: data, entry: ForensicEntry{RecordID: id, Sequence: rec.Sequence, Path: name, SHA256: hex.EncodeToString(sum[:])}})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].entry.Sequence < files[j].entry.Sequence })
	keys := append([]ForensicKey(nil), opts.ExtraKeys...)
	addSignerKey := func(s CheckpointSigner) error {
		pemData, e := s.PublicKeyPEM()
		if e != nil {
			return e
		}
		for _, k := range keys {
			if k.KeyID == s.KeyID() {
				return nil
			}
		}
		keys = append(keys, ForensicKey{KeyID: s.KeyID(), Algorithm: s.Algorithm(), PublicPEM: string(pemData)})
		return nil
	}
	if err = addSignerKey(store.opts.Signer); err != nil {
		return ForensicManifest{}, fmt.Errorf("zlog: checkpoint key cannot be embedded: %w", err)
	}
	if err = addSignerKey(opts.Signer); err != nil {
		return ForensicManifest{}, fmt.Errorf("zlog: export key cannot be embedded: %w", err)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
	manifest := ForensicManifest{Version: ForensicBundleVersion, ExportID: exportID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), CaseID: opts.CaseID, Reason: opts.Reason, ExporterID: opts.ExporterID, StreamID: cp.TreeID, Checkpoint: cp, Keys: keys, SignerKeyID: opts.Signer.KeyID(), SignatureAlgorithm: opts.Signer.Algorithm()}
	for _, f := range files {
		manifest.Entries = append(manifest.Entries, f.entry)
	}
	payload, err := CanonicalJSON(manifest.signingPayload())
	if err != nil {
		return ForensicManifest{}, err
	}
	sig, err := opts.Signer.Sign(ctx, payload)
	if err != nil {
		return ForensicManifest{}, err
	}
	manifest.Signature = signatureB64(sig)
	manifestData, err := CanonicalJSON(manifest)
	if err != nil {
		return ForensicManifest{}, err
	}
	manifestData = append(manifestData, '\n')
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	write := func(name string, data []byte) error {
		h := &tar.Header{Name: name, Mode: 0600, Size: int64(len(data)), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	if err = write("manifest.json", manifestData); err == nil {
		for _, f := range files {
			if err = write(f.name, f.data); err != nil {
				break
			}
		}
	}
	if closeErr := tw.Close(); err == nil {
		err = closeErr
	}
	if closeErr := gz.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return ForensicManifest{}, err
	}
	return manifest, nil
}

func VerifyForensicBundle(ctx context.Context, r io.Reader, maxBytes int64) (ForensicVerifyReport, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 30
	}
	gz, err := gzip.NewReader(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return ForensicVerifyReport{Valid: false}, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := make(map[string][]byte)
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ForensicVerifyReport{Valid: false}, err
		}
		if h.Typeflag != tar.TypeReg {
			return ForensicVerifyReport{Valid: false}, errors.New("zlog: forensic bundle contains non-regular entry")
		}
		clean := path.Clean(h.Name)
		if clean != h.Name || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return ForensicVerifyReport{Valid: false}, errors.New("zlog: unsafe forensic archive path")
		}
		if _, ok := files[clean]; ok {
			return ForensicVerifyReport{Valid: false}, fmt.Errorf("zlog: duplicate forensic entry %q", clean)
		}
		if h.Size < 0 || h.Size > 64<<20 {
			return ForensicVerifyReport{Valid: false}, errors.New("zlog: forensic entry too large")
		}
		total += h.Size
		if total > maxBytes {
			return ForensicVerifyReport{Valid: false}, errors.New("zlog: forensic bundle exceeds limit")
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(b)) != h.Size {
			return ForensicVerifyReport{Valid: false}, errors.New("zlog: truncated forensic entry")
		}
		files[clean] = b
	}
	manifestData, ok := files["manifest.json"]
	if !ok {
		return ForensicVerifyReport{Valid: false}, errors.New("zlog: forensic manifest missing")
	}
	var m ForensicManifest
	if err := strictUnmarshal(manifestData, &m); err != nil {
		return ForensicVerifyReport{Valid: false}, err
	}
	rep := ForensicVerifyReport{Valid: true, ExportID: m.ExportID}
	if m.Version != ForensicBundleVersion || m.ExportID == "" || m.StreamID == "" {
		rep.issue("manifest", "invalid forensic manifest")
	}
	reg := NewPublicKeyRegistry()
	for _, k := range m.Keys {
		if err := reg.RegisterPEM(k.KeyID, k.Algorithm, []byte(k.PublicPEM)); err != nil {
			rep.issue("key", err.Error())
		}
	}
	payload, err := CanonicalJSON(m.signingPayload())
	if err != nil {
		rep.issue("manifest", err.Error())
	} else if sig, e := decodeSignature(m.Signature); e != nil {
		rep.issue("manifest", e.Error())
	} else if e = reg.VerifySignature(ctx, m.SignerKeyID, m.SignatureAlgorithm, payload, sig); e != nil {
		rep.issue("manifest", e.Error())
	} else {
		rep.ManifestVerified = true
	}
	if err := VerifyCheckpoint(ctx, m.Checkpoint, reg); err != nil {
		rep.issue("checkpoint", err.Error())
	} else if m.Checkpoint.TreeID != m.StreamID {
		rep.issue("checkpoint", "checkpoint tree id mismatch")
	} else if len(m.Checkpoint.WitnessReceipts) > 0 {
		if _, err := VerifyCheckpointWitnesses(ctx, m.Checkpoint, reg, len(m.Checkpoint.WitnessReceipts)); err != nil {
			rep.issue("checkpoint_witness", err.Error())
		} else {
			rep.CheckpointVerified = true
		}
	} else {
		rep.CheckpointVerified = true
	}
	seen := make(map[string]struct{})
	seenPaths := make(map[string]struct{})
	for _, entry := range m.Entries {
		if _, ok := seen[entry.RecordID]; ok {
			rep.issue("duplicate_record", "duplicate record in manifest")
			continue
		}
		seen[entry.RecordID] = struct{}{}
		clean := path.Clean(entry.Path)
		if clean != entry.Path || !strings.HasPrefix(clean, "records/") || clean == "records/" || clean == "manifest.json" {
			rep.issue("evidence_path", entry.Path)
			continue
		}
		if _, ok := seenPaths[clean]; ok {
			rep.issue("duplicate_path", clean)
			continue
		}
		seenPaths[clean] = struct{}{}
		data, ok := files[entry.Path]
		if !ok {
			rep.issue("missing_evidence", entry.Path)
			continue
		}
		sum := sha256.Sum256(data)
		expected, e := decodeHash32(entry.SHA256)
		if e != nil || subtle.ConstantTimeCompare(sum[:], expected[:]) != 1 {
			rep.issue("evidence_hash", entry.RecordID)
			continue
		}
		var ev ForensicEvidence
		if e = strictUnmarshal(data, &ev); e != nil {
			rep.issue("evidence_json", e.Error())
			continue
		}
		if ev.Version != "zlog.forensic.evidence.v1" || ev.Record.RecordID != entry.RecordID || ev.Record.Sequence != entry.Sequence {
			rep.issue("evidence_identity", entry.RecordID)
			continue
		}
		if e = VerifyRecordAgainstEnvelope(ev.Record, ev.Envelope); e != nil {
			rep.issue("record", e.Error())
			continue
		}
		if e = verifyEnvelopeLeaf(ev.Envelope); e != nil {
			rep.issue("leaf", e.Error())
			continue
		}
		if ev.Proof.RootHash != m.Checkpoint.RootHash || ev.Proof.TreeSize != m.Checkpoint.TreeSize || ev.Proof.RecordID != entry.RecordID || ev.Proof.LeafHash != ev.Envelope.LeafHash {
			rep.issue("proof_binding", entry.RecordID)
			continue
		}
		if e = VerifyInclusionProof(ev.Proof); e != nil {
			rep.issue("proof", e.Error())
			continue
		}
		rep.Records++
	}
	if rep.Records != uint64(len(m.Entries)) {
		rep.Valid = false
	}
	if len(files) != len(m.Entries)+1 {
		rep.issue("unexpected_entry", "bundle contains unmanifested files")
	}
	return rep, nil
}
func verifyEnvelopeLeaf(env AuditEnvelope) error {
	chain, err := env.ChainHashBytes()
	if err != nil {
		return err
	}
	seqb := make([]byte, 8)
	binary.BigEndian.PutUint64(seqb, env.Sequence)
	leaf := domainHash("ZLOG-AUDIT-LEAF-V1", []byte(env.RecordID), []byte(env.StreamID), seqb, chain[:])
	stored, err := env.LeafHashBytes()
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(leaf[:], stored[:]) != 1 {
		return errors.New("zlog: envelope leaf hash mismatch")
	}
	return nil
}
func (r *ForensicVerifyReport) issue(code, msg string) {
	r.Valid = false
	r.Issues = append(r.Issues, VerifyIssue{Code: code, Message: msg})
}
