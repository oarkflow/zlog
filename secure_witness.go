package zlog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type WitnessReceipt struct {
	Version         string `json:"version"`
	WitnessID       string `json:"witness_id"`
	TreeID          string `json:"tree_id"`
	TreeSize        uint64 `json:"tree_size"`
	RootHash        string `json:"root_hash"`
	CheckpointHash  string `json:"checkpoint_hash"`
	PreviousReceipt string `json:"previous_receipt_hash,omitempty"`
	ObservedAt      string `json:"observed_at"`
	SignerKeyID     string `json:"signer_key_id"`
	Algorithm       string `json:"algorithm"`
	Signature       string `json:"signature"`
}

func (r WitnessReceipt) signingPayload() WitnessReceipt { r.Signature = ""; return r }
func (r WitnessReceipt) Hash() ([32]byte, error) {
	b, e := CanonicalJSON(r)
	if e != nil {
		return [32]byte{}, e
	}
	return domainHash("ZLOG-WITNESS-RECEIPT-HASH-V1", b), nil
}

type CheckpointWitness interface {
	Observe(context.Context, Checkpoint, SignatureVerifier) (WitnessReceipt, error)
	ID() string
}

// ConsistencyCheckpointWitness additionally verifies append-only consistency
// from its previously witnessed tree state before signing a newer checkpoint.
type ConsistencyCheckpointWitness interface {
	CheckpointWitness
	ObserveConsistency(context.Context, Checkpoint, *ConsistencyProof, SignatureVerifier) (WitnessReceipt, error)
}

type FileCheckpointWitness struct {
	mu       sync.Mutex
	id       string
	dir      string
	signer   CheckpointSigner
	verifier SignatureVerifier
	last     map[string]WitnessReceipt
}

func OpenFileCheckpointWitness(dir, id string, signer CheckpointSigner, verifier SignatureVerifier) (*FileCheckpointWitness, error) {
	if dir == "" || id == "" || signer == nil || verifier == nil {
		return nil, errors.New("zlog: witness dir, id, signer and verifier are required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	w := &FileCheckpointWitness{id: id, dir: dir, signer: signer, verifier: verifier, last: make(map[string]WitnessReceipt)}
	if err := w.load(); err != nil {
		return nil, err
	}
	return w, nil
}
func (w *FileCheckpointWitness) ID() string { return w.id }
func (w *FileCheckpointWitness) Observe(ctx context.Context, cp Checkpoint, sourceVerifier SignatureVerifier) (WitnessReceipt, error) {
	return w.observe(ctx, cp, nil, sourceVerifier, false)
}

func (w *FileCheckpointWitness) ObserveConsistency(ctx context.Context, cp Checkpoint, proof *ConsistencyProof, sourceVerifier SignatureVerifier) (WitnessReceipt, error) {
	return w.observe(ctx, cp, proof, sourceVerifier, true)
}

func (w *FileCheckpointWitness) observe(ctx context.Context, cp Checkpoint, proof *ConsistencyProof, sourceVerifier SignatureVerifier, requireConsistency bool) (WitnessReceipt, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if sourceVerifier == nil {
		sourceVerifier = w.verifier
	}
	payload, err := CanonicalJSON(cp.signingPayload())
	if err != nil {
		return WitnessReceipt{}, err
	}
	sig, err := decodeSignature(cp.Signature)
	if err != nil {
		return WitnessReceipt{}, err
	}
	if err = sourceVerifier.VerifySignature(ctx, cp.SignerKeyID, cp.SignatureAlgorithm, payload, sig); err != nil {
		return WitnessReceipt{}, fmt.Errorf("zlog: witness rejected checkpoint signature: %w", err)
	}
	if _, err = decodeHash32(cp.RootHash); err != nil {
		return WitnessReceipt{}, err
	}
	ch, err := cp.Hash()
	if err != nil {
		return WitnessReceipt{}, err
	}
	checkpointHash := hex.EncodeToString(ch[:])
	prev := w.last[cp.TreeID]
	if prev.TreeID != "" {
		if cp.TreeSize < prev.TreeSize {
			return WitnessReceipt{}, fmt.Errorf("zlog: witness rollback from %d to %d", prev.TreeSize, cp.TreeSize)
		}
		if cp.TreeSize == prev.TreeSize && cp.RootHash != prev.RootHash {
			return WitnessReceipt{}, ErrWitnessEquivocation
		}
		if cp.TreeSize == prev.TreeSize && cp.RootHash == prev.RootHash && prev.CheckpointHash == checkpointHash {
			return prev, nil
		}
		if cp.TreeSize > prev.TreeSize && requireConsistency {
			if proof == nil {
				return WitnessReceipt{}, errors.New("zlog: witness requires a consistency proof for tree growth")
			}
			if proof.TreeID != cp.TreeID || proof.FirstSize != prev.TreeSize || proof.SecondSize != cp.TreeSize || proof.FirstRoot != prev.RootHash || proof.SecondRoot != cp.RootHash {
				return WitnessReceipt{}, errors.New("zlog: consistency proof does not bind previous and current checkpoints")
			}
			if err = VerifyConsistencyProof(*proof); err != nil {
				return WitnessReceipt{}, fmt.Errorf("zlog: witness rejected consistency proof: %w", err)
			}
		}
	}
	r := WitnessReceipt{Version: "zlog.audit.witness.v1", WitnessID: w.id, TreeID: cp.TreeID, TreeSize: cp.TreeSize, RootHash: cp.RootHash, CheckpointHash: checkpointHash, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), SignerKeyID: w.signer.KeyID(), Algorithm: w.signer.Algorithm()}
	if prev.TreeID != "" {
		h, e := prev.Hash()
		if e != nil {
			return WitnessReceipt{}, e
		}
		r.PreviousReceipt = hex.EncodeToString(h[:])
	}
	b, err := CanonicalJSON(r.signingPayload())
	if err != nil {
		return WitnessReceipt{}, err
	}
	rsig, err := w.signer.Sign(ctx, b)
	if err != nil {
		return WitnessReceipt{}, err
	}
	r.Signature = signatureB64(rsig)
	line, err := json.Marshal(r)
	if err != nil {
		return WitnessReceipt{}, err
	}
	line = append(line, '\n')
	f, err := os.OpenFile(w.path(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return WitnessReceipt{}, err
	}
	_, we := f.Write(line)
	if we == nil {
		we = f.Sync()
	}
	ce := f.Close()
	if we != nil {
		return WitnessReceipt{}, we
	}
	if ce != nil {
		return WitnessReceipt{}, ce
	}
	w.last[cp.TreeID] = r
	return r, nil
}

// RegisterVerificationKey adds the witness's current signing key to a mutable
// registry. This allows stores that create their own registry to verify witness
// receipts on restart without exposing private key material.
func (w *FileCheckpointWitness) RegisterVerificationKey(reg *PublicKeyRegistry) error {
	if reg == nil {
		return errors.New("zlog: public key registry is required")
	}
	if hs, ok := w.signer.(*HMACCheckpointSigner); ok {
		return reg.RegisterHMAC(hs.KeyID(), hs.key)
	}
	b, err := w.signer.PublicKeyPEM()
	if err != nil {
		return err
	}
	return reg.RegisterPEM(w.signer.KeyID(), w.signer.Algorithm(), b)
}
func (w *FileCheckpointWitness) path() string {
	return filepath.Join(w.dir, "witness-"+sanitizeFilePart(w.id)+".jsonl")
}
func (w *FileCheckpointWitness) load() error {
	f, err := os.Open(w.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	states := make(map[string]WitnessReceipt)
	line := 0
	for sc.Scan() {
		line++
		var r WitnessReceipt
		if err = json.Unmarshal(sc.Bytes(), &r); err != nil {
			return fmt.Errorf("zlog: witness line %d: %w", line, err)
		}
		prev := states[r.TreeID]
		if err = VerifyWitnessReceipt(context.Background(), r, prev, w.verifier); err != nil {
			return fmt.Errorf("zlog: witness line %d: %w", line, err)
		}
		states[r.TreeID] = r
	}
	if err = sc.Err(); err != nil {
		return err
	}
	w.last = states
	return nil
}

func VerifyWitnessReceipt(ctx context.Context, r, prev WitnessReceipt, verifier SignatureVerifier) error {
	if r.Version != "zlog.audit.witness.v1" || r.WitnessID == "" || r.TreeID == "" {
		return errors.New("zlog: malformed witness receipt")
	}
	if _, err := decodeHash32(r.RootHash); err != nil {
		return err
	}
	if _, err := decodeHash32(r.CheckpointHash); err != nil {
		return err
	}
	expected := ""
	if prev.TreeID != "" {
		h, e := prev.Hash()
		if e != nil {
			return e
		}
		expected = hex.EncodeToString(h[:])
		if r.TreeID != prev.TreeID || r.TreeSize < prev.TreeSize {
			return errors.New("zlog: witness receipt rollback")
		}
		if r.TreeSize == prev.TreeSize && r.RootHash != prev.RootHash {
			return ErrWitnessEquivocation
		}
	}
	if r.PreviousReceipt != expected {
		return errors.New("zlog: witness receipt chain mismatch")
	}
	b, err := CanonicalJSON(r.signingPayload())
	if err != nil {
		return err
	}
	sig, err := decodeSignature(r.Signature)
	if err != nil {
		return err
	}
	return verifier.VerifySignature(ctx, r.SignerKeyID, r.Algorithm, b, sig)
}

func VerifyWitnessFile(ctx context.Context, path string, verifier SignatureVerifier) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	states := make(map[string]WitnessReceipt)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var n uint64
	for sc.Scan() {
		var r WitnessReceipt
		if err = json.Unmarshal(sc.Bytes(), &r); err != nil {
			return n, err
		}
		if err = VerifyWitnessReceipt(ctx, r, states[r.TreeID], verifier); err != nil {
			return n, err
		}
		states[r.TreeID] = r
		n++
	}
	return n, sc.Err()
}

func VerifyCheckpointWitnesses(ctx context.Context, cp Checkpoint, verifier SignatureVerifier, min int) (int, error) {
	valid := 0
	seen := make(map[string]struct{})
	ch, err := cp.Hash()
	if err != nil {
		return 0, err
	}
	for _, r := range cp.WitnessReceipts {
		if _, ok := seen[r.WitnessID]; ok {
			return valid, errors.New("zlog: duplicate witness receipt")
		}
		seen[r.WitnessID] = struct{}{}
		rh, err := decodeHash32(r.CheckpointHash)
		if err != nil {
			return valid, err
		}
		if subtle.ConstantTimeCompare(rh[:], ch[:]) != 1 || r.TreeID != cp.TreeID || r.TreeSize != cp.TreeSize || r.RootHash != cp.RootHash {
			return valid, errors.New("zlog: witness receipt does not bind checkpoint")
		}
		b, err := CanonicalJSON(r.signingPayload())
		if err != nil {
			return valid, err
		}
		sig, err := decodeSignature(r.Signature)
		if err != nil {
			return valid, err
		}
		if err = verifier.VerifySignature(ctx, r.SignerKeyID, r.Algorithm, b, sig); err != nil {
			return valid, err
		}
		valid++
	}
	if valid < min {
		return valid, fmt.Errorf("zlog: only %d valid witness receipts, need %d", valid, min)
	}
	return valid, nil
}

func sanitizeFilePart(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}
