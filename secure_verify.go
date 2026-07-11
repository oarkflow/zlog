package zlog

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

func (s *SecureAuditStore) Verify(ctx context.Context, opts VerifyOptions) (VerifyReport, error) {
	select {
	case <-ctx.Done():
		return VerifyReport{}, ctx.Err()
	default:
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rep := VerifyReport{Valid: true, Records: s.tree.Size(), LastSequence: s.seq, ContentVerified: true, CheckpointVerified: true}
	if s.prevHash != ([32]byte{}) {
		rep.LastChainHash = hex.EncodeToString(s.prevHash[:])
	}
	root := s.tree.Root()
	rep.MerkleRoot = hex.EncodeToString(root[:])
	files, err := segmentFiles(s.opts.Dir)
	if err != nil {
		return rep, err
	}
	rep.Segments = uint64(len(files))
	rep.Checkpoints = uint64(len(s.checkpoints))
	var prev [32]byte
	for i, cp := range s.checkpoints {
		if err := s.verifyCheckpoint(ctx, cp, prev); err != nil {
			rep.addIssue("checkpoint_signature", fmt.Sprintf("checkpoint %d: %v", i, err), 0, 0, "")
			rep.CheckpointVerified = false
		}
		if cp.TreeSize > s.tree.Size() {
			rep.addIssue("checkpoint_size", "checkpoint is larger than recovered tree", 0, 0, "")
			continue
		}
		r, err := s.tree.RootAt(cp.TreeSize)
		expectedRoot, rootErr := decodeHash32(cp.RootHash)
		if err != nil || rootErr != nil || subtle.ConstantTimeCompare(r[:], expectedRoot[:]) != 1 {
			rep.addIssue("checkpoint_root", fmt.Sprintf("checkpoint %d root mismatch", i), 0, 0, "")
			rep.CheckpointVerified = false
		}
		if len(cp.WitnessReceipts) > 0 {
			n, e := VerifyCheckpointWitnesses(ctx, cp, s.opts.Verifier, 0)
			rep.WitnessesVerified += uint64(n)
			if e != nil {
				rep.addIssue("witness", e.Error(), 0, 0, "")
			}
		}
		h, e := cp.Hash()
		if e == nil {
			prev = h
		}
	}
	if len(s.checkpoints) > 0 {
		last := s.checkpoints[len(s.checkpoints)-1]
		if last.TreeSize == s.tree.Size() && last.RootHash != rep.MerkleRoot {
			rep.addIssue("latest_checkpoint_root", "latest checkpoint does not match tree", 0, 0, "")
		}
	}
	if len(rep.Issues) > 0 {
		rep.Valid = false
	}
	return rep, nil
}

func (r *VerifyReport) addIssue(code, msg string, seg, seq uint64, recordID string) {
	r.Valid = false
	r.Issues = append(r.Issues, VerifyIssue{Code: code, Message: msg, SegmentID: seg, Sequence: seq, RecordID: recordID})
}

func VerifySecureAuditDirectory(ctx context.Context, storeOpts SecureAuditOptions, verifyOpts VerifyOptions) (VerifyReport, error) {
	storeOpts.ReadOnly = true
	storeOpts.RecoverPartial = false
	s, err := OpenSecureAuditStore(storeOpts)
	if err != nil {
		return VerifyReport{Valid: false, Issues: []VerifyIssue{{Code: "open_or_recovery", Message: err.Error()}}}, err
	}
	defer s.Close()
	return s.Verify(ctx, verifyOpts)
}

func VerifyCheckpoint(ctx context.Context, cp Checkpoint, verifier SignatureVerifier) error {
	if cp.Version != SecureCheckpointVersion {
		return errors.New("zlog: unsupported checkpoint version")
	}
	if _, err := decodeHash32(cp.RootHash); err != nil {
		return err
	}
	payload, err := CanonicalJSON(cp.signingPayload())
	if err != nil {
		return err
	}
	sig, err := decodeSignature(cp.Signature)
	if err != nil {
		return err
	}
	return verifier.VerifySignature(ctx, cp.SignerKeyID, cp.SignatureAlgorithm, payload, sig)
}

func VerifyRecordAgainstEnvelope(rec AuditRecord, env AuditEnvelope) error {
	plain, err := CanonicalJSON(rec)
	if err != nil {
		return err
	} // Audit envelopes use raw SHA-256.
	raw := sha256Bytes(plain)
	stored, err := decodeHash32(env.ContentHash)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(raw[:], stored[:]) != 1 {
		return errors.New("zlog: record content hash mismatch")
	}
	if rec.RecordID != env.RecordID || rec.StreamID != env.StreamID || rec.Sequence != env.Sequence {
		return errors.New("zlog: record/envelope identity mismatch")
	}
	return nil
}

func sha256Bytes(b []byte) [32]byte { return sha256.Sum256(b) }
