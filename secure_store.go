package zlog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SyncPolicy string

const (
	SyncAlways     SyncPolicy = "always"
	SyncCheckpoint SyncPolicy = "checkpoint"
	SyncNever      SyncPolicy = "never"
)

type SecureAuditOptions struct {
	Dir               string
	StreamID          string
	TenantID          string
	EncryptionKey     []byte
	EncryptionKeyID   string
	Signer            CheckpointSigner
	Verifier          SignatureVerifier
	CheckpointEvery   uint64
	SegmentMaxRecords uint64
	SegmentMaxBytes   int64
	MaxRecordBytes    int
	SyncPolicy        SyncPolicy
	RecoverPartial    bool
	Witnesses         []CheckpointWitness
	WitnessQuorum     int
	Clock             func() time.Time
	// ReadOnly verifies and queries existing data without creating, sealing or appending segments.
	ReadOnly bool
}

type recordLocator struct {
	segment uint64
	offset  int64
	length  int
	leaf    uint64
	seq     uint64
}

type segmentDiskLine struct {
	Type    string          `json:"type"`
	Header  *SegmentHeader  `json:"header,omitempty"`
	Record  *AuditEnvelope  `json:"record,omitempty"`
	Trailer *SegmentTrailer `json:"trailer,omitempty"`
}

type segmentRuntime struct {
	id       uint64
	path     string
	file     *os.File
	header   SegmentHeader
	leaves   [][32]byte
	records  uint64
	bytes    int64
	firstSeq uint64
	lastSeq  uint64
	sealed   bool
}

// SecureAuditStore is an encrypted, append-only, hash-chained and Merkle-
// checkpointed store. One instance owns exactly one stream, which keeps stream
// sequencing unambiguous and permits independent retention and key policies.
type SecureAuditStore struct {
	mu              sync.RWMutex
	opts            SecureAuditOptions
	gcm             cipher.AEAD
	tree            *MerkleTree
	segment         *segmentRuntime
	index           map[string]recordLocator
	seq             uint64
	prevHash        [32]byte
	prevSegmentRoot [32]byte
	checkpoints     []Checkpoint
	closed          bool
	stats           secureStoreStats
}

type secureStoreStats struct {
	appended atomic.Uint64
	bytes    atomic.Uint64
	failures atomic.Uint64
}

type SecureAuditStats struct {
	Appended    uint64 `json:"appended"`
	Bytes       uint64 `json:"bytes"`
	Failures    uint64 `json:"failures"`
	TreeSize    uint64 `json:"tree_size"`
	Sequence    uint64 `json:"sequence"`
	SegmentID   uint64 `json:"segment_id"`
	Checkpoints int    `json:"checkpoints"`
}

func OpenSecureAuditStore(opts SecureAuditOptions) (*SecureAuditStore, error) {
	if opts.Dir == "" {
		return nil, errors.New("zlog: secure audit directory is required")
	}
	if opts.StreamID == "" {
		return nil, errors.New("zlog: secure audit stream id is required")
	}
	if len(opts.EncryptionKey) != 32 {
		return nil, errors.New("zlog: secure audit encryption key must be exactly 32 bytes")
	}
	if opts.EncryptionKeyID == "" {
		return nil, errors.New("zlog: encryption key id is required")
	}
	if !opts.ReadOnly && opts.Signer == nil {
		return nil, errors.New("zlog: checkpoint signer is required for writable stores")
	}
	if opts.ReadOnly && opts.Verifier == nil && opts.Signer == nil {
		return nil, errors.New("zlog: checkpoint verifier is required for read-only stores")
	}
	if opts.CheckpointEvery == 0 {
		opts.CheckpointEvery = 1024
	}
	if opts.SegmentMaxRecords == 0 {
		opts.SegmentMaxRecords = 100000
	}
	if opts.SegmentMaxBytes == 0 {
		opts.SegmentMaxBytes = 128 << 20
	}
	if opts.MaxRecordBytes == 0 {
		opts.MaxRecordBytes = 4 << 20
	}
	if opts.SyncPolicy == "" {
		opts.SyncPolicy = SyncAlways
	}
	if opts.SyncPolicy != SyncAlways && opts.SyncPolicy != SyncCheckpoint && opts.SyncPolicy != SyncNever {
		return nil, fmt.Errorf("zlog: invalid sync policy %q", opts.SyncPolicy)
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.WitnessQuorum < 0 || opts.WitnessQuorum > len(opts.Witnesses) {
		return nil, errors.New("zlog: invalid witness quorum")
	}
	block, err := aes.NewCipher(opts.EncryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if opts.ReadOnly {
		st, statErr := os.Stat(filepath.Join(opts.Dir, "segments"))
		if statErr != nil {
			return nil, fmt.Errorf("zlog: open read-only audit store: %w", statErr)
		}
		if !st.IsDir() {
			return nil, errors.New("zlog: read-only segments path is not a directory")
		}
	} else {
		if err := os.MkdirAll(filepath.Join(opts.Dir, "segments"), 0700); err != nil {
			return nil, err
		}
		if err := os.Chmod(opts.Dir, 0700); err != nil && !os.IsPermission(err) {
			return nil, err
		}
	}
	s := &SecureAuditStore{opts: opts, gcm: gcm, tree: NewMerkleTree(), index: make(map[string]recordLocator)}
	if opts.Verifier == nil {
		reg := NewPublicKeyRegistry()
		if pemData, e := opts.Signer.PublicKeyPEM(); e == nil {
			if e = reg.RegisterPEM(opts.Signer.KeyID(), opts.Signer.Algorithm(), pemData); e != nil {
				return nil, e
			}
			opts.Verifier = reg
			s.opts.Verifier = reg
		} else if hs, ok := opts.Signer.(*HMACCheckpointSigner); ok {
			if e = reg.RegisterHMAC(hs.KeyID(), hs.key); e != nil {
				return nil, e
			}
			opts.Verifier = reg
			s.opts.Verifier = reg
		} else {
			return nil, fmt.Errorf("zlog: signer public key unavailable: %w", e)
		}
	}
	if reg, ok := s.opts.Verifier.(*PublicKeyRegistry); ok {
		for _, witness := range s.opts.Witnesses {
			fw, ok := witness.(*FileCheckpointWitness)
			if !ok {
				continue
			}
			if err := fw.RegisterVerificationKey(reg); err != nil {
				return nil, err
			}
		}
	}
	if err := s.loadCheckpoints(context.Background()); err != nil {
		return nil, err
	}
	if err := s.recoverSegments(context.Background()); err != nil {
		return nil, err
	}
	if err := s.validateRecoveredCheckpoints(context.Background()); err != nil {
		if s.segment != nil && s.segment.file != nil {
			_ = s.segment.file.Close()
		}
		return nil, err
	}
	return s, nil
}

func (s *SecureAuditStore) Append(ctx context.Context, rec AuditRecord) (AppendReceipt, error) {
	select {
	case <-ctx.Done():
		return AppendReceipt{}, ctx.Err()
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return AppendReceipt{}, ErrAuditStoreClosed
	}
	if s.opts.ReadOnly {
		return AppendReceipt{}, errors.New("zlog: audit store is read-only")
	}
	now := s.opts.Clock().UTC()
	if rec.StreamID == "" {
		rec.StreamID = s.opts.StreamID
	}
	if rec.StreamID != s.opts.StreamID {
		return AppendReceipt{}, fmt.Errorf("zlog: record stream %q does not match store stream %q", rec.StreamID, s.opts.StreamID)
	}
	if rec.TenantID == "" {
		rec.TenantID = s.opts.TenantID
	}
	if s.opts.TenantID != "" && rec.TenantID != s.opts.TenantID {
		return AppendReceipt{}, errors.New("zlog: record tenant does not match store tenant")
	}
	rec.Sequence = s.seq + 1
	if err := rec.normalize(now); err != nil {
		s.stats.failures.Add(1)
		return AppendReceipt{}, err
	}
	plain, err := CanonicalJSON(rec)
	if err != nil {
		s.stats.failures.Add(1)
		return AppendReceipt{}, err
	}
	if len(plain) > s.opts.MaxRecordBytes {
		s.stats.failures.Add(1)
		return AppendReceipt{}, fmt.Errorf("zlog: canonical audit record exceeds %d bytes", s.opts.MaxRecordBytes)
	}
	if s.segment == nil || s.segment.sealed || s.segment.records >= s.opts.SegmentMaxRecords || s.segment.bytes >= s.opts.SegmentMaxBytes {
		if s.segment != nil && !s.segment.sealed {
			if err := s.sealSegmentLocked(ctx); err != nil {
				return AppendReceipt{}, err
			}
		}
		if err := s.openNewSegmentLocked(now); err != nil {
			return AppendReceipt{}, err
		}
	}
	content := sha256.Sum256(plain)
	seqb := make([]byte, 8)
	binary.BigEndian.PutUint64(seqb, rec.Sequence)
	chain := domainHash("ZLOG-AUDIT-CHAIN-V1", []byte(rec.StreamID), seqb, s.prevHash[:], content[:])
	leaf := domainHash("ZLOG-AUDIT-LEAF-V1", []byte(rec.RecordID), []byte(rec.StreamID), seqb, chain[:])
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return AppendReceipt{}, err
	}
	env := AuditEnvelope{
		Version: SecureEnvelopeVersion, RecordID: rec.RecordID, StreamID: rec.StreamID, TenantID: rec.TenantID,
		Sequence: rec.Sequence, SegmentID: s.segment.id, SegmentOffset: s.segment.records,
		ObservedUnix: rec.ObservedTime.UnixNano(), KeyID: s.opts.EncryptionKeyID, EncryptionAlg: "AES-256-GCM",
		Nonce: base64.RawStdEncoding.EncodeToString(nonce), ContentHash: hex.EncodeToString(content[:]),
		PreviousHash: hex.EncodeToString(s.prevHash[:]), ChainHash: hex.EncodeToString(chain[:]), LeafHash: hex.EncodeToString(leaf[:]),
	}
	aad, err := canonicalEnvelopeAAD(env)
	if err != nil {
		return AppendReceipt{}, err
	}
	env.Ciphertext = base64.RawStdEncoding.EncodeToString(s.gcm.Seal(nil, nonce, plain, aad))
	line, err := json.Marshal(segmentDiskLine{Type: "record", Record: &env})
	if err != nil {
		return AppendReceipt{}, err
	}
	line = append(line, '\n')
	offset := s.segment.bytes
	n, err := s.segment.file.Write(line)
	if err != nil {
		s.stats.failures.Add(1)
		return AppendReceipt{}, err
	}
	if n != len(line) {
		s.stats.failures.Add(1)
		return AppendReceipt{}, io.ErrShortWrite
	}
	if s.opts.SyncPolicy == SyncAlways {
		if err := s.segment.file.Sync(); err != nil {
			return AppendReceipt{}, err
		}
	}
	leafIndex := s.tree.Append(leaf)
	s.index[rec.RecordID] = recordLocator{segment: s.segment.id, offset: offset, length: len(line), leaf: leafIndex, seq: rec.Sequence}
	s.segment.leaves = append(s.segment.leaves, leaf)
	s.segment.records++
	s.segment.bytes += int64(n)
	if s.segment.firstSeq == 0 {
		s.segment.firstSeq = rec.Sequence
	}
	s.segment.lastSeq = rec.Sequence
	s.seq = rec.Sequence
	s.prevHash = chain
	s.stats.appended.Add(1)
	s.stats.bytes.Add(uint64(n))
	receipt := AppendReceipt{RecordID: rec.RecordID, StreamID: rec.StreamID, Sequence: rec.Sequence, LeafIndex: leafIndex, ChainHash: env.ChainHash}
	if s.tree.Size()%s.opts.CheckpointEvery == 0 {
		cp, err := s.createCheckpointLocked(ctx)
		if err != nil {
			return receipt, &AppendCommittedError{Receipt: receipt, Cause: err}
		}
		receipt.Checkpoint = &cp
	}
	return receipt, nil
}

func canonicalEnvelopeAAD(e AuditEnvelope) ([]byte, error) {
	e.Ciphertext = ""
	return CanonicalJSON(e)
}

func (s *SecureAuditStore) Get(ctx context.Context, recordID string) (AuditRecord, AuditEnvelope, error) {
	select {
	case <-ctx.Done():
		return AuditRecord{}, AuditEnvelope{}, ctx.Err()
	default:
	}
	s.mu.RLock()
	loc, ok := s.index[recordID]
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return AuditRecord{}, AuditEnvelope{}, ErrAuditStoreClosed
	}
	if !ok {
		return AuditRecord{}, AuditEnvelope{}, ErrRecordNotFound
	}
	env, err := s.readEnvelope(loc)
	if err != nil {
		return AuditRecord{}, AuditEnvelope{}, err
	}
	rec, err := s.decryptEnvelope(env)
	return rec, env, err
}

func (s *SecureAuditStore) readEnvelope(loc recordLocator) (AuditEnvelope, error) {
	path := s.segmentPath(loc.segment)
	f, err := os.Open(path)
	if err != nil {
		return AuditEnvelope{}, err
	}
	defer f.Close()
	if _, err = f.Seek(loc.offset, io.SeekStart); err != nil {
		return AuditEnvelope{}, err
	}
	buf := make([]byte, loc.length)
	if _, err = io.ReadFull(f, buf); err != nil {
		return AuditEnvelope{}, err
	}
	var dl segmentDiskLine
	if err = json.Unmarshal(bytes.TrimSpace(buf), &dl); err != nil {
		return AuditEnvelope{}, err
	}
	if dl.Type != "record" || dl.Record == nil {
		return AuditEnvelope{}, errors.New("zlog: index does not reference a record")
	}
	return *dl.Record, nil
}

func (s *SecureAuditStore) decryptEnvelope(env AuditEnvelope) (AuditRecord, error) {
	if env.Version != SecureEnvelopeVersion || env.EncryptionAlg != "AES-256-GCM" || env.KeyID != s.opts.EncryptionKeyID {
		return AuditRecord{}, errors.New("zlog: unsupported or wrong encrypted envelope")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != s.gcm.NonceSize() {
		return AuditRecord{}, errors.New("zlog: invalid envelope nonce")
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return AuditRecord{}, err
	}
	aad, err := canonicalEnvelopeAAD(env)
	if err != nil {
		return AuditRecord{}, err
	}
	plain, err := s.gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return AuditRecord{}, fmt.Errorf("zlog: envelope authentication failed: %w", err)
	}
	content := sha256.Sum256(plain)
	expected, err := decodeHash32(env.ContentHash)
	if err != nil {
		return AuditRecord{}, err
	}
	if subtle.ConstantTimeCompare(content[:], expected[:]) != 1 {
		return AuditRecord{}, errors.New("zlog: content hash mismatch")
	}
	var rec AuditRecord
	if err := strictUnmarshal(plain, &rec); err != nil {
		return AuditRecord{}, err
	}
	if rec.RecordID != env.RecordID || rec.StreamID != env.StreamID || rec.TenantID != env.TenantID || rec.Sequence != env.Sequence || rec.ObservedTime.UnixNano() != env.ObservedUnix {
		return AuditRecord{}, errors.New("zlog: encrypted record identity mismatch")
	}
	if s.opts.TenantID != "" && rec.TenantID != s.opts.TenantID {
		return AuditRecord{}, errors.New("zlog: encrypted record tenant mismatch")
	}
	return rec, nil
}

func strictUnmarshal(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var x any
	if err := dec.Decode(&x); err == nil {
		return errors.New("zlog: trailing JSON")
	} else if err != io.EOF {
		return err
	}
	return nil
}

func (s *SecureAuditStore) InclusionProof(ctx context.Context, recordID string) (InclusionProof, error) {
	select {
	case <-ctx.Done():
		return InclusionProof{}, ctx.Err()
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	loc, ok := s.index[recordID]
	if !ok {
		return InclusionProof{}, ErrRecordNotFound
	}
	if s.closed {
		return InclusionProof{}, ErrAuditStoreClosed
	}
	cp, err := s.ensureCurrentCheckpointLocked(ctx)
	if err != nil {
		return InclusionProof{}, err
	}
	path, err := s.tree.Inclusion(loc.leaf, cp.TreeSize)
	if err != nil {
		return InclusionProof{}, err
	}
	env, err := s.readEnvelope(loc)
	if err != nil {
		return InclusionProof{}, err
	}
	return InclusionProof{Version: "zlog.audit.inclusion.v1", TreeID: s.opts.StreamID, TreeSize: cp.TreeSize, LeafIndex: loc.leaf, LeafHash: env.LeafHash, RootHash: cp.RootHash, AuditPath: hashesToStrings(path), RecordID: recordID, Sequence: loc.seq}, nil
}
func (s *SecureAuditStore) ConsistencyProof(ctx context.Context, first, second uint64) (ConsistencyProof, error) {
	select {
	case <-ctx.Done():
		return ConsistencyProof{}, ctx.Err()
	default:
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	path, err := s.tree.Consistency(first, second)
	if err != nil {
		return ConsistencyProof{}, err
	}
	fr, err := s.tree.RootAt(first)
	if err != nil {
		return ConsistencyProof{}, err
	}
	sr, err := s.tree.RootAt(second)
	if err != nil {
		return ConsistencyProof{}, err
	}
	return ConsistencyProof{Version: "zlog.audit.consistency.v1", TreeID: s.opts.StreamID, FirstSize: first, SecondSize: second, FirstRoot: hex.EncodeToString(fr[:]), SecondRoot: hex.EncodeToString(sr[:]), Path: hashesToStrings(path)}, nil
}
func (s *SecureAuditStore) LatestCheckpoint(ctx context.Context) (Checkpoint, error) {
	select {
	case <-ctx.Done():
		return Checkpoint{}, ctx.Err()
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Checkpoint{}, ErrAuditStoreClosed
	}
	return s.ensureCurrentCheckpointLocked(ctx)
}

func (s *SecureAuditStore) ensureCurrentCheckpointLocked(ctx context.Context) (Checkpoint, error) {
	if len(s.checkpoints) > 0 && s.checkpoints[len(s.checkpoints)-1].TreeSize == s.tree.Size() {
		return s.checkpoints[len(s.checkpoints)-1], nil
	}
	if s.opts.ReadOnly {
		return Checkpoint{}, ErrNoCheckpoint
	}
	return s.createCheckpointLocked(ctx)
}
func (s *SecureAuditStore) createCheckpointLocked(ctx context.Context) (Checkpoint, error) {
	if s.opts.ReadOnly || s.opts.Signer == nil {
		return Checkpoint{}, errors.New("zlog: cannot create checkpoint in read-only store")
	}
	root := s.tree.Root()
	cp := Checkpoint{Version: SecureCheckpointVersion, TreeID: s.opts.StreamID, TreeSize: s.tree.Size(), RootHash: hex.EncodeToString(root[:]), CreatedAt: s.opts.Clock().UTC().Format(time.RFC3339Nano), SignerKeyID: s.opts.Signer.KeyID(), SignatureAlgorithm: s.opts.Signer.Algorithm()}
	if len(s.checkpoints) > 0 {
		h, err := s.checkpoints[len(s.checkpoints)-1].Hash()
		if err != nil {
			return Checkpoint{}, err
		}
		cp.PreviousCheckpoint = hex.EncodeToString(h[:])
	}
	payload, err := CanonicalJSON(cp.signingPayload())
	if err != nil {
		return Checkpoint{}, err
	}
	sig, err := s.opts.Signer.Sign(ctx, payload)
	if err != nil {
		return Checkpoint{}, err
	}
	cp.Signature = signatureB64(sig)
	receipts := make([]WitnessReceipt, 0, len(s.opts.Witnesses))
	var consistency *ConsistencyProof
	if len(s.checkpoints) > 0 {
		previous := s.checkpoints[len(s.checkpoints)-1]
		if previous.TreeSize > 0 && previous.TreeSize < cp.TreeSize {
			path, e := s.tree.Consistency(previous.TreeSize, cp.TreeSize)
			if e != nil {
				return Checkpoint{}, e
			}
			consistency = &ConsistencyProof{Version: "zlog.audit.consistency.v1", TreeID: cp.TreeID, FirstSize: previous.TreeSize, SecondSize: cp.TreeSize, FirstRoot: previous.RootHash, SecondRoot: cp.RootHash, Path: hashesToStrings(path)}
		}
	}
	for _, w := range s.opts.Witnesses {
		var r WitnessReceipt
		var e error
		if cw, ok := w.(ConsistencyCheckpointWitness); ok {
			r, e = cw.ObserveConsistency(ctx, cp, consistency, s.opts.Verifier)
		} else {
			r, e = w.Observe(ctx, cp, s.opts.Verifier)
		}
		if e == nil {
			receipts = append(receipts, r)
		}
	}
	if len(receipts) < s.opts.WitnessQuorum {
		return Checkpoint{}, fmt.Errorf("zlog: witness quorum not met: got %d need %d", len(receipts), s.opts.WitnessQuorum)
	}
	cp.WitnessReceipts = receipts
	b, err := json.Marshal(cp)
	if err != nil {
		return Checkpoint{}, err
	}
	b = append(b, '\n')
	f, err := os.OpenFile(filepath.Join(s.opts.Dir, "checkpoints.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return Checkpoint{}, err
	}
	_, werr := f.Write(b)
	if werr == nil && (s.opts.SyncPolicy == SyncAlways || s.opts.SyncPolicy == SyncCheckpoint) {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr != nil {
		return Checkpoint{}, werr
	}
	if cerr != nil {
		return Checkpoint{}, cerr
	}
	s.checkpoints = append(s.checkpoints, cp)
	return cp, nil
}

func (s *SecureAuditStore) openNewSegmentLocked(now time.Time) error {
	id := uint64(1)
	if s.segment != nil {
		id = s.segment.id + 1
	} else {
		files, _ := filepath.Glob(filepath.Join(s.opts.Dir, "segments", "*.zseg"))
		if len(files) > 0 {
			id = segmentIDFromPath(files[len(files)-1]) + 1
		}
	}
	path := s.segmentPath(id)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	header := SegmentHeader{Version: SecureSegmentVersion, Type: "header", SegmentID: id, CreatedAt: now.Format(time.RFC3339Nano), FirstSequence: s.seq + 1, StreamID: s.opts.StreamID, HashAlgorithm: "SHA-256", EncryptionAlgorithm: "AES-256-GCM", KeyID: s.opts.EncryptionKeyID}
	if s.prevSegmentRoot != ([32]byte{}) {
		header.PreviousSegmentRoot = hex.EncodeToString(s.prevSegmentRoot[:])
	}
	line, err := json.Marshal(segmentDiskLine{Type: "header", Header: &header})
	if err != nil {
		f.Close()
		return err
	}
	line = append(line, '\n')
	n, err := f.Write(line)
	if err != nil {
		f.Close()
		return err
	}
	if s.opts.SyncPolicy == SyncAlways {
		if err = f.Sync(); err != nil {
			f.Close()
			return err
		}
	}
	s.segment = &segmentRuntime{id: id, path: path, file: f, header: header, bytes: int64(n)}
	return nil
}
func (s *SecureAuditStore) sealSegmentLocked(ctx context.Context) error {
	seg := s.segment
	if seg == nil || seg.sealed {
		return nil
	}
	root := merkleRoot(seg.leaves)
	headerBytes, err := CanonicalJSON(seg.header)
	if err != nil {
		return err
	}
	headerHash := domainHash("ZLOG-SEGMENT-HEADER-V1", headerBytes)
	tr := SegmentTrailer{Version: SecureSegmentVersion, Type: "trailer", SegmentID: seg.id, SealedAt: s.opts.Clock().UTC().Format(time.RFC3339Nano), FirstSequence: seg.firstSeq, LastSequence: seg.lastSeq, RecordCount: seg.records, SegmentRoot: hex.EncodeToString(root[:]), HeaderHash: hex.EncodeToString(headerHash[:]), SignerKeyID: s.opts.Signer.KeyID(), SignatureAlgorithm: s.opts.Signer.Algorithm()}
	if s.prevSegmentRoot != ([32]byte{}) {
		tr.PreviousSegmentRoot = hex.EncodeToString(s.prevSegmentRoot[:])
	}
	unsigned := tr
	unsigned.Signature = ""
	payload, err := CanonicalJSON(unsigned)
	if err != nil {
		return err
	}
	sig, err := s.opts.Signer.Sign(ctx, payload)
	if err != nil {
		return err
	}
	tr.Signature = signatureB64(sig)
	line, err := json.Marshal(segmentDiskLine{Type: "trailer", Trailer: &tr})
	if err != nil {
		return err
	}
	line = append(line, '\n')
	n, err := seg.file.Write(line)
	if err != nil {
		return err
	}
	seg.bytes += int64(n)
	if s.opts.SyncPolicy != SyncNever {
		if err = seg.file.Sync(); err != nil {
			return err
		}
	}
	if err = seg.file.Close(); err != nil {
		return err
	}
	seg.file = nil
	seg.sealed = true
	s.prevSegmentRoot = root
	_, err = s.ensureCurrentCheckpointLocked(ctx)
	return err
}

func (s *SecureAuditStore) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrAuditStoreClosed
	}
	if s.segment != nil && s.segment.file != nil {
		return s.segment.file.Sync()
	}
	return nil
}
func (s *SecureAuditStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	var err error
	if !s.opts.ReadOnly && s.segment != nil && !s.segment.sealed {
		err = s.sealSegmentLocked(context.Background())
	}
	s.closed = true
	return err
}
func (s *SecureAuditStore) Stats() SecureAuditStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id := uint64(0)
	if s.segment != nil {
		id = s.segment.id
	}
	return SecureAuditStats{Appended: s.stats.appended.Load(), Bytes: s.stats.bytes.Load(), Failures: s.stats.failures.Load(), TreeSize: s.tree.Size(), Sequence: s.seq, SegmentID: id, Checkpoints: len(s.checkpoints)}
}
func (s *SecureAuditStore) segmentPath(id uint64) string {
	return filepath.Join(s.opts.Dir, "segments", fmt.Sprintf("%020d.zseg", id))
}

func (s *SecureAuditStore) loadCheckpoints(ctx context.Context) error {
	path := filepath.Join(s.opts.Dir, "checkpoints.jsonl")
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var prev [32]byte
	line := 0
	for sc.Scan() {
		line++
		var cp Checkpoint
		if err = json.Unmarshal(sc.Bytes(), &cp); err != nil {
			return fmt.Errorf("zlog: checkpoint line %d: %w", line, err)
		}
		if err = s.verifyCheckpoint(ctx, cp, prev); err != nil {
			return fmt.Errorf("zlog: checkpoint line %d: %w", line, err)
		}
		h, e := cp.Hash()
		if e != nil {
			return e
		}
		prev = h
		s.checkpoints = append(s.checkpoints, cp)
	}
	return sc.Err()
}
func (s *SecureAuditStore) verifyCheckpoint(ctx context.Context, cp Checkpoint, prev [32]byte) error {
	if cp.Version != SecureCheckpointVersion || cp.TreeID != s.opts.StreamID {
		return errors.New("zlog: checkpoint identity mismatch")
	}
	expected := ""
	if prev != ([32]byte{}) {
		expected = hex.EncodeToString(prev[:])
	}
	if cp.PreviousCheckpoint != expected {
		return errors.New("zlog: checkpoint chain mismatch")
	}
	payload, err := CanonicalJSON(cp.signingPayload())
	if err != nil {
		return err
	}
	sig, err := decodeSignature(cp.Signature)
	if err != nil {
		return err
	}
	if s.opts.Verifier == nil {
		return errors.New("zlog: no checkpoint verifier configured")
	}
	if err = s.opts.Verifier.VerifySignature(ctx, cp.SignerKeyID, cp.SignatureAlgorithm, payload, sig); err != nil {
		return err
	}
	return nil
}

func (s *SecureAuditStore) recoverSegments(ctx context.Context) error {
	files, err := filepath.Glob(filepath.Join(s.opts.Dir, "segments", "*.zseg"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	var previousRoot [32]byte
	for i, path := range files {
		if i > 0 && s.segment != nil && !s.segment.sealed {
			return errors.New("zlog: unsealed segment is not the final segment")
		}
		seg, err := s.scanSegment(ctx, path, uint64(i+1), previousRoot)
		if err != nil {
			return err
		}
		s.segment = seg
		if seg.sealed {
			previousRoot = merkleRoot(seg.leaves)
			s.prevSegmentRoot = previousRoot
		}
	}
	// Segments are opened lazily by Append, so verification and empty-store
	// open/close operations never mutate the audit directory.
	return nil
}

func (s *SecureAuditStore) scanSegment(ctx context.Context, path string, expectedID uint64, previousRoot [32]byte) (*segmentRuntime, error) {
	flags := os.O_RDWR
	if s.opts.ReadOnly {
		flags = os.O_RDONLY
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(f, 128<<10)
	seg := &segmentRuntime{id: expectedID, path: path, file: f}
	var offset int64
	lineNo := 0
	for {
		start := offset
		line, rerr := reader.ReadBytes('\n')
		offset += int64(len(line))
		if len(line) == 0 && rerr == io.EOF {
			break
		}
		if rerr == io.EOF && len(line) > 0 {
			if s.opts.RecoverPartial && !s.opts.ReadOnly {
				if err = f.Truncate(start); err != nil {
					f.Close()
					return nil, err
				}
				offset = start
				break
			}
			f.Close()
			return nil, fmt.Errorf("zlog: partial final line in %s", path)
		}
		if rerr != nil && rerr != io.EOF {
			f.Close()
			return nil, rerr
		}
		lineNo++
		if len(line) > s.opts.MaxRecordBytes+(1<<20) {
			f.Close()
			return nil, fmt.Errorf("zlog: oversized segment line %d", lineNo)
		}
		var dl segmentDiskLine
		if err = json.Unmarshal(bytes.TrimSpace(line), &dl); err != nil {
			f.Close()
			return nil, fmt.Errorf("zlog: %s line %d: %w", path, lineNo, err)
		}
		switch dl.Type {
		case "header":
			if lineNo != 1 || dl.Header == nil {
				f.Close()
				return nil, errors.New("zlog: invalid segment header")
			}
			h := *dl.Header
			if h.Version != SecureSegmentVersion || h.SegmentID != expectedID || h.StreamID != s.opts.StreamID || h.KeyID != s.opts.EncryptionKeyID || h.HashAlgorithm != "SHA-256" || h.EncryptionAlgorithm != "AES-256-GCM" || h.FirstSequence != s.seq+1 {
				f.Close()
				return nil, errors.New("zlog: segment header identity mismatch")
			}
			expectedPrev := ""
			if previousRoot != ([32]byte{}) {
				expectedPrev = hex.EncodeToString(previousRoot[:])
			}
			if h.PreviousSegmentRoot != expectedPrev {
				f.Close()
				return nil, errors.New("zlog: segment linkage mismatch")
			}
			seg.header = h
			seg.bytes = offset
		case "record":
			if dl.Record == nil || seg.header.Version == "" || seg.sealed {
				f.Close()
				return nil, errors.New("zlog: invalid segment record placement")
			}
			env := *dl.Record
			if env.SegmentID != seg.id || env.SegmentOffset != seg.records || env.StreamID != s.opts.StreamID || env.Sequence != s.seq+1 {
				f.Close()
				return nil, fmt.Errorf("zlog: sequence or segment offset mismatch at line %d", lineNo)
			}
			rec, err := s.decryptEnvelope(env)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("zlog: decrypt line %d: %w", lineNo, err)
			}
			if err = s.verifyEnvelopeChain(env, rec, s.prevHash); err != nil {
				f.Close()
				return nil, fmt.Errorf("zlog: chain line %d: %w", lineNo, err)
			}
			leaf, _ := env.LeafHashBytes()
			idx := s.tree.Append(leaf)
			if _, exists := s.index[env.RecordID]; exists {
				f.Close()
				return nil, fmt.Errorf("zlog: duplicate record id %q", env.RecordID)
			}
			s.index[env.RecordID] = recordLocator{segment: seg.id, offset: start, length: len(line), leaf: idx, seq: env.Sequence}
			seg.leaves = append(seg.leaves, leaf)
			seg.records++
			seg.bytes = offset
			if seg.firstSeq == 0 {
				seg.firstSeq = env.Sequence
			}
			seg.lastSeq = env.Sequence
			s.seq = env.Sequence
			s.prevHash, _ = env.ChainHashBytes()
			s.stats.appended.Add(1)
			s.stats.bytes.Add(uint64(len(line)))
		case "trailer":
			if dl.Trailer == nil || seg.sealed {
				f.Close()
				return nil, errors.New("zlog: invalid segment trailer")
			}
			tr := *dl.Trailer
			if err = s.verifySegmentTrailer(ctx, tr, seg, previousRoot); err != nil {
				f.Close()
				return nil, err
			}
			seg.sealed = true
			seg.bytes = offset
		default:
			f.Close()
			return nil, fmt.Errorf("zlog: unknown segment line type %q", dl.Type)
		}
	}
	if seg.header.Version == "" {
		f.Close()
		return nil, errors.New("zlog: empty segment")
	}
	if seg.sealed || s.opts.ReadOnly {
		if err = f.Close(); err != nil {
			return nil, err
		}
		seg.file = nil
	} else {
		if _, err = f.Seek(0, io.SeekEnd); err != nil {
			f.Close()
			return nil, err
		}
	}
	return seg, nil
}
func (s *SecureAuditStore) verifyEnvelopeChain(env AuditEnvelope, rec AuditRecord, prev [32]byte) error {
	content, err := decodeHash32(env.ContentHash)
	if err != nil {
		return err
	}
	expectedPrev := hex.EncodeToString(prev[:])
	if env.PreviousHash != expectedPrev {
		return errors.New("zlog: previous hash mismatch")
	}
	seqb := make([]byte, 8)
	binary.BigEndian.PutUint64(seqb, env.Sequence)
	chain := domainHash("ZLOG-AUDIT-CHAIN-V1", []byte(env.StreamID), seqb, prev[:], content[:])
	stored, err := env.ChainHashBytes()
	if err != nil || subtle.ConstantTimeCompare(chain[:], stored[:]) != 1 {
		return errors.New("zlog: chain hash mismatch")
	}
	leaf := domainHash("ZLOG-AUDIT-LEAF-V1", []byte(env.RecordID), []byte(env.StreamID), seqb, chain[:])
	storedLeaf, err := env.LeafHashBytes()
	if err != nil || subtle.ConstantTimeCompare(leaf[:], storedLeaf[:]) != 1 {
		return errors.New("zlog: leaf hash mismatch")
	}
	if rec.Sequence != env.Sequence {
		return errors.New("zlog: record sequence mismatch")
	}
	return nil
}
func (s *SecureAuditStore) verifySegmentTrailer(ctx context.Context, tr SegmentTrailer, seg *segmentRuntime, previousRoot [32]byte) error {
	if tr.Version != SecureSegmentVersion || tr.SegmentID != seg.id || tr.RecordCount != seg.records || tr.FirstSequence != seg.firstSeq || tr.LastSequence != seg.lastSeq {
		return errors.New("zlog: segment trailer metadata mismatch")
	}
	root := merkleRoot(seg.leaves)
	if tr.SegmentRoot != hex.EncodeToString(root[:]) {
		return errors.New("zlog: segment root mismatch")
	}
	expectedPrev := ""
	if previousRoot != ([32]byte{}) {
		expectedPrev = hex.EncodeToString(previousRoot[:])
	}
	if tr.PreviousSegmentRoot != expectedPrev {
		return errors.New("zlog: trailer previous root mismatch")
	}
	headerBytes, err := CanonicalJSON(seg.header)
	if err != nil {
		return err
	}
	headerHash := domainHash("ZLOG-SEGMENT-HEADER-V1", headerBytes)
	if tr.HeaderHash != hex.EncodeToString(headerHash[:]) {
		return errors.New("zlog: segment header hash mismatch")
	}
	unsigned := tr
	unsigned.Signature = ""
	payload, err := CanonicalJSON(unsigned)
	if err != nil {
		return err
	}
	sig, err := decodeSignature(tr.Signature)
	if err != nil {
		return err
	}
	return s.opts.Verifier.VerifySignature(ctx, tr.SignerKeyID, tr.SignatureAlgorithm, payload, sig)
}

func segmentIDFromPath(path string) uint64 {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	n, _ := strconv.ParseUint(base, 10, 64)
	return n
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".zlog-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(perm); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	cerr := tmp.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (s *SecureAuditStore) validateRecoveredCheckpoints(ctx context.Context) error {
	var lastSize uint64
	for i, cp := range s.checkpoints {
		if i > 0 && cp.TreeSize < lastSize {
			return fmt.Errorf("zlog: checkpoint %d rolls tree size backward", i)
		}
		if cp.TreeSize > s.tree.Size() {
			return fmt.Errorf("zlog: checkpoint %d tree size %d exceeds recovered tree %d", i, cp.TreeSize, s.tree.Size())
		}
		root, err := s.tree.RootAt(cp.TreeSize)
		if err != nil {
			return err
		}
		expected, err := decodeHash32(cp.RootHash)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(root[:], expected[:]) != 1 {
			return fmt.Errorf("zlog: checkpoint %d root does not match recovered tree", i)
		}
		if len(cp.WitnessReceipts) > 0 {
			if _, err := VerifyCheckpointWitnesses(ctx, cp, s.opts.Verifier, len(cp.WitnessReceipts)); err != nil {
				return fmt.Errorf("zlog: checkpoint %d witness verification: %w", i, err)
			}
		}
		lastSize = cp.TreeSize
	}
	return nil
}

func segmentFiles(dir string) ([]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "segments", "*.zseg"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}
