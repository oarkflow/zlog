package zlog

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	SecureRecordVersion     = "zlog.audit.record.v1"
	SecureEnvelopeVersion   = "zlog.audit.envelope.v1"
	SecureCheckpointVersion = "zlog.audit.checkpoint.v1"
	SecureSegmentVersion    = "zlog.audit.segment.v1"
)

var (
	ErrAuditStoreClosed    = errors.New("zlog: audit store closed")
	ErrRecordNotFound      = errors.New("zlog: audit record not found")
	ErrInvalidProof        = errors.New("zlog: invalid merkle proof")
	ErrWitnessEquivocation = errors.New("zlog: witness detected checkpoint equivocation")
	ErrLegalHold           = errors.New("zlog: record is protected by legal hold")
	ErrNoCheckpoint        = errors.New("zlog: no checkpoint exists for the current tree")
)

// AppendCommittedError means the record is durable but a post-append action,
// such as checkpoint signing or witness quorum collection, failed. Receipt
// identifies the committed record so callers must not blindly retry it.
type AppendCommittedError struct {
	Receipt AppendReceipt
	Cause   error
}

func (e *AppendCommittedError) Error() string {
	return "zlog: audit record committed but finalization failed: " + e.Cause.Error()
}
func (e *AppendCommittedError) Unwrap() error { return e.Cause }

// AuditRecord is the stable, canonical payload written to SecureAuditStore.
// Attributes may contain JSON-compatible values, time.Time, time.Duration and []byte.
type AuditRecord struct {
	Version        string         `json:"version"`
	RecordID       string         `json:"record_id"`
	StreamID       string         `json:"stream_id"`
	TenantID       string         `json:"tenant_id,omitempty"`
	Sequence       uint64         `json:"sequence"`
	EventTime      time.Time      `json:"event_time"`
	ObservedTime   time.Time      `json:"observed_time"`
	Kind           string         `json:"kind"`
	Category       string         `json:"category,omitempty"`
	Name           string         `json:"name"`
	Action         string         `json:"action,omitempty"`
	Outcome        string         `json:"outcome,omitempty"`
	Reason         string         `json:"reason,omitempty"`
	ActorID        string         `json:"actor_id,omitempty"`
	SubjectID      string         `json:"subject_id,omitempty"`
	ResourceType   string         `json:"resource_type,omitempty"`
	ResourceID     string         `json:"resource_id,omitempty"`
	SessionID      string         `json:"session_id,omitempty"`
	RequestID      string         `json:"request_id,omitempty"`
	CorrelationID  string         `json:"correlation_id,omitempty"`
	TraceID        string         `json:"trace_id,omitempty"`
	SpanID         string         `json:"span_id,omitempty"`
	SourceIP       string         `json:"source_ip,omitempty"`
	Service        string         `json:"service,omitempty"`
	Host           string         `json:"host,omitempty"`
	ProcessID      int            `json:"process_id,omitempty"`
	SchemaName     string         `json:"schema_name,omitempty"`
	SchemaVersion  string         `json:"schema_version,omitempty"`
	Retention      string         `json:"retention,omitempty"`
	Classification string         `json:"classification,omitempty"`
	Attributes     map[string]any `json:"attributes,omitempty"`
}

func (r *AuditRecord) normalize(now time.Time) error {
	if r.Version == "" {
		r.Version = SecureRecordVersion
	}
	if r.Version != SecureRecordVersion {
		return fmt.Errorf("zlog: unsupported audit record version %q", r.Version)
	}
	if r.StreamID == "" {
		return errors.New("zlog: stream_id is required")
	}
	if r.Name == "" {
		return errors.New("zlog: event name is required")
	}
	if r.Kind == "" {
		r.Kind = "audit"
	}
	if r.EventTime.IsZero() {
		r.EventTime = now
	}
	if r.ObservedTime.IsZero() {
		r.ObservedTime = now
	}
	if r.RecordID == "" {
		id, err := newSecureID()
		if err != nil {
			return err
		}
		r.RecordID = id
	}
	if len(r.RecordID) > 256 || len(r.StreamID) > 256 || len(r.Name) > 512 {
		return errors.New("zlog: audit identity field too large")
	}
	return validateAuditValue(r.Attributes, 0, 32, 4096)
}

// AuditEnvelope contains the encrypted payload and all independently verifiable
// append-only metadata. Hash strings use lowercase hexadecimal SHA-256 values.
type AuditEnvelope struct {
	Version       string `json:"version"`
	RecordID      string `json:"record_id"`
	StreamID      string `json:"stream_id"`
	TenantID      string `json:"tenant_id,omitempty"`
	Sequence      uint64 `json:"sequence"`
	SegmentID     uint64 `json:"segment_id"`
	SegmentOffset uint64 `json:"segment_offset"`
	ObservedUnix  int64  `json:"observed_unix_nano"`
	KeyID         string `json:"key_id"`
	EncryptionAlg string `json:"encryption_alg"`
	Nonce         string `json:"nonce"`
	Ciphertext    string `json:"ciphertext"`
	ContentHash   string `json:"content_hash"`
	PreviousHash  string `json:"previous_hash"`
	ChainHash     string `json:"chain_hash"`
	LeafHash      string `json:"leaf_hash"`
}

func (e AuditEnvelope) ChainHashBytes() ([32]byte, error) { return decodeHash32(e.ChainHash) }
func (e AuditEnvelope) LeafHashBytes() ([32]byte, error)  { return decodeHash32(e.LeafHash) }

type SegmentHeader struct {
	Version             string `json:"version"`
	Type                string `json:"type"`
	SegmentID           uint64 `json:"segment_id"`
	CreatedAt           string `json:"created_at"`
	FirstSequence       uint64 `json:"first_sequence"`
	PreviousSegmentRoot string `json:"previous_segment_root,omitempty"`
	StreamID            string `json:"stream_id"`
	HashAlgorithm       string `json:"hash_algorithm"`
	EncryptionAlgorithm string `json:"encryption_algorithm"`
	KeyID               string `json:"key_id"`
}

type SegmentTrailer struct {
	Version             string `json:"version"`
	Type                string `json:"type"`
	SegmentID           uint64 `json:"segment_id"`
	SealedAt            string `json:"sealed_at"`
	FirstSequence       uint64 `json:"first_sequence"`
	LastSequence        uint64 `json:"last_sequence"`
	RecordCount         uint64 `json:"record_count"`
	SegmentRoot         string `json:"segment_root"`
	PreviousSegmentRoot string `json:"previous_segment_root,omitempty"`
	HeaderHash          string `json:"header_hash"`
	SignerKeyID         string `json:"signer_key_id"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	Signature           string `json:"signature"`
}

type Checkpoint struct {
	Version            string           `json:"version"`
	TreeID             string           `json:"tree_id"`
	TreeSize           uint64           `json:"tree_size"`
	RootHash           string           `json:"root_hash"`
	PreviousCheckpoint string           `json:"previous_checkpoint_hash,omitempty"`
	CreatedAt          string           `json:"created_at"`
	SignerKeyID        string           `json:"signer_key_id"`
	SignatureAlgorithm string           `json:"signature_algorithm"`
	Signature          string           `json:"signature"`
	WitnessReceipts    []WitnessReceipt `json:"witness_receipts,omitempty"`
}

func (c Checkpoint) signingPayload() Checkpoint {
	c.Signature = ""
	c.WitnessReceipts = nil
	return c
}

func (c Checkpoint) Hash() ([32]byte, error) {
	c.WitnessReceipts = nil
	b, err := CanonicalJSON(c)
	if err != nil {
		return [32]byte{}, err
	}
	return domainHash("ZLOG-CHECKPOINT-HASH-V1", b), nil
}

type InclusionProof struct {
	Version   string   `json:"version"`
	TreeID    string   `json:"tree_id"`
	TreeSize  uint64   `json:"tree_size"`
	LeafIndex uint64   `json:"leaf_index"`
	LeafHash  string   `json:"leaf_hash"`
	RootHash  string   `json:"root_hash"`
	AuditPath []string `json:"audit_path"`
	RecordID  string   `json:"record_id,omitempty"`
	Sequence  uint64   `json:"sequence,omitempty"`
}

type ConsistencyProof struct {
	Version    string   `json:"version"`
	TreeID     string   `json:"tree_id"`
	FirstSize  uint64   `json:"first_size"`
	SecondSize uint64   `json:"second_size"`
	FirstRoot  string   `json:"first_root"`
	SecondRoot string   `json:"second_root"`
	Path       []string `json:"path"`
}

type AppendReceipt struct {
	RecordID   string      `json:"record_id"`
	StreamID   string      `json:"stream_id"`
	Sequence   uint64      `json:"sequence"`
	LeafIndex  uint64      `json:"leaf_index"`
	ChainHash  string      `json:"chain_hash"`
	Checkpoint *Checkpoint `json:"checkpoint,omitempty"`
}

type VerifyOptions struct {
	DecryptContent bool
	Strict         bool
}

type VerifyIssue struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	SegmentID uint64 `json:"segment_id,omitempty"`
	Sequence  uint64 `json:"sequence,omitempty"`
	RecordID  string `json:"record_id,omitempty"`
}

type VerifyReport struct {
	Valid              bool          `json:"valid"`
	Records            uint64        `json:"records"`
	Segments           uint64        `json:"segments"`
	Checkpoints        uint64        `json:"checkpoints"`
	LastSequence       uint64        `json:"last_sequence"`
	LastChainHash      string        `json:"last_chain_hash,omitempty"`
	MerkleRoot         string        `json:"merkle_root,omitempty"`
	ContentVerified    bool          `json:"content_verified"`
	CheckpointVerified bool          `json:"checkpoint_verified"`
	WitnessesVerified  uint64        `json:"witnesses_verified"`
	Issues             []VerifyIssue `json:"issues,omitempty"`
}

// AuditStore is the authoritative secure audit interface.
type AuditStore interface {
	Append(context.Context, AuditRecord) (AppendReceipt, error)
	Get(context.Context, string) (AuditRecord, AuditEnvelope, error)
	LatestCheckpoint(context.Context) (Checkpoint, error)
	InclusionProof(context.Context, string) (InclusionProof, error)
	ConsistencyProof(context.Context, uint64, uint64) (ConsistencyProof, error)
	Verify(context.Context, VerifyOptions) (VerifyReport, error)
	Flush() error
	Close() error
}

func decodeHash32(s string) ([32]byte, error) {
	var out [32]byte
	if s == "" {
		return out, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(out) {
		return out, fmt.Errorf("zlog: invalid sha256 hash %q", s)
	}
	copy(out[:], b)
	return out, nil
}
