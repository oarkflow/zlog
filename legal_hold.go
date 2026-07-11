package zlog

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

const LegalHoldVersion = "zlog.legal-hold.v1"

type LegalHoldEntry struct {
	Version      string   `json:"version"`
	Sequence     uint64   `json:"sequence"`
	HoldID       string   `json:"hold_id"`
	Action       string   `json:"action"` // place or release
	StreamID     string   `json:"stream_id"`
	RecordIDs    []string `json:"record_ids,omitempty"`
	CaseID       string   `json:"case_id,omitempty"`
	Reason       string   `json:"reason"`
	ActorID      string   `json:"actor_id"`
	CreatedAt    string   `json:"created_at"`
	PreviousHash string   `json:"previous_hash,omitempty"`
	EntryHash    string   `json:"entry_hash"`
	SignerKeyID  string   `json:"signer_key_id"`
	Algorithm    string   `json:"algorithm"`
	Signature    string   `json:"signature"`
}

func (e LegalHoldEntry) hashPayload() LegalHoldEntry    { e.EntryHash = ""; e.Signature = ""; return e }
func (e LegalHoldEntry) signingPayload() LegalHoldEntry { e.Signature = ""; return e }

type ActiveLegalHold struct {
	HoldID    string   `json:"hold_id"`
	StreamID  string   `json:"stream_id"`
	RecordIDs []string `json:"record_ids,omitempty"`
	CaseID    string   `json:"case_id,omitempty"`
	Reason    string   `json:"reason"`
	ActorID   string   `json:"actor_id"`
	PlacedAt  string   `json:"placed_at"`
}

type LegalHoldLedger struct {
	mu       sync.RWMutex
	path     string
	signer   CheckpointSigner
	verifier SignatureVerifier
	seq      uint64
	prev     [32]byte
	active   map[string]ActiveLegalHold
}

func OpenLegalHoldLedger(path string, signer CheckpointSigner, verifier SignatureVerifier) (*LegalHoldLedger, error) {
	if path == "" || signer == nil || verifier == nil {
		return nil, errors.New("zlog: legal hold path, signer and verifier are required")
	}
	l := &LegalHoldLedger{path: path, signer: signer, verifier: verifier, active: make(map[string]ActiveLegalHold)}
	if err := l.load(context.Background()); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *LegalHoldLedger) Place(ctx context.Context, hold ActiveLegalHold) (LegalHoldEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if hold.HoldID == "" {
		id, err := newSecureID()
		if err != nil {
			return LegalHoldEntry{}, err
		}
		hold.HoldID = id
	}
	if hold.StreamID == "" || hold.Reason == "" || hold.ActorID == "" {
		return LegalHoldEntry{}, errors.New("zlog: hold stream, reason and actor are required")
	}
	if _, ok := l.active[hold.HoldID]; ok {
		return LegalHoldEntry{}, fmt.Errorf("zlog: legal hold %q already active", hold.HoldID)
	}
	hold.RecordIDs = uniqueSorted(hold.RecordIDs)
	if hold.PlacedAt == "" {
		hold.PlacedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	e := LegalHoldEntry{Version: LegalHoldVersion, Sequence: l.seq + 1, HoldID: hold.HoldID, Action: "place", StreamID: hold.StreamID, RecordIDs: hold.RecordIDs, CaseID: hold.CaseID, Reason: hold.Reason, ActorID: hold.ActorID, CreatedAt: hold.PlacedAt, SignerKeyID: l.signer.KeyID(), Algorithm: l.signer.Algorithm()}
	if l.prev != ([32]byte{}) {
		e.PreviousHash = hex.EncodeToString(l.prev[:])
	}
	if err := l.sealAndAppend(ctx, &e); err != nil {
		return LegalHoldEntry{}, err
	}
	l.active[hold.HoldID] = hold
	return e, nil
}

func (l *LegalHoldLedger) Release(ctx context.Context, holdID, actor, reason string) (LegalHoldEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	hold, ok := l.active[holdID]
	if !ok {
		return LegalHoldEntry{}, fmt.Errorf("zlog: legal hold %q is not active", holdID)
	}
	if actor == "" || reason == "" {
		return LegalHoldEntry{}, errors.New("zlog: release actor and reason are required")
	}
	e := LegalHoldEntry{Version: LegalHoldVersion, Sequence: l.seq + 1, HoldID: holdID, Action: "release", StreamID: hold.StreamID, RecordIDs: hold.RecordIDs, CaseID: hold.CaseID, Reason: reason, ActorID: actor, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), SignerKeyID: l.signer.KeyID(), Algorithm: l.signer.Algorithm()}
	if l.prev != ([32]byte{}) {
		e.PreviousHash = hex.EncodeToString(l.prev[:])
	}
	if err := l.sealAndAppend(ctx, &e); err != nil {
		return LegalHoldEntry{}, err
	}
	delete(l.active, holdID)
	return e, nil
}

func (l *LegalHoldLedger) sealAndAppend(ctx context.Context, e *LegalHoldEntry) error {
	b, err := CanonicalJSON(e.hashPayload())
	if err != nil {
		return err
	}
	h := domainHash("ZLOG-LEGAL-HOLD-ENTRY-V1", b)
	e.EntryHash = hex.EncodeToString(h[:])
	payload, err := CanonicalJSON(e.signingPayload())
	if err != nil {
		return err
	}
	sig, err := l.signer.Sign(ctx, payload)
	if err != nil {
		return err
	}
	e.Signature = signatureB64(sig)
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, we := f.Write(line)
	if we == nil {
		we = f.Sync()
	}
	ce := f.Close()
	if we != nil {
		return we
	}
	if ce != nil {
		return ce
	}
	l.seq = e.Sequence
	l.prev = h
	return nil
}

func (l *LegalHoldLedger) IsHeld(streamID, recordID string) (bool, []ActiveLegalHold) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	var holds []ActiveLegalHold
	for _, h := range l.active {
		if h.StreamID != streamID {
			continue
		}
		if len(h.RecordIDs) == 0 || containsString(h.RecordIDs, recordID) {
			holds = append(holds, h)
		}
	}
	sort.Slice(holds, func(i, j int) bool { return holds[i].HoldID < holds[j].HoldID })
	return len(holds) > 0, holds
}
func (l *LegalHoldLedger) Active() []ActiveLegalHold {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]ActiveLegalHold, 0, len(l.active))
	for _, h := range l.active {
		h.RecordIDs = append([]string(nil), h.RecordIDs...)
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HoldID < out[j].HoldID })
	return out
}
func (l *LegalHoldLedger) Verify(ctx context.Context) (uint64, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return verifyLegalHoldFile(ctx, l.path, l.verifier)
}

func (l *LegalHoldLedger) load(ctx context.Context) error {
	n, active, seq, prev, err := scanLegalHoldFile(ctx, l.path, l.verifier)
	_ = n
	if err != nil {
		return err
	}
	l.active = active
	l.seq = seq
	l.prev = prev
	return nil
}
func verifyLegalHoldFile(ctx context.Context, path string, verifier SignatureVerifier) (uint64, error) {
	n, _, _, _, err := scanLegalHoldFile(ctx, path, verifier)
	return n, err
}
func scanLegalHoldFile(ctx context.Context, path string, verifier SignatureVerifier) (uint64, map[string]ActiveLegalHold, uint64, [32]byte, error) {
	active := make(map[string]ActiveLegalHold)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, active, 0, [32]byte{}, nil
	}
	if err != nil {
		return 0, nil, 0, [32]byte{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var n, seq uint64
	var prev [32]byte
	for sc.Scan() {
		var e LegalHoldEntry
		if err = json.Unmarshal(sc.Bytes(), &e); err != nil {
			return n, nil, seq, prev, err
		}
		if e.Version != LegalHoldVersion || e.Sequence != seq+1 || e.HoldID == "" || e.StreamID == "" || e.ActorID == "" || e.Reason == "" {
			return n, nil, seq, prev, errors.New("zlog: malformed legal hold entry")
		}
		expected := ""
		if prev != ([32]byte{}) {
			expected = hex.EncodeToString(prev[:])
		}
		if e.PreviousHash != expected {
			return n, nil, seq, prev, errors.New("zlog: legal hold chain mismatch")
		}
		b, err := CanonicalJSON(e.hashPayload())
		if err != nil {
			return n, nil, seq, prev, err
		}
		h := domainHash("ZLOG-LEGAL-HOLD-ENTRY-V1", b)
		stored, err := decodeHash32(e.EntryHash)
		if err != nil || subtle.ConstantTimeCompare(h[:], stored[:]) != 1 {
			return n, nil, seq, prev, errors.New("zlog: legal hold entry hash mismatch")
		}
		payload, err := CanonicalJSON(e.signingPayload())
		if err != nil {
			return n, nil, seq, prev, err
		}
		sig, err := decodeSignature(e.Signature)
		if err != nil {
			return n, nil, seq, prev, err
		}
		if err = verifier.VerifySignature(ctx, e.SignerKeyID, e.Algorithm, payload, sig); err != nil {
			return n, nil, seq, prev, err
		}
		switch e.Action {
		case "place":
			if _, ok := active[e.HoldID]; ok {
				return n, nil, seq, prev, errors.New("zlog: duplicate active legal hold")
			}
			active[e.HoldID] = ActiveLegalHold{HoldID: e.HoldID, StreamID: e.StreamID, RecordIDs: uniqueSorted(e.RecordIDs), CaseID: e.CaseID, Reason: e.Reason, ActorID: e.ActorID, PlacedAt: e.CreatedAt}
		case "release":
			if _, ok := active[e.HoldID]; !ok {
				return n, nil, seq, prev, errors.New("zlog: release of inactive legal hold")
			}
			delete(active, e.HoldID)
		default:
			return n, nil, seq, prev, errors.New("zlog: unknown legal hold action")
		}
		n++
		seq = e.Sequence
		prev = h
	}
	if err = sc.Err(); err != nil {
		return n, nil, seq, prev, err
	}
	return n, active, seq, prev, nil
}
func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	cp := append([]string(nil), in...)
	sort.Strings(cp)
	out := cp[:0]
	for _, s := range cp {
		if s == "" {
			continue
		}
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}
func containsString(xs []string, s string) bool {
	i := sort.SearchStrings(xs, s)
	return i < len(xs) && xs[i] == s
}
