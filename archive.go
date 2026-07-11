package zlog

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const ArchiveReceiptVersion = "zlog.archive.receipt.v1"

type ArchiveReceipt struct {
	Version            string `json:"version"`
	ObjectName         string `json:"object_name"`
	Size               int64  `json:"size"`
	SHA256             string `json:"sha256"`
	ArchivedAt         string `json:"archived_at"`
	SignerKeyID        string `json:"signer_key_id"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Signature          string `json:"signature"`
}

func (r ArchiveReceipt) signingPayload() ArchiveReceipt { r.Signature = ""; return r }

type ImmutableArchive interface {
	Put(context.Context, string, io.Reader) (ArchiveReceipt, error)
	Verify(context.Context, string) (ArchiveReceipt, error)
}

// LocalWriteOnceArchive is a create-only archive backend with signed receipts.
// Files are created through O_EXCL, fsynced, renamed atomically, and changed to
// read-only permissions. Filesystem permissions are not a substitute for cloud
// object-lock or hardware WORM storage, but accidental overwrite is prevented.
type LocalWriteOnceArchive struct {
	mu             sync.Mutex
	dir            string
	signer         CheckpointSigner
	verifier       SignatureVerifier
	maxObjectBytes int64
}

func OpenLocalWriteOnceArchive(dir string, signer CheckpointSigner, verifier SignatureVerifier, maxObjectBytes int64) (*LocalWriteOnceArchive, error) {
	if dir == "" || signer == nil || verifier == nil {
		return nil, errors.New("zlog: archive dir, signer and verifier required")
	}
	if maxObjectBytes <= 0 {
		maxObjectBytes = 4 << 30
	}
	if err := os.MkdirAll(filepath.Join(dir, "objects"), 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "receipts"), 0700); err != nil {
		return nil, err
	}
	return &LocalWriteOnceArchive{dir: dir, signer: signer, verifier: verifier, maxObjectBytes: maxObjectBytes}, nil
}
func (a *LocalWriteOnceArchive) Put(ctx context.Context, name string, r io.Reader) (ArchiveReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	clean, err := safeArchiveName(name)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	obj := filepath.Join(a.dir, "objects", clean)
	receiptPath := filepath.Join(a.dir, "receipts", clean+".json")
	if _, err = os.Stat(obj); err == nil {
		if _, receiptErr := os.Stat(receiptPath); receiptErr == nil {
			return a.verifyLocked(ctx, clean)
		} else if !errors.Is(receiptErr, os.ErrNotExist) {
			return ArchiveReceipt{}, receiptErr
		}
		// Recover the narrow crash window where the immutable object was linked
		// and fsynced but its signed receipt was not yet written. The caller's
		// intended bytes must exactly match the existing object before signing.
		expectedHash, expectedSize, hashErr := hashArchiveReader(r, a.maxObjectBytes)
		if hashErr != nil {
			return ArchiveReceipt{}, hashErr
		}
		return a.signExistingObjectLocked(ctx, clean, expectedSize, expectedHash)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ArchiveReceipt{}, err
	}
	if err = os.MkdirAll(filepath.Dir(obj), 0700); err != nil {
		return ArchiveReceipt{}, err
	}
	if err = os.MkdirAll(filepath.Dir(receiptPath), 0700); err != nil {
		return ArchiveReceipt{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(obj), ".archive-*")
	if err != nil {
		return ArchiveReceipt{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, a.maxObjectBytes+1))
	if err == nil && n > a.maxObjectBytes {
		err = errors.New("zlog: archive object exceeds configured limit")
	}
	if err == nil {
		err = tmp.Sync()
	}
	ce := tmp.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return ArchiveReceipt{}, err
	}
	if err = os.Link(tmpName, obj); err != nil {
		if errors.Is(err, os.ErrExist) {
			return a.signExistingObjectLocked(ctx, clean, n, h.Sum(nil))
		}
		return ArchiveReceipt{}, err
	}
	_ = os.Chmod(obj, 0400)
	sum := h.Sum(nil)
	receipt := ArchiveReceipt{Version: ArchiveReceiptVersion, ObjectName: clean, Size: n, SHA256: hex.EncodeToString(sum), ArchivedAt: time.Now().UTC().Format(time.RFC3339Nano), SignerKeyID: a.signer.KeyID(), SignatureAlgorithm: a.signer.Algorithm()}
	payload, err := CanonicalJSON(receipt.signingPayload())
	if err != nil {
		return ArchiveReceipt{}, err
	}
	sig, err := a.signer.Sign(ctx, payload)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	receipt.Signature = signatureB64(sig)
	b, err := CanonicalJSON(receipt)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	b = append(b, '\n')
	if err = writeNewFile(receiptPath, b, 0400); err != nil {
		return ArchiveReceipt{}, err
	}
	return receipt, nil
}

func hashArchiveReader(r io.Reader, max int64) ([]byte, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, max+1))
	if err != nil {
		return nil, 0, err
	}
	if n > max {
		return nil, 0, errors.New("zlog: archive object exceeds configured limit")
	}
	return h.Sum(nil), n, nil
}

func (a *LocalWriteOnceArchive) signExistingObjectLocked(ctx context.Context, clean string, expectedSize int64, expectedHash []byte) (ArchiveReceipt, error) {
	obj := filepath.Join(a.dir, "objects", clean)
	f, err := os.Open(obj)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(h, f)
	closeErr := f.Close()
	if copyErr != nil {
		return ArchiveReceipt{}, copyErr
	}
	if closeErr != nil {
		return ArchiveReceipt{}, closeErr
	}
	actualHash := h.Sum(nil)
	if n != expectedSize || !hmac.Equal(actualHash, expectedHash) {
		return ArchiveReceipt{}, errors.New("zlog: existing archive object differs from requested content")
	}
	receipt := ArchiveReceipt{Version: ArchiveReceiptVersion, ObjectName: clean, Size: n, SHA256: hex.EncodeToString(actualHash), ArchivedAt: time.Now().UTC().Format(time.RFC3339Nano), SignerKeyID: a.signer.KeyID(), SignatureAlgorithm: a.signer.Algorithm()}
	payload, err := CanonicalJSON(receipt.signingPayload())
	if err != nil {
		return ArchiveReceipt{}, err
	}
	sig, err := a.signer.Sign(ctx, payload)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	receipt.Signature = signatureB64(sig)
	b, err := CanonicalJSON(receipt)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	b = append(b, '\n')
	receiptPath := filepath.Join(a.dir, "receipts", clean+".json")
	if err = os.MkdirAll(filepath.Dir(receiptPath), 0700); err != nil {
		return ArchiveReceipt{}, err
	}
	if err = writeNewFile(receiptPath, b, 0400); err != nil {
		if errors.Is(err, os.ErrExist) {
			return a.verifyLocked(ctx, clean)
		}
		return ArchiveReceipt{}, err
	}
	return receipt, nil
}
func (a *LocalWriteOnceArchive) Verify(ctx context.Context, name string) (ArchiveReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	clean, err := safeArchiveName(name)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	return a.verifyLocked(ctx, clean)
}
func (a *LocalWriteOnceArchive) verifyLocked(ctx context.Context, clean string) (ArchiveReceipt, error) {
	b, err := os.ReadFile(filepath.Join(a.dir, "receipts", clean+".json"))
	if err != nil {
		return ArchiveReceipt{}, err
	}
	var receipt ArchiveReceipt
	if err = strictUnmarshal(b, &receipt); err != nil {
		return ArchiveReceipt{}, err
	}
	if receipt.Version != ArchiveReceiptVersion || receipt.ObjectName != clean {
		return ArchiveReceipt{}, errors.New("zlog: archive receipt identity mismatch")
	}
	payload, err := CanonicalJSON(receipt.signingPayload())
	if err != nil {
		return ArchiveReceipt{}, err
	}
	sig, err := decodeSignature(receipt.Signature)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	if err = a.verifier.VerifySignature(ctx, receipt.SignerKeyID, receipt.SignatureAlgorithm, payload, sig); err != nil {
		return ArchiveReceipt{}, err
	}
	f, err := os.Open(filepath.Join(a.dir, "objects", clean))
	if err != nil {
		return ArchiveReceipt{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	expected, err := decodeHash32(receipt.SHA256)
	if err != nil {
		return ArchiveReceipt{}, err
	}
	sum := h.Sum(nil)
	if n != receipt.Size || subtle.ConstantTimeCompare(sum, expected[:]) != 1 {
		return ArchiveReceipt{}, errors.New("zlog: archived object does not match signed receipt")
	}
	return receipt, nil
}
func safeArchiveName(name string) (string, error) {
	name = filepath.ToSlash(strings.TrimSpace(name))
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean == "." || clean == "" || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") || strings.Contains(clean, "\\") {
		return "", errors.New("zlog: unsafe archive object name")
	}
	return clean, nil
}
func writeNewFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	_, we := f.Write(data)
	if we == nil {
		we = f.Sync()
	}
	ce := f.Close()
	if we != nil {
		return we
	}
	return ce
}

type SegmentArchiveResult struct {
	SegmentID  uint64         `json:"segment_id"`
	ObjectName string         `json:"object_name"`
	Receipt    ArchiveReceipt `json:"receipt"`
}

func ArchiveSealedSegments(ctx context.Context, store *SecureAuditStore, archive ImmutableArchive) ([]SegmentArchiveResult, error) {
	if store == nil || archive == nil {
		return nil, errors.New("zlog: store and archive are required")
	}
	store.mu.RLock()
	dir := store.opts.Dir
	stream := store.opts.StreamID
	store.mu.RUnlock()
	files, err := segmentFiles(dir)
	if err != nil {
		return nil, err
	}
	var out []SegmentArchiveResult
	for _, file := range files {
		sealed, err := segmentFileSealed(file)
		if err != nil {
			return out, err
		}
		if !sealed {
			continue
		}
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		f, err := os.Open(file)
		if err != nil {
			return out, err
		}
		id := segmentIDFromPath(file)
		name := fmt.Sprintf("%s/segments/%020d.zseg", sanitizeFilePart(stream), id)
		receipt, putErr := archive.Put(ctx, name, f)
		_ = f.Close()
		if putErr != nil {
			return out, putErr
		}
		out = append(out, SegmentArchiveResult{SegmentID: id, ObjectName: name, Receipt: receipt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SegmentID < out[j].SegmentID })
	return out, nil
}
func segmentFileSealed(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	last := ""
	for sc.Scan() {
		last = string(sc.Bytes())
	}
	if err = sc.Err(); err != nil {
		return false, err
	}
	if last == "" {
		return false, nil
	}
	var dl segmentDiskLine
	if err = json.Unmarshal([]byte(last), &dl); err != nil {
		return false, err
	}
	return dl.Type == "trailer" && dl.Trailer != nil, nil
}
