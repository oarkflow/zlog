package zlog

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type EncryptedFileOptions struct {
	Path string
	// Key is a raw AES-256 key when exactly 32 bytes. For compatibility, any
	// other non-empty length is treated as a passphrase and processed with
	// PBKDF2-HMAC-SHA-256 instead of the previous insecure single SHA-256 step.
	Key              []byte
	Passphrase       []byte
	KeyID            string
	Encoder          Encoder
	Level            Level
	Perm             os.FileMode
	Redactor         Redactor
	SyncWrite        bool
	PBKDF2Iterations int
	MaxRecordBytes   int
}

type EncryptedFileSink struct {
	mu             sync.Mutex
	f              *os.File
	enc            Encoder
	level          Level
	gcm            cipher.AEAD
	keyID          string
	sync           bool
	redactor       Redactor
	stats          sinkCounters
	kdf            string
	salt           []byte
	iterations     int
	noncePrefix    [8]byte
	nonceCounter   uint32
	closed         bool
	maxRecordBytes int
}

type encryptedLine struct {
	Version    string `json:"v"`
	Alg        string `json:"alg"`
	KeyID      string `json:"kid,omitempty"`
	KDF        string `json:"kdf,omitempty"`
	Salt       string `json:"salt,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
	Sequence   uint64 `json:"sequence,omitempty"`
	Nonce      string `json:"nonce"`
	Data       string `json:"data"`
	Time       string `json:"time,omitempty"`
}

func NewEncryptedFileSink(opts EncryptedFileOptions) (*EncryptedFileSink, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("encrypted file path required")
	}
	if len(opts.Key) > 0 && len(opts.Passphrase) > 0 {
		return nil, errors.New("zlog: specify either Key or Passphrase, not both")
	}
	if len(opts.Key) == 0 && len(opts.Passphrase) == 0 {
		return nil, fmt.Errorf("encryption key or passphrase required")
	}
	iterations := opts.PBKDF2Iterations
	if iterations == 0 {
		iterations = 600000
	}
	if iterations < 100000 {
		return nil, errors.New("zlog: PBKDF2 iterations must be at least 100000")
	}
	maxRecordBytes := opts.MaxRecordBytes
	if maxRecordBytes == 0 {
		maxRecordBytes = 4 << 20
	}
	if maxRecordBytes < 1024 {
		return nil, errors.New("zlog: encrypted file max record bytes must be at least 1024")
	}
	var key []byte
	var kdf string
	var salt []byte
	switch {
	case len(opts.Key) == 32:
		key = append([]byte(nil), opts.Key...)
	case len(opts.Passphrase) > 0:
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		key = pbkdf2SHA256(opts.Passphrase, salt, iterations, 32)
		kdf = "PBKDF2-HMAC-SHA256"
	default:
		// Backward-compatible call shape, but secure derivation.
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		key = pbkdf2SHA256(opts.Key, salt, iterations, 32)
		kdf = "PBKDF2-HMAC-SHA256"
	}
	block, err := aes.NewCipher(key)
	zeroBytes(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	perm := opts.Perm
	if perm == 0 {
		perm = 0600
	}
	f, err := os.OpenFile(opts.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, perm)
	if err != nil {
		return nil, err
	}
	enc := opts.Encoder
	if enc == nil {
		enc = NewJSONEncoder()
	}
	red := opts.Redactor
	if red.isZero() {
		red = DefaultRedactor().normalized()
	}
	s := &EncryptedFileSink{f: f, enc: enc, level: opts.Level, gcm: gcm, keyID: opts.KeyID, sync: opts.SyncWrite, redactor: red, kdf: kdf, salt: salt, iterations: iterations, maxRecordBytes: maxRecordBytes}
	if _, err = rand.Read(s.noncePrefix[:]); err != nil {
		_ = f.Close()
		return nil, err
	}
	return s, nil
}

func normalizeAESKey(key []byte) []byte { // retained only for v1 decryption compatibility
	if len(key) == 16 || len(key) == 24 || len(key) == 32 {
		return key
	}
	h := sha256.Sum256(key)
	return h[:]
}

func (s *EncryptedFileSink) WriteRecord(r Record, static []Attr) error {
	if r.Level < s.level {
		return nil
	}
	if s.redactor.Enabled && !r.Redacted {
		r.Redact(s.redactor)
	}
	var plain bytes.Buffer
	if err := s.enc.Encode(&plain, r, static); err != nil {
		s.recordFailure(err)
		return err
	}
	if plain.Len() > s.maxRecordBytes {
		err := fmt.Errorf("zlog: encrypted record exceeds %d bytes", s.maxRecordBytes)
		s.recordFailure(err)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrAuditStoreClosed
	}
	if s.nonceCounter == ^uint32(0) {
		return errors.New("zlog: encrypted file nonce space exhausted; rotate sink")
	}
	s.nonceCounter++
	nonce := make([]byte, s.gcm.NonceSize())
	if len(nonce) != 12 {
		return errors.New("zlog: unexpected GCM nonce size")
	}
	copy(nonce[:8], s.noncePrefix[:])
	binary.BigEndian.PutUint32(nonce[8:], s.nonceCounter)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	line := encryptedLine{Version: "2", Alg: "AES-256-GCM", KeyID: s.keyID, KDF: s.kdf, Iterations: 0, Sequence: uint64(s.nonceCounter), Nonce: base64.RawStdEncoding.EncodeToString(nonce), Time: timestamp}
	if len(s.salt) > 0 {
		line.Salt = base64.RawStdEncoding.EncodeToString(s.salt)
		line.Iterations = s.iterations
	}
	aad, err := encryptedLineAAD(line)
	if err != nil {
		s.recordFailure(err)
		return err
	}
	sealed := s.gcm.Seal(nil, nonce, plain.Bytes(), aad)
	line.Data = base64.RawStdEncoding.EncodeToString(sealed)
	encoded, err := json.Marshal(line)
	if err != nil {
		s.recordFailure(err)
		return err
	}
	encoded = append(encoded, '\n')
	n, err := s.f.Write(encoded)
	if err == nil && n != len(encoded) {
		err = io.ErrShortWrite
	}
	if err == nil && s.sync {
		err = s.f.Sync()
	}
	if err != nil {
		s.recordFailure(err)
		return err
	}
	s.stats.written.Add(1)
	s.stats.bytes.Add(uint64(n))
	return nil
}
func encryptedLineAAD(line encryptedLine) ([]byte, error) { line.Data = ""; return CanonicalJSON(line) }
func (s *EncryptedFileSink) recordFailure(err error) {
	s.stats.failed.Add(1)
	s.stats.last.Store(err.Error())
}
func (s *EncryptedFileSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	return s.f.Sync()
}
func (s *EncryptedFileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.f != nil {
		err = s.f.Sync()
		if e := s.f.Close(); err == nil {
			err = e
		}
	}
	zeroBytes(s.salt)
	return err
}
func (s *EncryptedFileSink) Stats() SinkStats {
	st := SinkStats{Written: s.stats.written.Load(), Failed: s.stats.failed.Load(), Bytes: s.stats.bytes.Load()}
	if v := s.stats.last.Load(); v != nil {
		st.LastError = v.(string)
	}
	return st
}

func DecryptEncryptedLogFile(r io.Reader, w io.Writer, keyOrPassphrase []byte) error {
	if len(keyOrPassphrase) == 0 {
		return errors.New("zlog: decryption key or passphrase required")
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 32<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		var line encryptedLine
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			return fmt.Errorf("zlog: encrypted line %d: %w", lineNo, err)
		}
		var key []byte
		var legacy bool
		switch line.Version {
		case "1":
			key = append([]byte(nil), normalizeAESKey(keyOrPassphrase)...)
			legacy = true
		case "2":
			if line.Alg != "AES-256-GCM" {
				return fmt.Errorf("zlog: unsupported encryption algorithm %q", line.Alg)
			}
			if line.KDF == "" {
				if len(keyOrPassphrase) != 32 {
					return errors.New("zlog: v2 raw AES key must be exactly 32 bytes")
				}
				key = append([]byte(nil), keyOrPassphrase...)
			} else if line.KDF == "PBKDF2-HMAC-SHA256" {
				if line.Iterations < 100000 {
					return errors.New("zlog: unsafe PBKDF2 iteration count")
				}
				salt, err := base64.RawStdEncoding.DecodeString(line.Salt)
				if err != nil || len(salt) < 16 {
					return errors.New("zlog: invalid PBKDF2 salt")
				}
				key = pbkdf2SHA256(keyOrPassphrase, salt, line.Iterations, 32)
			} else {
				return fmt.Errorf("zlog: unsupported KDF %q", line.KDF)
			}
		default:
			return fmt.Errorf("zlog: unsupported encrypted log version %q", line.Version)
		}
		block, err := aes.NewCipher(key)
		zeroBytes(key)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		nonce, err := decodeBase64Any(line.Nonce)
		if err != nil || len(nonce) != gcm.NonceSize() {
			return fmt.Errorf("zlog: invalid nonce on line %d", lineNo)
		}
		data, err := decodeBase64Any(line.Data)
		if err != nil {
			return err
		}
		var aad []byte
		if !legacy {
			aad, err = encryptedLineAAD(line)
			if err != nil {
				return err
			}
		}
		plain, err := gcm.Open(nil, nonce, data, aad)
		if err != nil {
			return fmt.Errorf("zlog: decrypt line %d: %w", lineNo, err)
		}
		if len(plain) == 0 || plain[len(plain)-1] != '\n' {
			plain = append(plain, '\n')
		}
		if _, err = w.Write(plain); err != nil {
			return err
		}
	}
	return sc.Err()
}

func decodeBase64Any(s string) ([]byte, error) {
	if b, e := base64.RawStdEncoding.DecodeString(s); e == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	if iterations < 1 {
		panic("invalid PBKDF2 iterations")
	}
	hLen := 32
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	var ibuf [4]byte
	for i := 1; i <= blocks; i++ {
		binary.BigEndian.PutUint32(ibuf[:], uint32(i))
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		_, _ = mac.Write(ibuf[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for j := 1; j < iterations; j++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(u[:0])
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
		zeroBytes(u)
		zeroBytes(t)
	}
	return out[:keyLen]
}
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
