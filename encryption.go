package zlog

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

type EncryptedFileOptions struct {
	Path      string
	Key       []byte
	KeyID     string
	Encoder   Encoder
	Level     Level
	Perm      os.FileMode
	Redactor  Redactor
	SyncWrite bool
}

type EncryptedFileSink struct {
	f        *os.File
	enc      Encoder
	level    Level
	gcm      cipher.AEAD
	keyID    string
	sync     bool
	redactor Redactor
	stats    sinkCounters
}

type encryptedLine struct {
	Version string `json:"v"`
	Alg     string `json:"alg"`
	KeyID   string `json:"kid,omitempty"`
	Nonce   string `json:"nonce"`
	Data    string `json:"data"`
	Time    string `json:"time,omitempty"`
}

func NewEncryptedFileSink(opts EncryptedFileOptions) (*EncryptedFileSink, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("encrypted file path required")
	}
	if len(opts.Key) == 0 {
		return nil, fmt.Errorf("encryption key required")
	}
	key := normalizeAESKey(opts.Key)
	block, err := aes.NewCipher(key)
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
	return &EncryptedFileSink{f: f, enc: enc, level: opts.Level, gcm: gcm, keyID: opts.KeyID, sync: opts.SyncWrite, redactor: red}, nil
}
func normalizeAESKey(key []byte) []byte {
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
		s.stats.failed.Add(1)
		s.stats.last.Store(err.Error())
		return err
	}
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := s.gcm.Seal(nil, nonce, plain.Bytes(), nil)
	line, err := json.Marshal(encryptedLine{Version: "1", Alg: "AES-GCM", KeyID: s.keyID, Nonce: base64.StdEncoding.EncodeToString(nonce), Data: base64.StdEncoding.EncodeToString(sealed), Time: time.Now().Format(time.RFC3339Nano)})
	if err != nil {
		return err
	}
	line = append(line, '\n')
	n, err := s.f.Write(line)
	if err != nil {
		s.stats.failed.Add(1)
		s.stats.last.Store(err.Error())
		return err
	}
	if s.sync {
		_ = s.f.Sync()
	}
	s.stats.written.Add(1)
	s.stats.bytes.Add(uint64(n))
	return nil
}
func (s *EncryptedFileSink) Flush() error {
	if s.f != nil {
		return s.f.Sync()
	}
	return nil
}
func (s *EncryptedFileSink) Close() error {
	if s.f != nil {
		_ = s.Flush()
		return s.f.Close()
	}
	return nil
}
func (s *EncryptedFileSink) Stats() SinkStats {
	st := SinkStats{Written: s.stats.written.Load(), Failed: s.stats.failed.Load(), Bytes: s.stats.bytes.Load()}
	if v := s.stats.last.Load(); v != nil {
		st.LastError = v.(string)
	}
	return st
}

func DecryptEncryptedLogFile(r io.Reader, w io.Writer, key []byte) error {
	block, err := aes.NewCipher(normalizeAESKey(key))
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		var line encryptedLine
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			return err
		}
		nonce, err := base64.StdEncoding.DecodeString(line.Nonce)
		if err != nil {
			return err
		}
		data, err := base64.StdEncoding.DecodeString(line.Data)
		if err != nil {
			return err
		}
		plain, err := gcm.Open(nil, nonce, data, nil)
		if err != nil {
			return err
		}
		if len(plain) == 0 || plain[len(plain)-1] != '\n' {
			plain = append(plain, '\n')
		}
		if _, err := w.Write(plain); err != nil {
			return err
		}
	}
	return sc.Err()
}
