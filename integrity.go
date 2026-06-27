package zlog

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
)

// IntegritySigner creates a tamper-evident HMAC hash chain. Use it for audit
// and compliance sinks when you need to prove order/integrity of local logs.
type IntegritySigner struct {
	mu   sync.Mutex
	key  []byte
	prev [32]byte
}

func NewIntegritySigner(key []byte) *IntegritySigner {
	cp := append([]byte(nil), key...)
	return &IntegritySigner{key: cp}
}

func (s *IntegritySigner) Sign(attrs ...Attr) Attr {
	r := Record{}
	r.SetAttrs(attrs)
	return s.SignRecord(r, nil)
}

func (s *IntegritySigner) SignRecord(r Record, static []Attr) Attr {
	s.mu.Lock()
	defer s.mu.Unlock()
	mac := hmac.New(sha256.New, s.key)
	mac.Write(s.prev[:])
	var buf bytes.Buffer
	enc := NewJSONEncoder()
	enc.Newline = false
	_ = enc.Encode(&buf, r, static)
	mac.Write(buf.Bytes())
	sum := mac.Sum(nil)
	copy(s.prev[:], sum)
	return String("log.integrity.hmac", hex.EncodeToString(sum))
}

type hashWriter interface{ Write([]byte) (int, error) }

func writeAttrMAC(w hashWriter, a Attr) {
	if a.Kind == KindInvalid {
		return
	}
	_, _ = w.Write([]byte(a.Key))
	_, _ = w.Write([]byte{0})
	switch a.Kind {
	case KindString, KindError:
		_, _ = w.Write([]byte(a.Str))
	case KindBytes, KindRawJSON:
		_, _ = w.Write(a.Bytes)
	case KindGroup:
		for i := range a.Group {
			writeAttrMAC(w, a.Group[i])
		}
	default:
		_, _ = w.Write([]byte(strconv.FormatInt(a.I64, 10)))
		_, _ = w.Write([]byte(strconv.FormatUint(a.U64, 10)))
	}
	_, _ = w.Write([]byte{0})
}
