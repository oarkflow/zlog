package zlog

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONAndRedaction(t *testing.T) {
	var b bytes.Buffer
	log := New(Options{Level: DebugLevel, Sink: NewWriterSink(&b, NewJSONEncoder(), TraceLevel)})
	log.Info("login", String("user", "a"), String("password", "secret"))
	if !json.Valid(b.Bytes()) {
		t.Fatalf("invalid json: %s", b.String())
	}
	if strings.Contains(b.String(), "secret") {
		t.Fatalf("secret leaked: %s", b.String())
	}
	if !strings.Contains(b.String(), "[REDACTED]") {
		t.Fatalf("missing redaction: %s", b.String())
	}
}
func TestLevelDisabled(t *testing.T) {
	var b bytes.Buffer
	log := New(Options{Level: ErrorLevel, Sink: NewWriterSink(&b, NewJSONEncoder(), TraceLevel)})
	log.Info("skip")
	if b.Len() != 0 {
		t.Fatalf("expected no log, got %s", b.String())
	}
}
func TestMultiSink(t *testing.T) {
	var a, b bytes.Buffer
	log := New(Options{Level: InfoLevel, Sink: NewMultiSink(NewWriterSink(&a, NewJSONEncoder(), TraceLevel), NewWriterSink(&b, NewLogfmtEncoder(), TraceLevel))})
	log.Info("x", Int("n", 1))
	if a.Len() == 0 || b.Len() == 0 {
		t.Fatal("both sinks should receive logs")
	}
}
func TestAsyncClose(t *testing.T) {
	var b bytes.Buffer
	sink := NewWriterSink(&b, NewJSONEncoder(), TraceLevel)
	log := New(Options{Level: InfoLevel, Sink: sink, Async: true, AsyncOptions: AsyncOptions{Capacity: 8, DropPolicy: DropBlock}})
	for i := 0; i < 10; i++ {
		log.Info("x", Int("i", i))
	}
	_ = log.Close()
	if b.Len() == 0 {
		t.Fatal("expected drained logs")
	}
}

func TestValueRedaction(t *testing.T) {
	var b bytes.Buffer
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(&b, NewJSONEncoder(), TraceLevel)})
	log.Info("auth", String("header", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue"))
	if strings.Contains(b.String(), "eyJhbGci") || strings.Contains(b.String(), "Bearer ") {
		t.Fatalf("secret-like value leaked: %s", b.String())
	}
}

func TestAsyncFlushDrains(t *testing.T) {
	var b bytes.Buffer
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(&b, NewJSONEncoder(), TraceLevel), Async: true, AsyncOptions: AsyncOptions{Capacity: 64, DropPolicy: DropBlock}})
	log.Info("flush.required", String("k", "v"))
	if err := log.Flush(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "flush.required") {
		t.Fatalf("flush did not drain async queue: %s", b.String())
	}
	_ = log.Close()
}

func TestIntegritySigning(t *testing.T) {
	var b bytes.Buffer
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(&b, NewJSONEncoder(), TraceLevel), IntegrityKey: []byte("test-key")})
	log.Info("signed", String("k", "v"))
	if !strings.Contains(b.String(), "log.integrity.hmac") {
		t.Fatalf("missing integrity hmac: %s", b.String())
	}
}
