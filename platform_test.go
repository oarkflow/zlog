package zlog

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestSlogWithGroup(t *testing.T) {
	cap := NewCaptureSink()
	l := New(Options{Level: DebugLevel, Sink: cap, DisableRedaction: true})
	s := slog.New(l.SlogHandler()).WithGroup("request")
	s.Info("hello", "id", "r1")
	if len(cap.Records) != 1 {
		t.Fatalf("expected one record")
	}
	a := cap.Records[0].AttrAt(0)
	if a.Key != "request" || a.Kind != KindGroup || len(a.Group) != 1 || a.Group[0].Key != "id" {
		t.Fatalf("group not preserved: %#v", a)
	}
}

func TestIntegrityVerifyRecords(t *testing.T) {
	key := []byte("secret")
	signer := NewIntegritySigner(key)
	r1 := Record{Level: InfoLevel, Message: "a", Sequence: 1}
	r1.SetAttrs([]Attr{String("k", "v")})
	r1.AddAttr(signer.SignRecord(r1, nil))
	rep := VerifyIntegrityRecords([]Record{r1}, nil, key)
	if rep.Invalid != 0 || rep.Valid != 1 {
		t.Fatalf("bad report: %#v", rep)
	}
	r1.Message = "tampered"
	rep = VerifyIntegrityRecords([]Record{r1}, nil, key)
	if rep.Invalid != 1 {
		t.Fatalf("expected invalid report: %#v", rep)
	}
}

func TestQueryNDJSON(t *testing.T) {
	in := bytes.NewBufferString(`{"level":"INFO","message":"ok","tenant":"a"}` + "\n" + `{"level":"ERROR","message":"bad","tenant":"b"}` + "\n")
	var out bytes.Buffer
	if err := QueryNDJSON(in, &out, QueryOptions{Level: "error"}); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &m); err != nil {
		t.Fatal(err)
	}
	if m["message"] != "bad" {
		t.Fatalf("unexpected query output: %s", out.String())
	}
}
