package zlog

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestContextAndSpanLogging(t *testing.T) {
	var out bytes.Buffer
	log := New(Options{Level: DebugLevel, Sink: NewWriterSink(&out, NewJSONEncoder(), TraceLevel), DisableRedaction: true})
	ctx := ContextWithRequestID(context.Background(), "req-1")
	ctx = ContextWithUserID(ctx, "user-1")
	ctx = ContextWithService(ctx, "billing", "1.2.3", "test")
	ctx = ContextWithTool(ctx, "email_sender", "tool-call-1")
	ctx, span := log.StartSpan(ctx, "send.email", WithSpanKind(SpanKindTool), WithSpanStartEvent(true))
	log.InfoContext(ctx, "inside", String("step", "compose"))
	span.End(String("outcome", "success"))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 log lines, got %d: %s", len(lines), out.String())
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &m); err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"request_id":   "req-1",
		"user_id":      "user-1",
		"service.name": "billing",
		"tool.name":    "email_sender",
		"tool.call_id": "tool-call-1",
		"span.name":    "send.email",
		"span.kind":    "tool",
	}
	for k, want := range checks {
		if got := m[k]; got != want {
			t.Fatalf("%s = %v, want %s in %#v", k, got, want, m)
		}
	}
	if m["trace_id"] == "" || m["span_id"] == "" {
		t.Fatalf("missing trace/span ids: %#v", m)
	}
}

func TestQueryContextFieldsAndSort(t *testing.T) {
	input := strings.NewReader(`{"time":"2026-01-01T00:00:02Z","level":"info","message":"b","request_id":"r1","trace_id":"t1","span.duration":20,"user_id":"u1","service.name":"api","tool.name":"sms"}
{"time":"2026-01-01T00:00:01Z","level":"info","message":"a","request_id":"r1","trace_id":"t1","span.duration":10,"user_id":"u1","service.name":"api","tool.name":"sms"}
{"time":"2026-01-01T00:00:03Z","level":"info","message":"c","request_id":"r2","trace_id":"t2","span.duration":30,"user_id":"u2","service.name":"worker","tool.name":"email"}
`)
	var out bytes.Buffer
	err := QueryNDJSON(input, &out, QueryOptions{RequestID: "r1", UserID: "u1", Service: "api", Tool: "sms", SortBy: "time"})
	if err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, `"message":"a"`) || !strings.Contains(got, `"message":"b"`) || strings.Contains(got, `"message":"c"`) {
		t.Fatalf("unexpected query result: %s", got)
	}
	if strings.Index(got, `"message":"a"`) > strings.Index(got, `"message":"b"`) {
		t.Fatalf("expected sorted by time asc: %s", got)
	}
}
