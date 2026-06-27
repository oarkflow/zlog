package zlog

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestObservabilityStoreFiltersServicesAndPrometheus(t *testing.T) {
	store := NewObservabilityStore(ObservabilityOptions{MaxLogs: 10, MaxSpans: 10, MaxMetrics: 10})
	store.RecordLog(ObsLog{Time: time.Now(), Level: "info", Message: "ok", Service: "api", Node: "n1", RequestID: "r1", TraceID: "t1", UserID: "u1"})
	store.RecordLog(ObsLog{Time: time.Now(), Level: "error", Message: "bad", Service: "api", Node: "n1", RequestID: "r2", TraceID: "t2", UserID: "u2"})
	store.RecordSpan(ObsSpan{TraceID: "t2", SpanID: "s1", Name: "handle", Service: "api", Node: "n1", Start: time.Now(), DurationNS: int64(25 * time.Millisecond), Status: "error"})
	logs := store.QueryLogs(ObsQuery{Service: "api", Level: "error"})
	if len(logs) != 1 || logs[0].RequestID != "r2" {
		t.Fatalf("unexpected logs: %#v", logs)
	}
	svcs := store.Services()
	if len(svcs) != 1 || svcs[0].ErrorCount < 2 || svcs[0].P95LatencyNS == 0 {
		t.Fatalf("unexpected service summary: %#v", svcs)
	}
	n, err := ParsePrometheusText(context.Background(), strings.NewReader(`http_requests_total{service="api",node="n1"} 42
cpu_usage_percent 12.5
`), "", "", store.RecordMetric)
	if err != nil || n != 2 {
		t.Fatalf("prom parse n=%d err=%v", n, err)
	}
	ms := store.QueryMetrics(ObsQuery{Name: "http_requests_total", Service: "api"})
	if len(ms) != 1 || ms[0].Value != 42 {
		t.Fatalf("unexpected metric: %#v", ms)
	}
}

func TestObservabilityHandlerIngestAndUI(t *testing.T) {
	store := NewObservabilityStore(ObservabilityOptions{})
	h := NewObservabilityHandler(store)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/logs", bytes.NewBufferString(`{"time":"2026-01-01T00:00:00Z","level":"info","message":"hello","service":"api","request_id":"r1"}`))
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := store.QueryLogs(ObsQuery{RequestID: "r1"}); len(got) != 1 {
		t.Fatalf("expected ingested log, got %#v", got)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	body := rr.Body.String()
	if rr.Code != 200 || !strings.Contains(body, "zlog Observability") {
		t.Fatalf("ui not served: %d", rr.Code)
	}
	for _, want := range []string{"openDetails", "data-json", "Related data", "routeHash", "drawer", "showTip(e"} {
		if !strings.Contains(body, want) {
			t.Fatalf("ui missing interactive behavior %q", want)
		}
	}
}

func TestObservabilitySinkCapturesSpan(t *testing.T) {
	store := NewObservabilityStore(ObservabilityOptions{})
	l := New(Options{Level: DebugLevel, Sink: NewObservabilitySink(store, nil), Static: []Attr{ServiceName("api"), String("node.name", "n1")}})
	ctx := ContextWithRequestID(context.Background(), "r1")
	ctx, sp := l.StartSpan(ctx, "work", WithSpanStartEvent(true))
	l.InfoContext(ctx, "inside")
	sp.End()
	if len(store.QueryLogs(ObsQuery{RequestID: "r1"})) != 3 {
		t.Fatalf("expected span start, inside, span end logs")
	}
	if len(store.QuerySpans(ObsQuery{Name: "work"})) == 0 {
		t.Fatalf("expected captured span")
	}
}
