package zlog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ObsLog is the normalized log event used by the built-in observability store and UI.
type ObsLog struct {
	Time          time.Time      `json:"time"`
	Level         string         `json:"level"`
	Message       string         `json:"message"`
	Logger        string         `json:"logger,omitempty"`
	Service       string         `json:"service,omitempty"`
	ServiceVer    string         `json:"service_version,omitempty"`
	Environment   string         `json:"environment,omitempty"`
	Node          string         `json:"node,omitempty"`
	Instance      string         `json:"instance,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	TraceID       string         `json:"trace_id,omitempty"`
	SpanID        string         `json:"span_id,omitempty"`
	ParentSpanID  string         `json:"parent_span_id,omitempty"`
	UserID        string         `json:"user_id,omitempty"`
	TenantID      string         `json:"tenant_id,omitempty"`
	Tool          string         `json:"tool,omitempty"`
	WorkflowID    string         `json:"workflow_id,omitempty"`
	TaskID        string         `json:"task_id,omitempty"`
	Attrs         map[string]any `json:"attrs,omitempty"`
}

// ObsSpan is a normalized trace/span event.
type ObsSpan struct {
	TraceID      string         `json:"trace_id"`
	SpanID       string         `json:"span_id"`
	ParentSpanID string         `json:"parent_span_id,omitempty"`
	Name         string         `json:"name"`
	Kind         string         `json:"kind,omitempty"`
	Service      string         `json:"service,omitempty"`
	Node         string         `json:"node,omitempty"`
	Instance     string         `json:"instance,omitempty"`
	UserID       string         `json:"user_id,omitempty"`
	TenantID     string         `json:"tenant_id,omitempty"`
	Tool         string         `json:"tool,omitempty"`
	WorkflowID   string         `json:"workflow_id,omitempty"`
	TaskID       string         `json:"task_id,omitempty"`
	Start        time.Time      `json:"start"`
	End          time.Time      `json:"end,omitempty"`
	DurationNS   int64          `json:"duration_ns,omitempty"`
	Status       string         `json:"status,omitempty"`
	Error        string         `json:"error,omitempty"`
	Attrs        map[string]any `json:"attrs,omitempty"`
}

// ObsMetric is a normalized service/node metric sample.
type ObsMetric struct {
	Time     time.Time         `json:"time"`
	Name     string            `json:"name"`
	Value    float64           `json:"value"`
	Type     string            `json:"type,omitempty"`
	Unit     string            `json:"unit,omitempty"`
	Service  string            `json:"service,omitempty"`
	Node     string            `json:"node,omitempty"`
	Instance string            `json:"instance,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type ObsServiceSummary struct {
	Service      string    `json:"service"`
	Node         string    `json:"node,omitempty"`
	Instance     string    `json:"instance,omitempty"`
	LogCount     int       `json:"log_count"`
	ErrorCount   int       `json:"error_count"`
	SpanCount    int       `json:"span_count"`
	MetricCount  int       `json:"metric_count"`
	P95LatencyNS int64     `json:"p95_latency_ns,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
}

type ObsQuery struct {
	Service       string
	Node          string
	Instance      string
	Level         string
	RequestID     string
	CorrelationID string
	TraceID       string
	SpanID        string
	UserID        string
	TenantID      string
	Tool          string
	WorkflowID    string
	TaskID        string
	Name          string
	Since         time.Duration
	Limit         int
	Sort          string
	Desc          bool
}

type ObservabilityStore struct {
	mu         sync.RWMutex
	maxLogs    int
	maxSpans   int
	maxMetrics int
	logs       []ObsLog
	spans      []ObsSpan
	metrics    []ObsMetric
}

type ObservabilityOptions struct{ MaxLogs, MaxSpans, MaxMetrics int }

func NewObservabilityStore(opts ObservabilityOptions) *ObservabilityStore {
	if opts.MaxLogs <= 0 {
		opts.MaxLogs = 50000
	}
	if opts.MaxSpans <= 0 {
		opts.MaxSpans = 50000
	}
	if opts.MaxMetrics <= 0 {
		opts.MaxMetrics = 100000
	}
	return &ObservabilityStore{maxLogs: opts.MaxLogs, maxSpans: opts.MaxSpans, maxMetrics: opts.MaxMetrics}
}

func (s *ObservabilityStore) RecordLog(l ObsLog) {
	if l.Time.IsZero() {
		l.Time = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, l)
	if len(s.logs) > s.maxLogs {
		copy(s.logs, s.logs[len(s.logs)-s.maxLogs:])
		s.logs = s.logs[:s.maxLogs]
	}
}
func (s *ObservabilityStore) RecordSpan(sp ObsSpan) {
	if sp.Start.IsZero() {
		sp.Start = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.spans = append(s.spans, sp)
	if len(s.spans) > s.maxSpans {
		copy(s.spans, s.spans[len(s.spans)-s.maxSpans:])
		s.spans = s.spans[:s.maxSpans]
	}
}
func (s *ObservabilityStore) RecordMetric(m ObsMetric) {
	if m.Time.IsZero() {
		m.Time = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metrics = append(s.metrics, m)
	if len(s.metrics) > s.maxMetrics {
		copy(s.metrics, s.metrics[len(s.metrics)-s.maxMetrics:])
		s.metrics = s.metrics[:s.maxMetrics]
	}
}

func (s *ObservabilityStore) QueryLogs(q ObsQuery) []ObsLog {
	s.mu.RLock()
	src := append([]ObsLog(nil), s.logs...)
	s.mu.RUnlock()
	cutoff := cutoffTime(q.Since)
	out := make([]ObsLog, 0, minInt(len(src), limitOf(q.Limit)))
	for _, l := range src {
		if matchLog(l, q, cutoff) {
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if q.Desc {
			return out[i].Time.After(out[j].Time)
		}
		return out[i].Time.Before(out[j].Time)
	})
	return trimLimit(out, q.Limit)
}
func (s *ObservabilityStore) QuerySpans(q ObsQuery) []ObsSpan {
	s.mu.RLock()
	src := append([]ObsSpan(nil), s.spans...)
	s.mu.RUnlock()
	cutoff := cutoffTime(q.Since)
	out := make([]ObsSpan, 0, minInt(len(src), limitOf(q.Limit)))
	for _, sp := range src {
		if matchSpan(sp, q, cutoff) {
			out = append(out, sp)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		switch q.Sort {
		case "duration", "duration_ns":
			if q.Desc {
				return out[i].DurationNS > out[j].DurationNS
			}
			return out[i].DurationNS < out[j].DurationNS
		}
		if q.Desc {
			return out[i].Start.After(out[j].Start)
		}
		return out[i].Start.Before(out[j].Start)
	})
	return trimLimit(out, q.Limit)
}
func (s *ObservabilityStore) QueryMetrics(q ObsQuery) []ObsMetric {
	s.mu.RLock()
	src := append([]ObsMetric(nil), s.metrics...)
	s.mu.RUnlock()
	cutoff := cutoffTime(q.Since)
	out := make([]ObsMetric, 0, minInt(len(src), limitOf(q.Limit)))
	for _, m := range src {
		if matchMetric(m, q, cutoff) {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if q.Desc {
			return out[i].Time.After(out[j].Time)
		}
		return out[i].Time.Before(out[j].Time)
	})
	return trimLimit(out, q.Limit)
}

func (s *ObservabilityStore) Services() []ObsServiceSummary {
	s.mu.RLock()
	logs := append([]ObsLog(nil), s.logs...)
	spans := append([]ObsSpan(nil), s.spans...)
	metrics := append([]ObsMetric(nil), s.metrics...)
	s.mu.RUnlock()
	by := map[string]*ObsServiceSummary{}
	key := func(service, node, inst string) string {
		if service == "" {
			service = "unknown"
		}
		return service + "\x00" + node + "\x00" + inst
	}
	durs := map[string][]int64{}
	touch := func(k, service, node, inst string, t time.Time) *ObsServiceSummary {
		ss := by[k]
		if ss == nil {
			ss = &ObsServiceSummary{Service: service, Node: node, Instance: inst}
			if ss.Service == "" {
				ss.Service = "unknown"
			}
			by[k] = ss
		}
		if t.After(ss.LastSeen) {
			ss.LastSeen = t
		}
		return ss
	}
	for _, l := range logs {
		ss := touch(key(l.Service, l.Node, l.Instance), l.Service, l.Node, l.Instance, l.Time)
		ss.LogCount++
		if isErrLevel(l.Level) {
			ss.ErrorCount++
		}
	}
	for _, sp := range spans {
		k := key(sp.Service, sp.Node, sp.Instance)
		ss := touch(k, sp.Service, sp.Node, sp.Instance, sp.Start)
		ss.SpanCount++
		if sp.DurationNS > 0 {
			durs[k] = append(durs[k], sp.DurationNS)
		}
		if strings.EqualFold(sp.Status, "error") {
			ss.ErrorCount++
		}
	}
	for _, m := range metrics {
		ss := touch(key(m.Service, m.Node, m.Instance), m.Service, m.Node, m.Instance, m.Time)
		ss.MetricCount++
	}
	out := make([]ObsServiceSummary, 0, len(by))
	for k, ss := range by {
		if ds := durs[k]; len(ds) > 0 {
			ss.P95LatencyNS = percentile(ds, .95)
		}
		out = append(out, *ss)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

func (s *ObservabilityStore) Overview() map[string]any {
	s.mu.RLock()
	logsN, spansN, metricsN := len(s.logs), len(s.spans), len(s.metrics)
	s.mu.RUnlock()
	services := s.Services()
	errN := 0
	for _, svc := range services {
		errN += svc.ErrorCount
	}
	return map[string]any{"logs": logsN, "spans": spansN, "metrics": metricsN, "services": len(services), "errors": errN, "service_summaries": services, "generated_at": time.Now()}
}

// ChartData returns ready-to-render aggregate data for the built-in observability UI.
// It intentionally returns plain JSON-friendly maps so external frontends can reuse it
// without importing zlog-specific Go types.
func (s *ObservabilityStore) ChartData(since time.Duration) map[string]any {
	s.mu.RLock()
	logs := append([]ObsLog(nil), s.logs...)
	spans := append([]ObsSpan(nil), s.spans...)
	metrics := append([]ObsMetric(nil), s.metrics...)
	s.mu.RUnlock()
	cutoff := cutoffTime(since)
	if cutoff.IsZero() {
		cutoff = time.Now().Add(-30 * time.Minute)
	}
	now := time.Now()
	buckets := 24
	window := now.Sub(cutoff)
	if window <= 0 {
		window = 30 * time.Minute
	}
	step := window / time.Duration(buckets)
	if step <= 0 {
		step = time.Minute
	}
	timeline := make([]map[string]any, buckets)
	durations := make([][]int64, buckets)
	for i := 0; i < buckets; i++ {
		t := cutoff.Add(time.Duration(i) * step)
		timeline[i] = map[string]any{"bucket": t.Format("15:04"), "logs": 0, "errors": 0, "spans": 0, "metrics": 0, "p95_ms": 0.0}
	}
	idx := func(t time.Time) int {
		if t.Before(cutoff) {
			return -1
		}
		i := int(t.Sub(cutoff) / step)
		if i < 0 {
			return -1
		}
		if i >= buckets {
			i = buckets - 1
		}
		return i
	}
	levels := map[string]int{}
	serviceLogs := map[string]int{}
	serviceErrors := map[string]int{}
	serviceSpans := map[string]int{}
	metricNames := map[string]int{}
	traceDurations := map[string]int64{}
	traceServices := map[string]map[string]struct{}{}
	for _, l := range logs {
		if i := idx(l.Time); i >= 0 {
			timeline[i]["logs"] = timeline[i]["logs"].(int) + 1
			if isErrLevel(l.Level) {
				timeline[i]["errors"] = timeline[i]["errors"].(int) + 1
			}
		}
		lvl := strings.ToLower(l.Level)
		if lvl == "" {
			lvl = "unknown"
		}
		levels[lvl]++
		svc := l.Service
		if svc == "" {
			svc = "unknown"
		}
		serviceLogs[svc]++
		if isErrLevel(l.Level) {
			serviceErrors[svc]++
		}
	}
	for _, sp := range spans {
		if i := idx(sp.Start); i >= 0 {
			timeline[i]["spans"] = timeline[i]["spans"].(int) + 1
			if sp.DurationNS > 0 {
				durations[i] = append(durations[i], sp.DurationNS)
			}
		}
		svc := sp.Service
		if svc == "" {
			svc = "unknown"
		}
		serviceSpans[svc]++
		if sp.TraceID != "" {
			if sp.DurationNS > traceDurations[sp.TraceID] {
				traceDurations[sp.TraceID] = sp.DurationNS
			}
			m := traceServices[sp.TraceID]
			if m == nil {
				m = map[string]struct{}{}
				traceServices[sp.TraceID] = m
			}
			m[svc] = struct{}{}
		}
	}
	for i, ds := range durations {
		if len(ds) > 0 {
			timeline[i]["p95_ms"] = float64(percentile(ds, .95)) / 1e6
		}
	}
	for _, m := range metrics {
		if i := idx(m.Time); i >= 0 {
			timeline[i]["metrics"] = timeline[i]["metrics"].(int) + 1
		}
		name := m.Name
		if name == "" {
			name = "unknown"
		}
		metricNames[name]++
	}
	return map[string]any{
		"generated_at":   now,
		"timeline":       timeline,
		"levels":         rankedCounts(levels, 8),
		"service_logs":   rankedCounts(serviceLogs, 10),
		"service_errors": rankedCounts(serviceErrors, 10),
		"service_spans":  rankedCounts(serviceSpans, 10),
		"metric_names":   rankedCounts(metricNames, 10),
		"slow_traces":    slowTraceRows(traceDurations, traceServices, 10),
	}
}

func rankedCounts(m map[string]int, limit int) []map[string]any {
	type kv struct {
		K string
		V int
	}
	xs := make([]kv, 0, len(m))
	for k, v := range m {
		if v > 0 {
			xs = append(xs, kv{k, v})
		}
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].V > xs[j].V })
	if limit > 0 && len(xs) > limit {
		xs = xs[:limit]
	}
	out := make([]map[string]any, 0, len(xs))
	for _, x := range xs {
		out = append(out, map[string]any{"name": x.K, "count": x.V})
	}
	return out
}

func slowTraceRows(durs map[string]int64, services map[string]map[string]struct{}, limit int) []map[string]any {
	type kv struct {
		Trace string
		Dur   int64
	}
	xs := make([]kv, 0, len(durs))
	for k, v := range durs {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].Dur > xs[j].Dur })
	if limit > 0 && len(xs) > limit {
		xs = xs[:limit]
	}
	out := make([]map[string]any, 0, len(xs))
	for _, x := range xs {
		ss := make([]string, 0, len(services[x.Trace]))
		for svc := range services[x.Trace] {
			ss = append(ss, svc)
		}
		sort.Strings(ss)
		out = append(out, map[string]any{"trace_id": x.Trace, "duration_ms": float64(x.Dur) / 1e6, "services": ss})
	}
	return out
}

// ObservabilitySink mirrors local logger records into the observability store.
type ObservabilitySink struct {
	Store *ObservabilityStore
	Next  Sink
}

func NewObservabilitySink(store *ObservabilityStore, next Sink) *ObservabilitySink {
	return &ObservabilitySink{Store: store, Next: next}
}
func (s *ObservabilitySink) WriteRecord(r Record, static []Attr) error {
	if s.Store != nil {
		s.Store.RecordLog(recordToObsLog(r, static))
		if sp, ok := recordToObsSpan(r, static); ok {
			s.Store.RecordSpan(sp)
		}
	}
	if s.Next != nil {
		return s.Next.WriteRecord(r, static)
	}
	return nil
}
func (s *ObservabilitySink) Flush() error {
	if s.Next != nil {
		return s.Next.Flush()
	}
	return nil
}
func (s *ObservabilitySink) Close() error {
	if s.Next != nil {
		return s.Next.Close()
	}
	return nil
}
func (s *ObservabilitySink) Stats() SinkStats {
	if s.Next != nil {
		return s.Next.Stats()
	}
	return SinkStats{}
}

func recordToObsLog(r Record, static []Attr) ObsLog {
	attrs := map[string]any{}
	for _, a := range static {
		putAttr(attrs, a)
	}
	for i := 0; i < r.AttrLen(); i++ {
		putAttr(attrs, r.AttrAt(i))
	}
	l := ObsLog{Time: r.Time, Level: r.Level.String(), Message: r.Message, Logger: r.Logger, Attrs: attrs}
	l.Service = strAttr(attrs, "service.name")
	l.ServiceVer = strAttr(attrs, "service.version")
	l.Environment = strAttr(attrs, "deployment.environment")
	l.Node = firstStr(attrs, "node.name", "node", "host.name")
	l.Instance = firstStr(attrs, "service.instance.id", "instance", "process.pid")
	l.RequestID = strAttr(attrs, "request_id")
	l.CorrelationID = strAttr(attrs, "correlation_id")
	l.TraceID = strAttr(attrs, "trace_id")
	l.SpanID = strAttr(attrs, "span_id")
	l.ParentSpanID = strAttr(attrs, "parent_span_id")
	l.UserID = strAttr(attrs, "user_id")
	l.TenantID = strAttr(attrs, "tenant_id")
	l.Tool = strAttr(attrs, "tool.name")
	l.WorkflowID = strAttr(attrs, "workflow.id")
	l.TaskID = strAttr(attrs, "task.id")
	return l
}
func recordToObsSpan(r Record, static []Attr) (ObsSpan, bool) {
	attrs := map[string]any{}
	for _, a := range static {
		putAttr(attrs, a)
	}
	for i := 0; i < r.AttrLen(); i++ {
		putAttr(attrs, r.AttrAt(i))
	}
	name := strAttr(attrs, "span.name")
	tid := strAttr(attrs, "trace_id")
	sid := strAttr(attrs, "span_id")
	isSpan := name != "" && tid != "" && sid != "" && (r.Message == "span.end" || r.Message == "span.start" || attrs["span.duration"] != nil)
	if !isSpan {
		return ObsSpan{}, false
	}
	dur := int64Attr(attrs, "span.duration")
	sp := ObsSpan{TraceID: tid, SpanID: sid, ParentSpanID: strAttr(attrs, "parent_span_id"), Name: name, Kind: strAttr(attrs, "span.kind"), Service: strAttr(attrs, "service.name"), Node: firstStr(attrs, "node.name", "node", "host.name"), Instance: firstStr(attrs, "service.instance.id", "instance", "process.pid"), UserID: strAttr(attrs, "user_id"), TenantID: strAttr(attrs, "tenant_id"), Tool: strAttr(attrs, "tool.name"), WorkflowID: strAttr(attrs, "workflow.id"), TaskID: strAttr(attrs, "task.id"), Start: r.Time, DurationNS: dur, Status: strAttr(attrs, "span.status"), Error: strAttr(attrs, "error"), Attrs: attrs}
	if dur > 0 {
		sp.End = r.Time
		sp.Start = r.Time.Add(-time.Duration(dur))
	}
	return sp, true
}

// ObservabilityHandler exposes ingestion, query APIs, and a built-in dashboard UI.
type ObservabilityHandler struct {
	Store  *ObservabilityStore
	Title  string
	Prefix string
}

func NewObservabilityHandler(store *ObservabilityStore) *ObservabilityHandler {
	if store == nil {
		store = NewObservabilityStore(ObservabilityOptions{})
	}
	return &ObservabilityHandler{Store: store, Title: "zlog Observability", Prefix: "/"}
}
func (h *ObservabilityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, h.Prefix)
	if h.Prefix == "/" {
		path = strings.TrimPrefix(r.URL.Path, "/")
	}
	switch {
	case path == "" || path == "ui" || path == "dashboard":
		h.serveUI(w, r)
	case path == "api/v1/overview":
		writeJSON(w, h.Store.Overview())
	case path == "api/v1/charts":
		writeJSON(w, h.Store.ChartData(queryFromRequest(r).Since))
	case path == "api/v1/services" || path == "api/v1/nodes":
		writeJSON(w, h.Store.Services())
	case path == "api/v1/logs" && r.Method == http.MethodPost:
		h.ingestLogs(w, r)
	case path == "api/v1/logs":
		writeJSON(w, h.Store.QueryLogs(queryFromRequest(r)))
	case path == "api/v1/spans" && r.Method == http.MethodPost:
		h.ingestSpans(w, r)
	case path == "api/v1/spans":
		writeJSON(w, h.Store.QuerySpans(queryFromRequest(r)))
	case path == "api/v1/traces":
		h.traces(w, r)
	case path == "api/v1/metrics" && r.Method == http.MethodPost:
		h.ingestMetrics(w, r)
	case path == "api/v1/metrics":
		writeJSON(w, h.Store.QueryMetrics(queryFromRequest(r)))
	case path == "api/v1/prometheus" && r.Method == http.MethodPost:
		h.ingestPrometheus(w, r)
	default:
		http.NotFound(w, r)
	}
}
func (h *ObservabilityHandler) serveUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = observabilityHTML.Execute(w, map[string]string{"Title": h.Title})
}
func (h *ObservabilityHandler) ingestLogs(w http.ResponseWriter, r *http.Request) {
	n, err := decodeMany(r.Body, func(l ObsLog) { h.Store.RecordLog(l) })
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]any{"ingested": n})
}
func (h *ObservabilityHandler) ingestSpans(w http.ResponseWriter, r *http.Request) {
	n, err := decodeMany(r.Body, func(sp ObsSpan) { h.Store.RecordSpan(sp) })
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]any{"ingested": n})
}
func (h *ObservabilityHandler) ingestMetrics(w http.ResponseWriter, r *http.Request) {
	n, err := decodeMany(r.Body, func(m ObsMetric) { h.Store.RecordMetric(m) })
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]any{"ingested": n})
}
func (h *ObservabilityHandler) ingestPrometheus(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	node := r.URL.Query().Get("node")
	n, err := ParsePrometheusText(r.Context(), r.Body, service, node, h.Store.RecordMetric)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	writeJSON(w, map[string]any{"ingested": n})
}
func (h *ObservabilityHandler) traces(w http.ResponseWriter, r *http.Request) {
	q := queryFromRequest(r)
	spans := h.Store.QuerySpans(q)
	by := map[string][]ObsSpan{}
	for _, sp := range spans {
		by[sp.TraceID] = append(by[sp.TraceID], sp)
	}
	writeJSON(w, by)
}

func decodeMany[T any](body io.Reader, emit func(T)) (int, error) {
	b, err := io.ReadAll(io.LimitReader(body, 32<<20))
	if err != nil {
		return 0, err
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return 0, nil
	}
	if b[0] == '[' {
		var xs []T
		if err := json.Unmarshal(b, &xs); err != nil {
			return 0, err
		}
		for _, x := range xs {
			emit(x)
		}
		return len(xs), nil
	}
	if bytes.Contains(b, []byte("\n")) {
		sc := bufio.NewScanner(bytes.NewReader(b))
		n := 0
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var x T
			if err := json.Unmarshal(line, &x); err != nil {
				return n, err
			}
			emit(x)
			n++
		}
		return n, sc.Err()
	}
	var x T
	if err := json.Unmarshal(b, &x); err != nil {
		return 0, err
	}
	emit(x)
	return 1, nil
}

func ParsePrometheusText(ctx context.Context, r io.Reader, service, node string, emit func(ObsMetric)) (int, error) {
	sc := bufio.NewScanner(r)
	now := time.Now()
	n := 0
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return n, ctx.Err()
		default:
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, labels, val, ok := parsePromLine(line)
		if !ok {
			continue
		}
		m := ObsMetric{Time: now, Name: name, Value: val, Type: "prometheus", Service: service, Node: node, Labels: labels}
		if svc := labels["service"]; svc != "" && m.Service == "" {
			m.Service = svc
		}
		if nd := labels["node"]; nd != "" && m.Node == "" {
			m.Node = nd
		}
		if inst := labels["instance"]; inst != "" {
			m.Instance = inst
		}
		emit(m)
		n++
	}
	return n, sc.Err()
}
func parsePromLine(line string) (string, map[string]string, float64, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", nil, 0, false
	}
	left := fields[0]
	v, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return "", nil, 0, false
	}
	labels := map[string]string{}
	name := left
	if i := strings.Index(left, "{"); i >= 0 && strings.HasSuffix(left, "}") {
		name = left[:i]
		raw := strings.TrimSuffix(left[i+1:], "}")
		for _, p := range splitCSV(raw) {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) == 2 {
				labels[strings.TrimSpace(kv[0])] = strings.Trim(strings.TrimSpace(kv[1]), `"`)
			}
		}
	}
	return name, labels, v, true
}
func splitCSV(s string) []string {
	var out []string
	var b strings.Builder
	inQ := false
	for _, r := range s {
		if r == '"' {
			inQ = !inQ
		}
		if r == ',' && !inQ {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteRune(r)
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

func queryFromRequest(r *http.Request) ObsQuery {
	qv := r.URL.Query()
	lim, _ := strconv.Atoi(qv.Get("limit"))
	since, _ := time.ParseDuration(qv.Get("since"))
	return ObsQuery{Service: qv.Get("service"), Node: qv.Get("node"), Instance: qv.Get("instance"), Level: qv.Get("level"), RequestID: qv.Get("request_id"), CorrelationID: qv.Get("correlation_id"), TraceID: qv.Get("trace_id"), SpanID: qv.Get("span_id"), UserID: qv.Get("user_id"), TenantID: qv.Get("tenant_id"), Tool: qv.Get("tool"), WorkflowID: qv.Get("workflow_id"), TaskID: qv.Get("task_id"), Name: qv.Get("name"), Since: since, Limit: lim, Sort: qv.Get("sort"), Desc: qv.Get("desc") == "true"}
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func matchLog(l ObsLog, q ObsQuery, cutoff time.Time) bool {
	if !cutoff.IsZero() && l.Time.Before(cutoff) {
		return false
	}
	return eq(q.Service, l.Service) && eq(q.Node, l.Node) && eq(q.Instance, l.Instance) && eqFold(q.Level, l.Level) && eq(q.RequestID, l.RequestID) && eq(q.CorrelationID, l.CorrelationID) && eq(q.TraceID, l.TraceID) && eq(q.SpanID, l.SpanID) && eq(q.UserID, l.UserID) && eq(q.TenantID, l.TenantID) && eq(q.Tool, l.Tool) && eq(q.WorkflowID, l.WorkflowID) && eq(q.TaskID, l.TaskID) && containsName(q.Name, l.Message)
}
func matchSpan(sp ObsSpan, q ObsQuery, cutoff time.Time) bool {
	if !cutoff.IsZero() && sp.Start.Before(cutoff) {
		return false
	}
	return eq(q.Service, sp.Service) && eq(q.Node, sp.Node) && eq(q.Instance, sp.Instance) && eq(q.TraceID, sp.TraceID) && eq(q.SpanID, sp.SpanID) && eq(q.UserID, sp.UserID) && eq(q.TenantID, sp.TenantID) && eq(q.Tool, sp.Tool) && eq(q.WorkflowID, sp.WorkflowID) && eq(q.TaskID, sp.TaskID) && containsName(q.Name, sp.Name)
}
func matchMetric(m ObsMetric, q ObsQuery, cutoff time.Time) bool {
	if !cutoff.IsZero() && m.Time.Before(cutoff) {
		return false
	}
	return eq(q.Service, m.Service) && eq(q.Node, m.Node) && eq(q.Instance, m.Instance) && containsName(q.Name, m.Name)
}
func eq(want, got string) bool     { return want == "" || want == got }
func eqFold(want, got string) bool { return want == "" || strings.EqualFold(want, got) }
func containsName(want, got string) bool {
	return want == "" || strings.Contains(strings.ToLower(got), strings.ToLower(want))
}
func cutoffTime(d time.Duration) time.Time {
	if d <= 0 {
		return time.Time{}
	}
	return time.Now().Add(-d)
}
func limitOf(n int) int {
	if n <= 0 {
		return 200
	}
	return n
}
func trimLimit[T any](xs []T, n int) []T {
	if n <= 0 {
		n = 200
	}
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func isErrLevel(s string) bool {
	s = strings.ToLower(s)
	return s == "error" || s == "critical" || s == "fatal" || s == "panic"
}
func percentile(xs []int64, p float64) int64 {
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	if len(xs) == 0 {
		return 0
	}
	idx := int(math.Ceil(float64(len(xs))*p)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(xs) {
		idx = len(xs) - 1
	}
	return xs[idx]
}

func putAttr(m map[string]any, a Attr) {
	if a.Kind == KindInvalid || a.Key == "" {
		return
	}
	m[a.Key] = attrAny(a)
}
func attrAny(a Attr) any {
	switch a.Kind {
	case KindString, KindError:
		return a.Str
	case KindBytes:
		return string(a.Bytes)
	case KindBool:
		return a.I64 != 0
	case KindInt64, KindDuration:
		return a.I64
	case KindUint64:
		return a.U64
	case KindFloat64:
		return mathFloat64frombits(a.U64)
	case KindTime:
		return a.Any
	case KindGroup:
		mm := map[string]any{}
		for _, g := range a.Group {
			putAttr(mm, g)
		}
		return mm
	case KindAny:
		return a.Any
	case KindRawJSON:
		var v any
		if json.Unmarshal(a.Bytes, &v) == nil {
			return v
		}
		return string(a.Bytes)
	default:
		return nil
	}
}
func strAttr(m map[string]any, k string) string {
	v := m[k]
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		if x != nil {
			return fmt.Sprint(x)
		}
		return ""
	}
}
func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v := strAttr(m, k); v != "" {
			return v
		}
	}
	return ""
}
func int64Attr(m map[string]any, k string) int64 {
	switch x := m[k].(type) {
	case int64:
		return x
	case int:
		return int64(x)
	case float64:
		return int64(x)
	case string:
		v, _ := strconv.ParseInt(x, 10, 64)
		return v
	}
	return 0
}

// PushMetrics periodically emits runtime/process metrics into the store until ctx is done.
func (s *ObservabilityStore) PushMetric(name string, value float64, service, node string, labels map[string]string) {
	s.RecordMetric(ObsMetric{Time: time.Now(), Name: name, Value: value, Service: service, Node: node, Labels: labels})
}
func ErrObservabilityNotConfigured() error {
	return errors.New("zlog observability store is not configured")
}

var observabilityHTML = template.Must(template.New("obs").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title><style>
:root{--bg:#08101f;--panel:#101a33;--panel2:#0b1327;--line:#26385f;--muted:#91a5c9;--text:#eef5ff;--accent:#79c9ff;--accent2:#a78bfa;--bad:#ff6b7a;--ok:#70e2a3;--warn:#ffd166}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 20% -10%,#173365,#08101f 38%,#050914);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,Segoe UI,Arial}header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center;justify-content:space-between;background:rgba(8,16,31,.86);backdrop-filter:blur(10px);position:sticky;top:0;z-index:20}.brand{font-size:22px;font-weight:900}.label,.muted{color:var(--muted);font-size:13px}.tabs{display:flex;gap:8px;flex-wrap:wrap}.tabs button,.toolbar button,.linkbtn{background:#1a2750;color:var(--text);border:1px solid #354a7d;border-radius:10px;padding:9px 12px;cursor:pointer;text-decoration:none}.tabs button.active,.linkbtn.primary{background:var(--accent);color:#07111f}.wrap{padding:18px;display:grid;gap:16px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}.card,.panel{background:rgba(16,26,51,.95);border:1px solid var(--line);border-radius:16px;padding:14px;box-shadow:0 16px 55px #0004}.num{font-size:28px;font-weight:900}.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}.grid3{display:grid;grid-template-columns:2fr 1fr 1fr;gap:16px}.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:8px 0 14px}.toolbar input,.toolbar select{background:var(--panel2);color:var(--text);border:1px solid #354a7d;border-radius:10px;padding:9px;min-width:130px}table{width:100%;border-collapse:separate;border-spacing:0;background:rgba(16,26,51,.95);border-radius:16px;overflow:hidden}th,td{text-align:left;padding:10px;border-bottom:1px solid #24365d;font-size:13px;vertical-align:top}th{color:#bed0f1;background:#151f3c;position:sticky;top:0}.clickable{cursor:pointer}.clickable:hover{background:#18274b}.pill{padding:3px 8px;border-radius:999px;background:#26385f;display:inline-block}.error{color:var(--bad)}.ok{color:var(--ok)}.warn{color:var(--warn)}.hidden{display:none}.chart{height:260px;width:100%;display:block}.chart text{fill:#bed0f1;font-size:11px}.chart .grid{stroke:#26385f;stroke-width:1}.chart .line{fill:none;stroke:var(--accent);stroke-width:2.5}.chart .line2{fill:none;stroke:var(--bad);stroke-width:2.2}.chart .bar{fill:var(--accent);opacity:.82}.chart .bar2{fill:var(--bad);opacity:.78}.chart .dot{fill:var(--accent)}.legend{display:flex;gap:14px;flex-wrap:wrap;color:var(--muted);font-size:12px}.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;background:var(--accent)}.sw.bad{background:var(--bad)}.trace-card{border:1px solid #26385f;border-radius:14px;margin:10px 0;background:#0b1327;overflow:hidden}.trace-head{padding:10px 12px;background:#151f3c;display:flex;gap:12px;flex-wrap:wrap;align-items:center}.span-row{display:grid;grid-template-columns:minmax(260px,1.4fr) 90px 110px 1fr 120px;gap:10px;padding:9px 12px;border-top:1px solid #22345b;font-size:13px;align-items:center}.span-name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.timeline{height:10px;background:#22345b;border-radius:99px;overflow:hidden;position:relative}.timeline span{position:absolute;height:10px;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px}.json-tip{position:fixed;max-width:min(640px,calc(100vw - 26px));max-height:min(520px,calc(100vh - 26px));overflow:auto;display:none;background:#050816;color:#dbeafe;border:1px solid #3b4f86;border-radius:12px;padding:12px;box-shadow:0 22px 80px #000b;z-index:1000;pointer-events:none}.json-tip pre{margin:0;white-space:pre-wrap;font-size:12px}.drawer{position:fixed;right:0;top:0;bottom:0;width:min(700px,92vw);background:#071124;border-left:1px solid #3b4f86;box-shadow:-24px 0 80px #000a;z-index:900;transform:translateX(105%);transition:.18s transform ease;display:flex;flex-direction:column}.drawer.open{transform:translateX(0)}.drawer-head{padding:14px;border-bottom:1px solid #26385f;display:flex;justify-content:space-between;gap:10px}.drawer-body{padding:14px;overflow:auto}.drawer pre{white-space:pre-wrap;background:#050816;border:1px solid #26385f;border-radius:12px;padding:12px;color:#dbeafe}.actions{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.actions button{background:#18274b;color:var(--text);border:1px solid #354a7d;border-radius:9px;padding:7px 9px;cursor:pointer}code{color:#c4d8ff}.hint{border:1px dashed #405786;border-radius:12px;padding:10px;color:#b8c9ea;background:#0b1327}@media(max-width:1100px){.grid2,.grid3{grid-template-columns:1fr}.span-row{grid-template-columns:1fr 80px 90px 1fr}}@media(max-width:760px){header{display:block}.tabs{margin-top:12px}.wrap{padding:12px}.span-row{display:block}.timeline{margin-top:8px}}
</style></head><body><header><div><div class="brand">zlog Observability</div><div class="label">Interactive logs, traces, metrics, services, and nodes. Click rows to drill into related data; hover for a moving JSON model.</div></div><div class="tabs"><button data-tab="overview" class="active">Overview</button><button data-tab="services">Services</button><button data-tab="logs">Logs</button><button data-tab="traces">Traces</button><button data-tab="metrics">Metrics</button></div></header><main class="wrap"><section id="overview"><div class="cards" id="cards"></div><div class="grid3"><div class="panel"><h3>Traffic and errors</h3><svg id="trafficChart" class="chart"></svg><div class="legend"><span><i class="sw"></i>logs</span><span><i class="sw bad"></i>errors</span></div></div><div class="panel"><h3>Log levels</h3><svg id="levelChart" class="chart"></svg></div><div class="panel"><h3>Top error services</h3><svg id="errorServiceChart" class="chart"></svg></div></div><div class="grid2"><div class="panel"><h3>Service health</h3><table id="svcMini"></table></div><div class="panel"><h3>Slow traces</h3><table id="slowTraceTable"></table></div></div></section><section id="services" class="hidden"><h2>Services and nodes</h2><div class="hint">Click a service to open its logs, traces, and metrics from the detail drawer.</div><div class="grid2"><div class="panel"><h3>Logs by service</h3><svg id="svcLogChart" class="chart"></svg></div><div class="panel"><h3>Spans by service</h3><svg id="svcSpanChart" class="chart"></svg></div></div><table id="servicesTable"></table></section><section id="logs" class="hidden"><h2>Logs</h2><div class="toolbar"><input id="logService" placeholder="service"><input id="logReq" placeholder="request_id"><input id="logTrace" placeholder="trace_id"><input id="logUser" placeholder="user_id"><select id="logLevel"><option value="">any level</option><option>error</option><option>warn</option><option>info</option><option>debug</option></select><button onclick="loadLogs()">Filter</button><button onclick="clearLogFilters()">Clear</button></div><table id="logsTable"></table></section><section id="traces" class="hidden"><h2>Tracing</h2><div class="label">Click a trace or span to jump to related logs, service, user, tool, and request filters.</div><div class="toolbar"><input id="traceID" placeholder="trace_id"><input id="spanService" placeholder="service"><input id="spanUser" placeholder="user_id"><input id="spanTool" placeholder="tool"><button onclick="loadSpans()">Filter</button><button onclick="clearTraceFilters()">Clear</button></div><div class="grid2"><div class="panel"><h3>Latency p95 over time</h3><svg id="latencyChart" class="chart"></svg></div><div class="panel"><h3>Span volume over time</h3><svg id="spanVolumeChart" class="chart"></svg></div></div><div id="traceTree"></div></section><section id="metrics" class="hidden"><h2>Metrics</h2><div class="toolbar"><input id="metricService" placeholder="service"><input id="metricName" placeholder="metric name"><button onclick="loadMetrics()">Filter</button><button onclick="clearMetricFilters()">Clear</button></div><div class="grid2"><div class="panel"><h3>Metric samples over time</h3><svg id="metricVolumeChart" class="chart"></svg></div><div class="panel"><h3>Top metric names</h3><svg id="metricNameChart" class="chart"></svg></div></div><table id="metricsTable"></table></section></main><div id="tip" class="json-tip"><pre></pre></div><aside id="drawer" class="drawer"><div class="drawer-head"><div><b id="drawerTitle">Details</b><div id="drawerSub" class="muted"></div></div><button class="linkbtn" onclick="closeDrawer()">Close</button></div><div id="drawerActions" class="actions"></div><div class="drawer-body"><pre id="drawerJSON"></pre><div id="relatedBox"></div></div></aside><script>
const $=id=>document.getElementById(id); const esc=s=>String(s??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const state={tab:'overview',selected:null,lastCharts:null};
async function api(p){const r=await fetch(p); if(!r.ok) throw new Error(await r.text()); return r.json()}
function setTab(t,push){state.tab=t; document.querySelectorAll('.tabs button').forEach(x=>x.classList.toggle('active',x.dataset.tab===t)); document.querySelectorAll('main section').forEach(s=>s.classList.add('hidden')); $(t).classList.remove('hidden'); if(push!==false) location.hash=t; refresh(t)}
document.querySelectorAll('.tabs button').forEach(b=>b.onclick=()=>setTab(b.dataset.tab)); window.onhashchange=()=>routeHash();
function routeHash(){let parts=(location.hash||'#overview').slice(1).split('?'); let tab=parts[0]||'overview'; let q=new URLSearchParams(parts[1]||''); if(tab==='logs'){for(const [id,k] of [['logService','service'],['logReq','request_id'],['logTrace','trace_id'],['logUser','user_id'],['logLevel','level']]) if(q.has(k)) $(id).value=q.get(k)} if(tab==='traces'){for(const [id,k] of [['traceID','trace_id'],['spanService','service'],['spanUser','user_id'],['spanTool','tool']]) if(q.has(k)) $(id).value=q.get(k)} if(tab==='metrics'){for(const [id,k] of [['metricService','service'],['metricName','name']]) if(q.has(k)) $(id).value=q.get(k)} setTab(tab,false)}
function nav(tab,params){let q=new URLSearchParams(params||{}); location.hash=tab+(q.toString()?'?'+q:''); routeHash()}
function dur(ns){if(!ns)return''; if(ns>1e9)return(ns/1e9).toFixed(2)+'s'; if(ns>1e6)return(ns/1e6).toFixed(1)+'ms'; return(ns/1e3).toFixed(0)+'µs'} function ms(v){return Number(v||0).toFixed(1)+'ms'}
function level(l){let c=String(l).toLowerCase(); return '<span class="pill '+(c==='error'||c==='fatal'||c==='panic'?'error':c==='warn'?'warn':'')+'">'+esc(l)+'</span>'}
function row(o,type){return ' data-json="'+encodeURIComponent(JSON.stringify(o))+'" data-type="'+esc(type||'record')+'" class="clickable"'}
function table(id, heads, rows){$(id).innerHTML='<thead><tr>'+heads.map(h=>'<th>'+h+'</th>').join('')+'</tr></thead><tbody>'+rows.join('')+'</tbody>'; bindInteractive($(id))}
function bindInteractive(root){root.querySelectorAll('[data-json]').forEach(el=>{el.onmousemove=e=>showTip(e, decodeURIComponent(el.dataset.json)); el.onmouseenter=e=>showTip(e, decodeURIComponent(el.dataset.json)); el.onmouseleave=hideTip; el.onclick=e=>{e.stopPropagation(); openDetails(JSON.parse(decodeURIComponent(el.dataset.json)), el.dataset.type)}})}
function showTip(e, raw){let t=$('tip'), pre=t.querySelector('pre'); pre.textContent=formatJSON(raw); t.style.display='block'; let w=t.offsetWidth||520,h=t.offsetHeight||360,x=e.clientX+18,y=e.clientY+18; if(x+w>window.innerWidth-12)x=e.clientX-w-18; if(y+h>window.innerHeight-12)y=e.clientY-h-18; t.style.left=Math.max(8,x)+'px'; t.style.top=Math.max(8,y)+'px'} function hideTip(){ $('tip').style.display='none' }
function formatJSON(raw){try{return JSON.stringify(JSON.parse(raw),null,2)}catch{return raw}}
function openDetails(o,type){state.selected=o; $('drawer').classList.add('open'); $('drawerTitle').textContent=(type||'record')+' details'; $('drawerSub').textContent=[o.service,o.node,o.message||o.name,o.trace_id].filter(Boolean).join(' · '); $('drawerJSON').textContent=JSON.stringify(o,null,2); $('drawerActions').innerHTML=actionsFor(o,type); $('relatedBox').innerHTML=''; loadRelated(o,type)}
function closeDrawer(){ $('drawer').classList.remove('open') }
function actionsFor(o,type){let a=[]; if(o.service)a.push('<button onclick="nav(\'services\',{service:\''+escJS(o.service)+'\'})">service</button>','<button onclick="nav(\'logs\',{service:\''+escJS(o.service)+'\'})">service logs</button>','<button onclick="nav(\'traces\',{service:\''+escJS(o.service)+'\'})">service traces</button>','<button onclick="nav(\'metrics\',{service:\''+escJS(o.service)+'\'})">service metrics</button>'); if(o.request_id)a.push('<button onclick="nav(\'logs\',{request_id:\''+escJS(o.request_id)+'\'})">request logs</button>'); if(o.trace_id)a.push('<button onclick="nav(\'traces\',{trace_id:\''+escJS(o.trace_id)+'\'})">trace view</button>','<button onclick="nav(\'logs\',{trace_id:\''+escJS(o.trace_id)+'\'})">trace logs</button>'); if(o.user_id)a.push('<button onclick="nav(\'logs\',{user_id:\''+escJS(o.user_id)+'\'})">user logs</button>','<button onclick="nav(\'traces\',{user_id:\''+escJS(o.user_id)+'\'})">user traces</button>'); if(o.tool)a.push('<button onclick="nav(\'traces\',{tool:\''+escJS(o.tool)+'\'})">tool traces</button>'); if(o.name && type==='metric')a.push('<button onclick="nav(\'metrics\',{name:\''+escJS(o.name)+'\'})">metric samples</button>'); return a.join('')||'<span class="muted">No related filters available.</span>'}
function escJS(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'")}
async function loadRelated(o,type){let box=$('relatedBox'), html='<h3>Related data</h3>'; let calls=[]; if(o.trace_id)calls.push(api('/api/v1/logs?limit=8&trace_id='+encodeURIComponent(o.trace_id)).then(xs=>html+=miniTable('Trace logs',xs,['time','level','service','message']))); if(o.service)calls.push(api('/api/v1/spans?limit=8&service='+encodeURIComponent(o.service)).then(xs=>html+=miniTable('Recent service spans',xs,['start','status','service','name']))); if(o.request_id)calls.push(api('/api/v1/logs?limit=8&request_id='+encodeURIComponent(o.request_id)).then(xs=>html+=miniTable('Request logs',xs,['time','level','service','message']))); try{await Promise.all(calls)}catch(e){html+='<div class="error">'+esc(e.message)+'</div>'} box.innerHTML=html; bindInteractive(box)}
function miniTable(title,xs,cols){return '<h4>'+esc(title)+'</h4><table><tbody>'+(xs||[]).map(x=>'<tr'+row(x,title)+'>'+cols.map(c=>'<td>'+esc(c.includes('time')||c==='start'?new Date(x[c]).toLocaleTimeString():x[c])+'</td>').join('')+'</tr>').join('')+'</tbody></table>'}
function maxOf(xs,key){return Math.max(1,...(xs||[]).map(x=>Number(x[key]||0)))} function svg(id){let el=$(id); let w=el.clientWidth||600,h=el.clientHeight||260; el.setAttribute('viewBox','0 0 '+w+' '+h); el.innerHTML=''; return {el,w,h,p:34}}
function drawLine(id,data,series){let c=svg(id), w=c.w,h=c.h,p=c.p, n=Math.max((data||[]).length,1); let max=Math.max(1,...series.flatMap(s=>(data||[]).map(d=>Number(d[s.key]||0)))); for(let i=0;i<4;i++){let y=p+(h-2*p)*i/3; c.el.innerHTML+='<line class="grid" x1="'+p+'" y1="'+y+'" x2="'+(w-p)+'" y2="'+y+'"/>'} series.forEach((s,si)=>{let pts=(data||[]).map((d,i)=>{let x=p+(w-2*p)*(n===1?0:i/(n-1)); let y=h-p-(h-2*p)*Number(d[s.key]||0)/max; return x+','+y}).join(' '); c.el.innerHTML+='<polyline class="'+(si?'line2':'line')+'" points="'+pts+'"/>'; (data||[]).forEach((d,i)=>{let x=p+(w-2*p)*(n===1?0:i/(n-1)); let y=h-p-(h-2*p)*Number(d[s.key]||0)/max; c.el.innerHTML+='<circle class="dot clickable" cx="'+x+'" cy="'+y+'" r="4" data-json="'+encodeURIComponent(JSON.stringify(d))+'" data-type="chart point"><title>'+esc(d.bucket+' '+s.key+': '+d[s.key])+'</title></circle>'})}); for(let i=0;i<(data||[]).length;i+=Math.ceil(data.length/6)||1){let x=p+(w-2*p)*(n===1?0:i/(n-1)); c.el.innerHTML+='<text x="'+x+'" y="'+(h-8)+'" text-anchor="middle">'+esc(data[i].bucket)+'</text>'} bindInteractive(c.el)}
function drawBars(id,data,key,labelKey){let c=svg(id),w=c.w,h=c.h,p=c.p; let xs=(data||[]).slice(0,10), max=maxOf(xs,key), bw=(w-2*p)/Math.max(xs.length,1); xs.forEach((d,i)=>{let v=Number(d[key]||0), bh=(h-70)*v/max, x=p+i*bw+6, y=h-36-bh; c.el.innerHTML+='<rect class="bar clickable" x="'+x+'" y="'+y+'" width="'+Math.max(8,bw-12)+'" height="'+bh+'" data-json="'+encodeURIComponent(JSON.stringify(d))+'" data-type="chart bar"></rect><text x="'+(x+(bw-12)/2)+'" y="'+(h-12)+'" text-anchor="middle">'+esc(short(d[labelKey]||d.name))+'</text><text x="'+(x+(bw-12)/2)+'" y="'+(y-6)+'" text-anchor="middle">'+v+'</text>'}); bindInteractive(c.el)}
function drawHorizontalBars(id,data,key,labelKey){let c=svg(id),w=c.w,h=c.h,p=22; let xs=(data||[]).slice(0,8), max=maxOf(xs,key), rowh=(h-2*p)/Math.max(xs.length,1); xs.forEach((d,i)=>{let v=Number(d[key]||0), y=p+i*rowh+6, bw=(w-150)*v/max; c.el.innerHTML+='<text x="10" y="'+(y+13)+'">'+esc(short(d[labelKey]||d.name,18))+'</text><rect class="bar clickable" x="130" y="'+y+'" width="'+bw+'" height="16" data-json="'+encodeURIComponent(JSON.stringify(d))+'" data-type="chart bar"></rect><text x="'+(135+bw)+'" y="'+(y+13)+'">'+v+'</text>'}); bindInteractive(c.el)}
function short(s,n){s=String(s||''); n=n||9; return s.length>n?s.slice(0,n-1)+'…':s} async function chartData(){state.lastCharts=await api('/api/v1/charts?since=1h'); return state.lastCharts}
async function loadOverview(){let o=await api('/api/v1/overview'); let ch=await chartData(); $('cards').innerHTML=['services','logs','spans','metrics','errors'].map(k=>'<div class="card clickable" onclick="nav(\''+(k==='metrics'?'metrics':k==='spans'?'traces':k==='services'?'services':'logs')+'\',{})"><div class="num">'+esc(o[k])+'</div><div class="label">'+k+'</div></div>').join(''); drawLine('trafficChart',ch.timeline,[{key:'logs'},{key:'errors'}]); drawBars('levelChart',ch.levels,'count','name'); drawHorizontalBars('errorServiceChart',ch.service_errors,'count','name'); let ss=o.service_summaries||[]; table('svcMini',['service','node','logs','errors','p95','last seen'],ss.slice(0,8).map(s=>'<tr'+row(s,'service')+'><td><b>'+esc(s.service)+'</b></td><td>'+esc(s.node)+'</td><td>'+s.log_count+'</td><td class="error">'+s.error_count+'</td><td>'+dur(s.p95_latency_ns)+'</td><td>'+esc(new Date(s.last_seen).toLocaleTimeString())+'</td></tr>')); table('slowTraceTable',['trace','services','duration'],(ch.slow_traces||[]).map(t=>'<tr'+row(t,'trace')+'><td><code>'+esc(short(t.trace_id,24))+'</code></td><td>'+esc((t.services||[]).join(', '))+'</td><td>'+ms(t.duration_ms)+'</td></tr>'))}
async function loadServices(){let ss=await api('/api/v1/services'); let ch=await chartData(); drawHorizontalBars('svcLogChart',ch.service_logs,'count','name'); drawHorizontalBars('svcSpanChart',ch.service_spans,'count','name'); let qs=new URLSearchParams((location.hash.split('?')[1]||'')); let filter=qs.get('service'); let rows=ss.filter(s=>!filter||s.service===filter).map(s=>'<tr'+row(s,'service')+'><td><b>'+esc(s.service)+'</b></td><td>'+esc(s.node)+'</td><td>'+esc(s.instance)+'</td><td>'+s.log_count+'</td><td>'+s.span_count+'</td><td>'+s.metric_count+'</td><td class="error">'+s.error_count+'</td><td>'+dur(s.p95_latency_ns)+'</td><td>'+esc(new Date(s.last_seen).toLocaleString())+'</td></tr>'); table('servicesTable',['service','node','instance','logs','spans','metrics','errors','p95 latency','last seen'],rows)}
function logQuery(){let q=new URLSearchParams({limit:500,desc:true}); if($('logService').value)q.set('service',$('logService').value); if($('logReq').value)q.set('request_id',$('logReq').value); if($('logTrace').value)q.set('trace_id',$('logTrace').value); if($('logUser').value)q.set('user_id',$('logUser').value); if($('logLevel').value)q.set('level',$('logLevel').value); return q} async function loadLogs(){let xs=await api('/api/v1/logs?'+logQuery()); table('logsTable',['time','level','service','node','request','user','trace/span','message'],xs.map(l=>'<tr'+row(l,'log')+'><td>'+esc(new Date(l.time).toLocaleTimeString())+'</td><td>'+level(l.level)+'</td><td>'+esc(l.service)+'</td><td>'+esc(l.node)+'</td><td>'+esc(l.request_id)+'</td><td>'+esc(l.user_id)+'</td><td><code>'+esc(short(l.trace_id,18))+'<br>'+esc(short(l.span_id,18))+'</code></td><td>'+esc(l.message)+'</td></tr>'))}
function clearLogFilters(){['logService','logReq','logTrace','logUser','logLevel'].forEach(id=>$(id).value='');loadLogs()}
async function loadSpans(){let ch=await chartData(); drawLine('latencyChart',ch.timeline,[{key:'p95_ms'}]); drawLine('spanVolumeChart',ch.timeline,[{key:'spans'}]); let q=new URLSearchParams({limit:800,desc:false}); if($('traceID').value)q.set('trace_id',$('traceID').value); if($('spanService').value)q.set('service',$('spanService').value); if($('spanUser').value)q.set('user_id',$('spanUser').value); if($('spanTool').value)q.set('tool',$('spanTool').value); let xs=await api('/api/v1/spans?'+q); renderTraceTree(xs)} function clearTraceFilters(){['traceID','spanService','spanUser','spanTool'].forEach(id=>$(id).value='');loadSpans()}
function renderTraceTree(spans){let by={}; spans.forEach(s=>{(by[s.trace_id]=by[s.trace_id]||[]).push(s)}); let html=''; Object.keys(by).slice(0,40).forEach(tid=>{let xs=by[tid].sort((a,b)=>new Date(a.start)-new Date(b.start)); let min=Math.min(...xs.map(s=>new Date(s.start).getTime())); let max=Math.max(...xs.map(s=>new Date(s.end||s.start).getTime())); let total=Math.max(1,max-min); let services=[...new Set(xs.map(s=>s.service).filter(Boolean))].join(' → '); let root=xs.find(s=>!s.parent_span_id)||xs[0]; html+='<div class="trace-card"><div '+row({trace_id:tid,services:services,span_count:xs.length,duration_ms:total,root:root},'trace')+'><div class="trace-head"><b><code>'+esc(short(tid,34))+'</code></b><span class="muted">'+esc(services)+'</span><span class="pill">'+xs.length+' spans</span><span class="pill">'+ms(total)+'</span></div></div>'; xs.forEach(s=>{let st=new Date(s.start).getTime(), en=new Date(s.end||s.start).getTime(); let left=((st-min)/total*100).toFixed(1), width=Math.max(1,((en-st)/total*100)).toFixed(1); let depth=depthOf(s,xs); html+='<div '+row(s,'span')+'><div class="span-row"><div class="span-name" style="padding-left:'+(depth*18)+'px">'+(s.status==='error'?'⚠ ':'')+esc(s.name)+'<div class="muted">'+esc(s.service)+' · '+esc(s.tool||s.kind||'span')+' · user '+esc(s.user_id||'-')+' · req '+esc(s.request_id||'-')+'</div></div><div class="'+(s.status==='error'?'error':'ok')+'">'+esc(s.status||'ok')+'</div><div>'+dur(s.duration_ns)+'</div><div class="timeline"><span style="left:'+left+'%;width:'+width+'%"></span></div><div><button onclick="event.stopPropagation();nav(\'logs\',{trace_id:\''+escJS(s.trace_id)+'\'})">logs</button></div></div></div>'}); html+='</div>'}); $('traceTree').innerHTML=html||'<div class="panel">No spans match the filter.</div>'; bindInteractive($('traceTree'))}
function depthOf(s,xs){let d=0,p=s.parent_span_id; while(p&&d<12){let parent=xs.find(x=>x.span_id===p); if(!parent)break; d++; p=parent.parent_span_id} return d}
async function loadMetrics(){let ch=await chartData(); drawLine('metricVolumeChart',ch.timeline,[{key:'metrics'}]); drawHorizontalBars('metricNameChart',ch.metric_names,'count','name'); let q=new URLSearchParams({limit:500,desc:true}); if($('metricService').value)q.set('service',$('metricService').value); if($('metricName').value)q.set('name',$('metricName').value); let xs=await api('/api/v1/metrics?'+q); table('metricsTable',['time','service','node','name','value','unit','labels'],xs.map(m=>'<tr'+row(m,'metric')+'><td>'+esc(new Date(m.time).toLocaleTimeString())+'</td><td>'+esc(m.service)+'</td><td>'+esc(m.node)+'</td><td>'+esc(m.name)+'</td><td>'+esc(m.value)+'</td><td>'+esc(m.unit)+'</td><td>'+esc(JSON.stringify(m.labels||{}))+'</td></tr>'))} function clearMetricFilters(){['metricService','metricName'].forEach(id=>$(id).value='');loadMetrics()}
function refresh(t){({overview:loadOverview,services:loadServices,logs:loadLogs,traces:loadSpans,metrics:loadMetrics}[t]||loadOverview)()} routeHash(); setInterval(()=>refresh(state.tab),5000);
</script></body></html>`))
