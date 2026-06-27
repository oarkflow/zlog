package zlog

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/syslog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PrometheusHandler exposes logger counters in Prometheus text format without third-party dependencies.
func (l *Logger) PrometheusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := l.Snapshot()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "# TYPE zlog_records_written_total counter\nzlog_records_written_total %d\n", st.Sink.Written)
		fmt.Fprintf(w, "# TYPE zlog_records_failed_total counter\nzlog_records_failed_total %d\n", st.Sink.Failed)
		fmt.Fprintf(w, "# TYPE zlog_records_dropped_total counter\nzlog_records_dropped_total %d\n", st.Sink.Dropped+st.Dropped)
		fmt.Fprintf(w, "# TYPE zlog_bytes_written_total counter\nzlog_bytes_written_total %d\n", st.Sink.Bytes)
		fmt.Fprintf(w, "# TYPE zlog_queue_depth gauge\nzlog_queue_depth %d\n", st.Sink.QueueDepth+st.QueueDepth)
	})
}

func (l *Logger) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/_zlog/stats", l.StatsHandler())
	mux.Handle("/_zlog/metrics", l.PrometheusHandler())
	mux.HandleFunc("/_zlog/level", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(l.Level().String() + "\n"))
		case http.MethodPost:
			lvl := r.URL.Query().Get("level")
			if lvl == "" {
				lvl = r.FormValue("level")
			}
			parsed, ok := ParseLevel(lvl)
			if !ok {
				http.Error(w, "invalid level", 400)
				return
			}
			l.SetLevel(parsed)
			_, _ = w.Write([]byte(parsed.String() + "\n"))
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
	mux.HandleFunc("/_zlog/health", func(w http.ResponseWriter, r *http.Request) {
		st := l.Stats()
		if st.LastError != "" {
			w.WriteHeader(206)
		}
		_ = json.NewEncoder(w).Encode(st)
	})
	return mux
}

func WatchConfig(ctx context.Context, path string, interval time.Duration, apply func(Config) error) error {
	if interval <= 0 {
		interval = time.Second
	}
	var last time.Time
	for {
		st, err := os.Stat(path)
		if err == nil && st.ModTime().After(last) {
			c, err := LoadConfig(path)
			if err == nil {
				err = apply(c)
			}
			if err != nil {
				return err
			}
			last = st.ModTime()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
func (l *Logger) WatchConfig(ctx context.Context, path string, interval time.Duration) error {
	return WatchConfig(ctx, path, interval, func(c Config) error {
		lvl, ok := ParseLevel(c.Level)
		if ok {
			l.SetLevel(lvl)
		}
		return nil
	})
}

type TokenBucketSampler struct {
	Rate     uint64
	Burst    uint64
	tokens   atomic.Uint64
	last     atomic.Int64
	MinLevel Level
}

func NewTokenBucketSampler(rate, burst uint64) *TokenBucketSampler {
	s := &TokenBucketSampler{Rate: rate, Burst: burst}
	s.tokens.Store(burst)
	s.last.Store(time.Now().UnixNano())
	return s
}
func (s *TokenBucketSampler) Allow(l Level, msg string) bool {
	if s == nil || s.Rate == 0 || l >= s.MinLevel {
		return true
	}
	now := time.Now()
	last := time.Unix(0, s.last.Swap(now.UnixNano()))
	add := uint64(now.Sub(last).Seconds() * float64(s.Rate))
	if add > 0 {
		for {
			old := s.tokens.Load()
			neu := old + add
			if neu > s.Burst {
				neu = s.Burst
			}
			if s.tokens.CompareAndSwap(old, neu) {
				break
			}
		}
	}
	for {
		old := s.tokens.Load()
		if old == 0 {
			return false
		}
		if s.tokens.CompareAndSwap(old, old-1) {
			return true
		}
	}
}

type FirstThenEverySampler struct {
	First    uint64
	Every    uint64
	c        atomic.Uint64
	MinLevel Level
}

func (s *FirstThenEverySampler) Allow(l Level, msg string) bool {
	if s == nil || l >= s.MinLevel {
		return true
	}
	n := s.c.Add(1)
	if n <= s.First {
		return true
	}
	return s.Every > 0 && (n-s.First)%s.Every == 0
}

type DedupSampler struct {
	Window   time.Duration
	mu       sync.Mutex
	seen     map[string]time.Time
	MinLevel Level
}

func NewDedupSampler(window time.Duration) *DedupSampler {
	if window <= 0 {
		window = time.Minute
	}
	return &DedupSampler{Window: window, seen: map[string]time.Time{}}
}
func (s *DedupSampler) Allow(l Level, msg string) bool {
	if s == nil || l >= s.MinLevel {
		return true
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.seen[msg]; ok && now.Sub(t) < s.Window {
		return false
	}
	s.seen[msg] = now
	for k, t := range s.seen {
		if now.Sub(t) > s.Window {
			delete(s.seen, k)
		}
	}
	return true
}

func Stack() Attr {
	buf := make([]byte, 64<<10)
	n := runtime.Stack(buf, false)
	return String("stack", string(buf[:n]))
}
func ErrWithStack(err error) Attr {
	if err == nil {
		return Attr{Kind: KindInvalid}
	}
	return Group("error", String("message", err.Error()), String("type", fmt.Sprintf("%T", err)), Stack())
}
func PanicStack(v any) Attr { return Group("panic", Any("value", v), Stack()) }

// Trace context helpers.
type traceCtxKey struct{}
type TraceContext struct {
	TraceID    string
	SpanID     string
	TraceFlags string
}

func ContextWithTrace(ctx context.Context, tc TraceContext) context.Context {
	return context.WithValue(ctx, traceCtxKey{}, tc)
}
func TraceFromContext(ctx context.Context) (TraceContext, bool) {
	tc, ok := ctx.Value(traceCtxKey{}).(TraceContext)
	return tc, ok
}
func ExtractW3CTraceparent(v string) (TraceContext, bool) {
	parts := strings.Split(v, "-")
	if len(parts) < 4 {
		return TraceContext{}, false
	}
	if len(parts[1]) != 32 || len(parts[2]) != 16 {
		return TraceContext{}, false
	}
	return TraceContext{TraceID: parts[1], SpanID: parts[2], TraceFlags: parts[3]}, true
}
func InjectTraceparent(ctx context.Context, h http.Header) {
	if tc, ok := TraceFromContext(ctx); ok && tc.TraceID != "" && tc.SpanID != "" {
		flags := tc.TraceFlags
		if flags == "" {
			flags = "01"
		}
		h.Set("traceparent", "00-"+tc.TraceID+"-"+tc.SpanID+"-"+flags)
	}
}
func ContextFromHTTP(r *http.Request) context.Context {
	ctx := r.Context()
	if tc, ok := ExtractW3CTraceparent(r.Header.Get("traceparent")); ok {
		ctx = ContextWithTrace(ctx, tc)
		ctx = ContextWithAttrs(ctx, TraceID(tc.TraceID), SpanID(tc.SpanID), String("trace_flags", tc.TraceFlags))
	}
	return ctx
}

// Syslog sink.
func NewSyslogSink(network, raddr, tag string, priority syslog.Priority) (Sink, error) {
	w, err := syslog.Dial(network, raddr, priority, tag)
	if err != nil {
		return nil, err
	}
	return NewWriterSink(w, NewLogfmtEncoder(), TraceLevel), nil
}

// Integrity verification for records or zlog native JSON lines.
type IntegrityReport struct {
	Total        int      `json:"total"`
	Valid        int      `json:"valid"`
	Invalid      int      `json:"invalid"`
	FirstBadLine int      `json:"first_bad_line,omitempty"`
	Errors       []string `json:"errors,omitempty"`
}

func VerifyIntegrityRecords(records []Record, static []Attr, key []byte) IntegrityReport {
	signer := NewIntegritySigner(key)
	rep := IntegrityReport{}
	for i, r := range records {
		rep.Total++
		var got string
		attrs := make([]Attr, 0, r.AttrLen())
		for j := 0; j < r.AttrLen(); j++ {
			a := r.AttrAt(j)
			if a.Key == "log.integrity.hmac" {
				got = a.Str
				continue
			}
			attrs = append(attrs, a)
		}
		r.SetAttrs(attrs)
		want := signer.SignRecord(r, static).Str
		if hmac.Equal([]byte(want), []byte(got)) {
			rep.Valid++
		} else {
			rep.Invalid++
			if rep.FirstBadLine == 0 {
				rep.FirstBadLine = i + 1
			}
			rep.Errors = append(rep.Errors, fmt.Sprintf("line %d integrity mismatch", i+1))
		}
	}
	return rep
}
func VerifyIntegrityNDJSON(r io.Reader, key []byte) (IntegrityReport, error) {
	sc := bufio.NewScanner(r)
	var prev [32]byte
	rep := IntegrityReport{}
	lineNo := 0
	for sc.Scan() {
		lineNo++
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			continue
		}
		got := fmt.Sprint(m["log.integrity.hmac"])
		if got == "" || got == "<nil>" {
			continue
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(prev[:])
		mac.Write([]byte(fmt.Sprint(m["sequence"])))
		mac.Write([]byte(fmt.Sprint(m["level"])))
		mac.Write([]byte(fmt.Sprint(m["message"])))
		keys := make([]string, 0, len(m))
		for k := range m {
			if k == "time" || k == "level" || k == "message" || k == "logger" || k == "sequence" || k == "caller" || k == "log.integrity.hmac" {
				continue
			}
			keys = append(keys, k)
		} // deterministic fallback: sorted map order for verification of regular JSON output
		for _, k := range keys {
			mac.Write([]byte(k))
			mac.Write([]byte{0})
			mac.Write([]byte(fmt.Sprint(m[k])))
			mac.Write([]byte{0})
		}
		sum := mac.Sum(nil)
		want := hex.EncodeToString(sum)
		rep.Total++
		if hmac.Equal([]byte(want), []byte(got)) {
			rep.Valid++
			copy(prev[:], sum)
		} else {
			rep.Invalid++
			if rep.FirstBadLine == 0 {
				rep.FirstBadLine = lineNo
			}
			rep.Errors = append(rep.Errors, "line "+strconv.Itoa(lineNo)+" integrity mismatch")
		}
	}
	return rep, sc.Err()
}

// Local ring buffer sink for diagnostics.
type RingBufferSink struct {
	sink    Sink
	mu      sync.Mutex
	records []Record
	next    int
	full    bool
}

func NewRingBufferSink(s Sink, n int) *RingBufferSink {
	if n <= 0 {
		n = 1000
	}
	return &RingBufferSink{sink: s, records: make([]Record, n)}
}
func (r *RingBufferSink) WriteRecord(rec Record, st []Attr) error {
	r.mu.Lock()
	r.records[r.next] = rec
	r.next = (r.next + 1) % len(r.records)
	if r.next == 0 {
		r.full = true
	}
	r.mu.Unlock()
	if r.sink != nil {
		return r.sink.WriteRecord(rec, st)
	}
	return nil
}
func (r *RingBufferSink) Recent() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		return append([]Record(nil), r.records[:r.next]...)
	}
	out := append([]Record(nil), r.records[r.next:]...)
	out = append(out, r.records[:r.next]...)
	return out
}
func (r *RingBufferSink) Flush() error {
	if r.sink != nil {
		return r.sink.Flush()
	}
	return nil
}
func (r *RingBufferSink) Close() error {
	if r.sink != nil {
		return r.sink.Close()
	}
	return nil
}
func (r *RingBufferSink) Stats() SinkStats {
	if r.sink != nil {
		return r.sink.Stats()
	}
	return SinkStats{Written: uint64(len(r.Recent()))}
}

// zlogtest-style capture helpers in package for zero dependency use.
type CaptureSink struct {
	mu      sync.Mutex
	Records []Record
}

func NewCaptureSink() *CaptureSink { return &CaptureSink{} }
func (c *CaptureSink) WriteRecord(r Record, st []Attr) error {
	c.mu.Lock()
	c.Records = append(c.Records, r)
	c.mu.Unlock()
	return nil
}
func (c *CaptureSink) Flush() error { return nil }
func (c *CaptureSink) Close() error { return nil }
func (c *CaptureSink) Stats() SinkStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return SinkStats{Written: uint64(len(c.Records))}
}
func (c *CaptureSink) ContainsMessage(msg string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.Records {
		if r.Message == msg {
			return true
		}
	}
	return false
}

var ErrIntegrityVerification = errors.New("zlog integrity verification failed")
