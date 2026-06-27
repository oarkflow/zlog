package zlog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type DeliveryMode int

const (
	BestEffort DeliveryMode = iota
	AtLeastOnce
	AuditStrict
	BlockOnFailure
	SpoolOnFailure
	DropWithMetrics
)

type RetryOptions struct {
	Attempts   int
	MinBackoff time.Duration
	MaxBackoff time.Duration
	Factor     float64
}

type RetrySink struct {
	sink  Sink
	opts  RetryOptions
	stats sinkCounters
}

func NewRetrySink(s Sink, opts RetryOptions) *RetrySink {
	if opts.Attempts <= 0 {
		opts.Attempts = 3
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = 50 * time.Millisecond
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = time.Second
	}
	if opts.Factor <= 1 {
		opts.Factor = 2
	}
	return &RetrySink{sink: s, opts: opts}
}
func (r *RetrySink) WriteRecord(rec Record, st []Attr) error {
	var err error
	back := r.opts.MinBackoff
	for i := 0; i < r.opts.Attempts; i++ {
		err = r.sink.WriteRecord(rec, st)
		if err == nil {
			r.stats.written.Add(1)
			return nil
		}
		r.stats.failed.Add(1)
		r.stats.last.Store(err.Error())
		time.Sleep(back)
		nb := time.Duration(float64(back) * r.opts.Factor)
		if nb > r.opts.MaxBackoff {
			nb = r.opts.MaxBackoff
		}
		back = nb
	}
	return err
}
func (r *RetrySink) Flush() error { return r.sink.Flush() }
func (r *RetrySink) Close() error { return r.sink.Close() }
func (r *RetrySink) Stats() SinkStats {
	st := r.sink.Stats()
	st.Written += r.stats.written.Load()
	st.Failed += r.stats.failed.Load()
	if v := r.stats.last.Load(); v != nil {
		st.LastError = v.(string)
	}
	return st
}

type CircuitBreakerOptions struct {
	FailureThreshold uint64
	ResetAfter       time.Duration
}
type CircuitBreakerSink struct {
	sink     Sink
	opts     CircuitBreakerOptions
	failures atomic.Uint64
	opened   atomic.Int64
	stats    sinkCounters
}

func NewCircuitBreakerSink(s Sink, opts CircuitBreakerOptions) *CircuitBreakerSink {
	if opts.FailureThreshold == 0 {
		opts.FailureThreshold = 5
	}
	if opts.ResetAfter <= 0 {
		opts.ResetAfter = 10 * time.Second
	}
	return &CircuitBreakerSink{sink: s, opts: opts}
}
func (c *CircuitBreakerSink) WriteRecord(r Record, st []Attr) error {
	if until := c.opened.Load(); until > time.Now().UnixNano() {
		c.stats.failed.Add(1)
		err := errors.New("zlog circuit breaker open")
		c.stats.last.Store(err.Error())
		return err
	}
	err := c.sink.WriteRecord(r, st)
	if err != nil {
		if c.failures.Add(1) >= c.opts.FailureThreshold {
			c.opened.Store(time.Now().Add(c.opts.ResetAfter).UnixNano())
		}
		c.stats.failed.Add(1)
		c.stats.last.Store(err.Error())
		return err
	}
	c.failures.Store(0)
	c.stats.written.Add(1)
	return nil
}
func (c *CircuitBreakerSink) Flush() error { return c.sink.Flush() }
func (c *CircuitBreakerSink) Close() error { return c.sink.Close() }
func (c *CircuitBreakerSink) Stats() SinkStats {
	st := c.sink.Stats()
	st.Failed += c.stats.failed.Load()
	st.Written += c.stats.written.Load()
	if v := c.stats.last.Load(); v != nil {
		st.LastError = v.(string)
	}
	return st
}

type DurableSinkOptions struct {
	Dir           string
	MaxBytes      int64
	DrainInterval time.Duration
	BatchSize     int
	Mode          DeliveryMode
}
type DurableSink struct {
	sink     Sink
	enc      Encoder
	opts     DurableSinkOptions
	mu       sync.Mutex
	cur      *os.File
	path     string
	stats    sinkCounters
	closed   atomic.Bool
	done     chan struct{}
	wg       sync.WaitGroup
	redactor Redactor
}

func NewDurableSink(s Sink, opts DurableSinkOptions) (*DurableSink, error) {
	if opts.Dir == "" {
		opts.Dir = ".zlog-spool"
	}
	if opts.DrainInterval <= 0 {
		opts.DrainInterval = time.Second
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 128
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 1 << 30
	}
	if err := os.MkdirAll(opts.Dir, 0750); err != nil {
		return nil, err
	}
	d := &DurableSink{sink: s, enc: NewJSONEncoder(), opts: opts, done: make(chan struct{}), redactor: DefaultRedactor().normalized()}
	d.path = filepath.Join(opts.Dir, "spool.ndjson")
	f, err := os.OpenFile(d.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, err
	}
	d.cur = f
	d.wg.Add(1)
	go d.loop()
	return d, nil
}
func (d *DurableSink) Redactor(r Redactor) *DurableSink { d.redactor = r; return d }
func (d *DurableSink) WriteRecord(r Record, st []Attr) error {
	err := d.sink.WriteRecord(r, st)
	if err == nil {
		d.stats.written.Add(1)
		return nil
	}
	d.stats.failed.Add(1)
	d.stats.last.Store(err.Error())
	if d.opts.Mode == AuditStrict || d.opts.Mode == BlockOnFailure {
		return err
	}
	if e := d.spool(r, st); e != nil {
		return e
	}
	return nil
}
func (d *DurableSink) spool(r Record, st []Attr) error {
	if d.redactor.Enabled && !r.Redacted {
		r.Redact(d.redactor)
	}
	var b bytes.Buffer
	if err := d.enc.Encode(&b, r, st); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if info, err := d.cur.Stat(); err == nil && info.Size()+int64(b.Len()) > d.opts.MaxBytes {
		return fmt.Errorf("zlog durable spool full: %d bytes", info.Size())
	}
	_, err := d.cur.Write(b.Bytes())
	return err
}
func (d *DurableSink) loop() {
	defer d.wg.Done()
	t := time.NewTicker(d.opts.DrainInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_ = d.Drain(context.Background())
		case <-d.done:
			_ = d.Drain(context.Background())
			return
		}
	}
}
func (d *DurableSink) Drain(ctx context.Context) error {
	d.mu.Lock()
	_ = d.cur.Sync()
	_ = d.cur.Close()
	drain := filepath.Join(d.opts.Dir, "drain-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".ndjson")
	if err := os.Rename(d.path, drain); err != nil {
		d.cur, _ = os.OpenFile(d.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		d.mu.Unlock()
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	d.cur, _ = os.OpenFile(d.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	d.mu.Unlock()
	f, err := os.Open(drain)
	if err != nil {
		return err
	}
	defer f.Close()
	rd := bufio.NewScanner(f)
	ok := true
	for rd.Scan() {
		select {
		case <-ctx.Done():
			ok = false
			break
		default:
		}
		if !ok {
			break
		}
		line := append([]byte(nil), rd.Bytes()...)
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if _, err := d.sink.(interface{ Write([]byte) (int, error) }).Write(line); err != nil {
			ok = false
			break
		}
	}
	if ok && rd.Err() == nil {
		return os.Remove(drain)
	}
	dlq := filepath.Join(d.opts.Dir, "deadletter.ndjson")
	out, _ := os.OpenFile(dlq, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if out != nil {
		_, _ = f.Seek(0, 0)
		_, _ = io.Copy(out, f)
		_ = out.Close()
	}
	return rd.Err()
}
func (d *DurableSink) Flush() error { _ = d.cur.Sync(); return d.sink.Flush() }
func (d *DurableSink) Close() error {
	if d.closed.Swap(true) {
		return nil
	}
	close(d.done)
	d.wg.Wait()
	d.mu.Lock()
	if d.cur != nil {
		_ = d.cur.Close()
	}
	d.mu.Unlock()
	return d.sink.Close()
}
func (d *DurableSink) Stats() SinkStats {
	st := d.sink.Stats()
	st.Failed += d.stats.failed.Load()
	st.Written += d.stats.written.Load()
	if v := d.stats.last.Load(); v != nil {
		st.LastError = v.(string)
	}
	return st
}

type BatchHTTPWriter struct {
	URL           string
	Client        *http.Client
	Header        http.Header
	MaxBatch      int
	FlushInterval time.Duration
	mu            sync.Mutex
	buf           [][]byte
	closed        bool
}

func NewBatchHTTPWriter(url string) *BatchHTTPWriter {
	return &BatchHTTPWriter{URL: url, MaxBatch: 100, FlushInterval: time.Second}
}
func (w *BatchHTTPWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	cp := append([]byte(nil), p...)
	w.buf = append(w.buf, cp)
	need := w.MaxBatch > 0 && len(w.buf) >= w.MaxBatch
	w.mu.Unlock()
	if need {
		return len(p), w.Flush()
	}
	return len(p), nil
}
func (w *BatchHTTPWriter) Flush() error {
	w.mu.Lock()
	if len(w.buf) == 0 {
		w.mu.Unlock()
		return nil
	}
	data := bytes.Join(w.buf, nil)
	w.buf = nil
	w.mu.Unlock()
	_, err := HTTPWriter{URL: w.URL, Client: w.Client, Header: w.Header}.Write(data)
	return err
}

// Exporter helpers.
func NewOTLPHTTPExporter(endpoint string, headers http.Header) Sink {
	if headers == nil {
		headers = http.Header{}
	}
	headers.Set("Content-Type", "application/json")
	return NewWriterSink(HTTPWriter{URL: endpoint, Header: headers}, NewJSONEncoder(), TraceLevel)
}
func NewLokiSink(endpoint string, headers http.Header) Sink {
	return NewWriterSink(HTTPWriter{URL: endpoint, Header: headers}, NewJSONEncoder(), TraceLevel)
}
func NewOpenSearchSink(endpoint string, headers http.Header) Sink {
	return NewWriterSink(HTTPWriter{URL: endpoint, Header: headers}, NewJSONEncoder(), TraceLevel)
}
func NewWebhookSink(endpoint string, headers http.Header) Sink {
	return NewWriterSink(HTTPWriter{URL: endpoint, Header: headers}, NewJSONEncoder(), TraceLevel)
}

func writeRawPayload(s Sink, p []byte) (int, error) {
	switch x := s.(type) {
	case interface{ Write([]byte) (int, error) }:
		return x.Write(p)
	case *RetrySink:
		return writeRawPayload(x.sink, p)
	case *CircuitBreakerSink:
		return writeRawPayload(x.sink, p)
	case *AsyncSink:
		return writeRawPayload(x.sink, p)
	case *MultiSink:
		var first error
		var total int
		for _, child := range x.sinks {
			n, err := writeRawPayload(child, p)
			total += n
			if err != nil && first == nil {
				first = err
			}
		}
		return total, first
	default:
		return 0, errors.New("zlog sink does not support raw spool replay")
	}
}

// Simple NDJSON query utility used by CLI and local inspections.
type QueryOptions struct {
	Level    string
	Field    string
	Value    string
	Contains string
	Limit    int
}

func QueryNDJSON(r io.Reader, w io.Writer, q QueryOptions) error {
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		line := sc.Bytes()
		var m map[string]any
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		if q.Level != "" && !strings.EqualFold(fmt.Sprint(m["level"]), q.Level) && !strings.EqualFold(fmt.Sprint(m["log.level"]), q.Level) {
			continue
		}
		if q.Field != "" && fmt.Sprint(m[q.Field]) != q.Value {
			continue
		}
		if q.Contains != "" && !bytes.Contains(line, []byte(q.Contains)) {
			continue
		}
		_, _ = w.Write(line)
		_, _ = w.Write([]byte("\n"))
		n++
		if q.Limit > 0 && n >= q.Limit {
			break
		}
	}
	return sc.Err()
}
