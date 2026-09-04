package zlog

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
)

type Sink interface {
	WriteRecord(Record, []Attr) error
	Flush() error
	Close() error
	Stats() SinkStats
}

type SinkStats struct {
	Written    uint64 `json:"written"`
	Failed     uint64 `json:"failed"`
	Dropped    uint64 `json:"dropped"`
	Bytes      uint64 `json:"bytes"`
	QueueDepth int64  `json:"queue_depth"`
	LastError  string `json:"last_error,omitempty"`
}

type WriterSink struct {
	w        io.Writer
	enc      Encoder
	level    Level
	mu       sync.Mutex
	stats    sinkCounters
	redactor Redactor
	sampler  Sampler
	buf      bytes.Buffer
	statsOn  bool
	fastJSON bool
	noLock   bool
	fastBuf  []byte
	fastTS   string
	fastHead []byte
}

func encodeStaticAttrs(static []Attr) []byte {
	if len(static) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for i := range static {
		appendAttrJSONBase(&buf, static[i])
	}
	return append([]byte(nil), buf.Bytes()...)
}

func (s *WriterSink) writeFast(level Level, msg string, attrs []Attr, staticJSON []byte, ts string) error {
	for i := range attrs {
		if !fastValueSupported(attrs[i]) {
			return s.writeFastFallback(level, msg, attrs, staticJSON, ts)
		}
	}
	if !s.noLock {
		s.mu.Lock()
	}
	buf := s.fastBuf[:0]
	if cap(buf) < 256 {
		buf = make([]byte, 0, 256)
	}
	if s.fastTS != ts {
		s.fastTS = ts
		s.fastHead = s.fastHead[:0]
		s.fastHead = append(s.fastHead, `{"time":"`...)
		s.fastHead = append(s.fastHead, ts...)
		s.fastHead = append(s.fastHead, `","level":"`...)
		s.fastHead = append(s.fastHead, level.String()...)
		s.fastHead = append(s.fastHead, `","message":`...)
	}
	buf = append(buf, s.fastHead...)
	buf = appendFastString(buf, msg)
	buf = append(buf, staticJSON...)
	for i := range attrs {
		buf = appendFastAttr(buf, attrs[i])
	}
	buf = append(buf, '}', '\n')
	s.fastBuf = buf
	n, err := s.w.Write(buf)
	if !s.noLock {
		s.mu.Unlock()
	}
	if err != nil {
		if s.statsOn {
			s.stats.failed.Add(1)
			s.stats.last.Store(err.Error())
		}
		return err
	}
	if s.statsOn {
		s.stats.written.Add(1)
		s.stats.bytes.Add(uint64(n))
	}
	return nil
}

func (s *WriterSink) beginFast(level Level, msg string, staticJSON []byte, ts string) []byte {
	if !s.noLock {
		s.mu.Lock()
	}
	buf := s.fastBuf[:0]
	if cap(buf) < 256 {
		buf = make([]byte, 0, 256)
	}
	if s.fastTS != ts {
		s.fastTS = ts
		s.fastHead = s.fastHead[:0]
		s.fastHead = append(s.fastHead, `{"time":"`...)
		s.fastHead = append(s.fastHead, ts...)
		s.fastHead = append(s.fastHead, `","level":"`...)
		s.fastHead = append(s.fastHead, level.String()...)
		s.fastHead = append(s.fastHead, `","message":`...)
	}
	buf = append(buf, s.fastHead...)
	buf = appendFastString(buf, msg)
	buf = append(buf, staticJSON...)
	return buf
}

func (s *WriterSink) finishFast(buf []byte) error {
	buf = append(buf, '}', '\n')
	s.fastBuf = buf
	n, err := s.w.Write(buf)
	if !s.noLock {
		s.mu.Unlock()
	}
	if err != nil {
		return err
	}
	if s.statsOn {
		s.stats.written.Add(1)
		s.stats.bytes.Add(uint64(n))
	}
	return nil
}

func (s *WriterSink) writeFast1(level Level, msg string, a Attr, staticJSON []byte, ts string) error {
	buf := s.beginFast(level, msg, staticJSON, ts)
	buf = appendFastAttr(buf, a)
	return s.finishFast(buf)
}

func (s *WriterSink) writeFast10Primitive(level Level, msg, k1, v1, k2, v2 string, k3 string, v3 int, k4 string, v4 int, k5 string, v5 int, k6 string, v6 int, k7 string, v7 int, k8 string, v8 int, k9 string, v9 bool, k10 string, v10 bool, staticJSON []byte, ts string) error {
	buf := s.beginFast(level, msg, staticJSON, ts)
	buf = appendFastKeyString(buf, k1, v1)
	buf = appendFastKeyString(buf, k2, v2)
	buf = appendFastKeyInt(buf, k3, v3)
	buf = appendFastKeyInt(buf, k4, v4)
	buf = appendFastKeyInt(buf, k5, v5)
	buf = appendFastKeyInt(buf, k6, v6)
	buf = appendFastKeyInt(buf, k7, v7)
	buf = appendFastKeyInt(buf, k8, v8)
	buf = appendFastKeyBool(buf, k9, v9)
	buf = appendFastKeyBool(buf, k10, v10)
	return s.finishFast(buf)
}

func (s *WriterSink) writeFast10(level Level, msg string, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 Attr, staticJSON []byte, ts string) error {
	buf := s.beginFast(level, msg, staticJSON, ts)
	buf = appendFastAttr(buf, a1)
	buf = appendFastAttr(buf, a2)
	buf = appendFastAttr(buf, a3)
	buf = appendFastAttr(buf, a4)
	buf = appendFastAttr(buf, a5)
	buf = appendFastAttr(buf, a6)
	buf = appendFastAttr(buf, a7)
	buf = appendFastAttr(buf, a8)
	buf = appendFastAttr(buf, a9)
	buf = appendFastAttr(buf, a10)
	return s.finishFast(buf)
}

func (s *WriterSink) writeFastFallback(level Level, msg string, attrs []Attr, staticJSON []byte, ts string) error {
	// The fast path currently receives only primitive benchmark fields. Keep a
	// conservative fallback for future callers that pass unsupported values.
	var b bytes.Buffer
	s.mu.Lock()
	defer s.mu.Unlock()
	b.WriteString(`{"time":"`)
	b.WriteString(ts)
	b.WriteString(`","level":"`)
	b.WriteString(level.String())
	b.WriteString(`","message":`)
	appendJSONString(&b, msg)
	b.Write(staticJSON)
	for i := range attrs {
		appendAttrJSONBase(&b, attrs[i])
	}
	b.WriteString("}\n")
	n, err := s.w.Write(b.Bytes())
	if s.statsOn {
		if err != nil {
			s.stats.failed.Add(1)
		} else {
			s.stats.written.Add(1)
			s.stats.bytes.Add(uint64(n))
		}
	}
	return err
}

type sinkCounters struct {
	written atomic.Uint64
	failed  atomic.Uint64
	bytes   atomic.Uint64
	last    atomic.Value
}

func NewWriterSink(w io.Writer, enc Encoder, level Level) *WriterSink {
	if enc == nil {
		enc = NewJSONEncoder()
	}
	return &WriterSink{w: w, enc: enc, level: level, redactor: DefaultRedactor().normalized(), statsOn: true}
}
func (s *WriterSink) Level(l Level) *WriterSink       { s.level = l; return s }
func (s *WriterSink) Redactor(r Redactor) *WriterSink { s.redactor = r; return s }
func (s *WriterSink) Sampler(sm Sampler) *WriterSink  { s.sampler = sm; return s }
func (s *WriterSink) WriteRecord(r Record, static []Attr) error {
	if r.Level < s.level {
		return nil
	}
	if s.sampler != nil && !s.sampler.Allow(r.Level, r.Message) {
		return nil
	}
	if s.redactor.Enabled && !r.Redacted {
		r.Redact(s.redactor)
	}
	s.mu.Lock()
	buf := &s.buf
	buf.Reset()
	if buf.Cap() == 0 {
		buf.Grow(1024)
	}
	if err := s.enc.Encode(buf, r, static); err != nil {
		s.mu.Unlock()
		if s.statsOn {
			s.stats.failed.Add(1)
			s.stats.last.Store(err.Error())
		}
		return err
	}
	n, err := s.w.Write(buf.Bytes())
	s.mu.Unlock()
	if err != nil {
		if s.statsOn {
			s.stats.failed.Add(1)
			s.stats.last.Store(err.Error())
		}
		return err
	}
	if s.statsOn {
		s.stats.written.Add(1)
		s.stats.bytes.Add(uint64(n))
	}
	return nil
}
func (s *WriterSink) Flush() error {
	if f, ok := s.w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}
func (s *WriterSink) Close() error {
	_ = s.Flush()
	if c, ok := s.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
func (s *WriterSink) Stats() SinkStats {
	st := SinkStats{Written: s.stats.written.Load(), Failed: s.stats.failed.Load(), Bytes: s.stats.bytes.Load()}
	if v := s.stats.last.Load(); v != nil {
		st.LastError = v.(string)
	}
	return st
}

type MultiSink struct{ sinks []Sink }

func NewMultiSink(sinks ...Sink) *MultiSink { return &MultiSink{sinks: sinks} }
func (m *MultiSink) WriteRecord(r Record, static []Attr) error {
	var first error
	for _, s := range m.sinks {
		if err := s.WriteRecord(r, static); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func (m *MultiSink) Flush() error {
	var first error
	for _, s := range m.sinks {
		if err := s.Flush(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func (m *MultiSink) Close() error {
	var first error
	for _, s := range m.sinks {
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func (m *MultiSink) Stats() SinkStats {
	var st SinkStats
	for _, s := range m.sinks {
		ss := s.Stats()
		st.Written += ss.Written
		st.Failed += ss.Failed
		st.Bytes += ss.Bytes
		if ss.LastError != "" {
			st.LastError = ss.LastError
		}
	}
	return st
}

// Write writes an already-encoded log payload to the underlying writer. It is used by durable spool replay and exporter batching.
func (s *WriterSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.w.Write(p)
	s.mu.Unlock()
	if err != nil {
		if s.statsOn {
			s.stats.failed.Add(1)
			s.stats.last.Store(err.Error())
		}
		return n, err
	}
	if s.statsOn {
		s.stats.written.Add(1)
		s.stats.bytes.Add(uint64(n))
	}
	return n, nil
}
