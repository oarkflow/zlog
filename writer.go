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
	return &WriterSink{w: w, enc: enc, level: level, redactor: DefaultRedactor().normalized()}
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
		s.stats.failed.Add(1)
		s.stats.last.Store(err.Error())
		return err
	}
	n, err := s.w.Write(buf.Bytes())
	s.mu.Unlock()
	if err != nil {
		s.stats.failed.Add(1)
		s.stats.last.Store(err.Error())
		return err
	}
	s.stats.written.Add(1)
	s.stats.bytes.Add(uint64(n))
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
