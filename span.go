package zlog

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SpanKindType string

const (
	SpanKindInternal SpanKindType = "internal"
	SpanKindServer   SpanKindType = "server"
	SpanKindClient   SpanKindType = "client"
	SpanKindProducer SpanKindType = "producer"
	SpanKindConsumer SpanKindType = "consumer"
	SpanKindTool     SpanKindType = "tool"
)

type SpanOptions struct {
	Kind       SpanKindType
	TraceID    string
	SpanID     string
	ParentID   string
	TraceFlags string
	Attrs      []Attr
	StartEvent bool
}

type SpanOption func(*SpanOptions)

func WithSpanKind(kind SpanKindType) SpanOption { return func(o *SpanOptions) { o.Kind = kind } }
func WithSpanTraceID(v string) SpanOption       { return func(o *SpanOptions) { o.TraceID = v } }
func WithSpanID(v string) SpanOption            { return func(o *SpanOptions) { o.SpanID = v } }
func WithParentSpanID(v string) SpanOption      { return func(o *SpanOptions) { o.ParentID = v } }
func WithSpanTraceFlags(v string) SpanOption    { return func(o *SpanOptions) { o.TraceFlags = v } }
func WithSpanAttrs(attrs ...Attr) SpanOption {
	return func(o *SpanOptions) { o.Attrs = append(o.Attrs, attrs...) }
}
func WithSpanStartEvent(v bool) SpanOption { return func(o *SpanOptions) { o.StartEvent = v } }

type Span struct {
	logger     *Logger
	name       string
	traceID    string
	spanID     string
	parentID   string
	traceFlags string
	kind       SpanKindType
	start      time.Time
	attrs      []Attr
	ctx        context.Context
	ended      bool
}

func StartSpan(ctx context.Context, l *Logger, name string, opts ...SpanOption) (context.Context, *Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	if l == nil {
		if from, ok := FromContext(ctx); ok {
			l = from
		}
	}
	o := SpanOptions{Kind: SpanKindInternal, TraceFlags: "01"}
	for _, fn := range opts {
		if fn != nil {
			fn(&o)
		}
	}
	if tc, ok := TraceFromContext(ctx); ok {
		if o.TraceID == "" {
			o.TraceID = tc.TraceID
		}
		if o.ParentID == "" {
			o.ParentID = tc.SpanID
		}
		if o.TraceFlags == "" {
			o.TraceFlags = tc.TraceFlags
		}
	}
	if lc, ok := LogContextFromContext(ctx); ok {
		if o.TraceID == "" {
			o.TraceID = lc.TraceID
		}
		if o.ParentID == "" {
			o.ParentID = lc.SpanID
		}
		if o.TraceFlags == "" {
			o.TraceFlags = lc.TraceFlags
		}
	}
	if o.TraceID == "" {
		o.TraceID = randomHex(16)
	}
	if o.SpanID == "" {
		o.SpanID = randomHex(8)
	}
	if o.TraceFlags == "" {
		o.TraceFlags = "01"
	}
	sp := &Span{logger: l, name: name, traceID: o.TraceID, spanID: o.SpanID, parentID: o.ParentID, traceFlags: o.TraceFlags, kind: o.Kind, start: time.Now(), attrs: append([]Attr(nil), o.Attrs...)}
	lc := LogContext{TraceID: sp.traceID, SpanID: sp.spanID, ParentSpanID: sp.parentID, TraceFlags: sp.traceFlags, Attrs: []Attr{SpanName(name), SpanKind(string(sp.kind))}}
	ctx = ContextWithLogContext(ctx, lc)
	ctx = IntoContext(ctx, l)
	sp.ctx = ctx
	if o.StartEvent && l != nil {
		l.InfoContext(ctx, "span.start", sp.baseAttrs()...)
	}
	return ctx, sp
}

func (l *Logger) StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, *Span) {
	return StartSpan(ctx, l, name, opts...)
}

func (s *Span) Context() context.Context {
	if s == nil {
		return context.Background()
	}
	return s.ctx
}
func (s *Span) TraceID() string {
	if s == nil {
		return ""
	}
	return s.traceID
}
func (s *Span) SpanID() string {
	if s == nil {
		return ""
	}
	return s.spanID
}
func (s *Span) ParentSpanID() string {
	if s == nil {
		return ""
	}
	return s.parentID
}
func (s *Span) Attrs(attrs ...Attr) {
	if s != nil {
		s.attrs = append(s.attrs, attrs...)
	}
}

func (s *Span) End(attrs ...Attr) {
	if s == nil || s.ended {
		return
	}
	s.ended = true
	if s.logger == nil {
		return
	}
	all := append(s.baseAttrs(), Duration("span.duration", time.Since(s.start)), SpanStatus("ok"))
	all = append(all, attrs...)
	s.logger.InfoContext(s.ctx, "span.end", all...)
}
func (s *Span) EndError(err error, attrs ...Attr) {
	if s == nil || s.ended {
		return
	}
	s.ended = true
	if s.logger == nil {
		return
	}
	all := append(s.baseAttrs(), Duration("span.duration", time.Since(s.start)), SpanStatus("error"), Err(err))
	all = append(all, attrs...)
	s.logger.ErrorContext(s.ctx, "span.end", all...)
}
func (s *Span) Log(level Level, msg string, attrs ...Attr) {
	if s == nil || s.logger == nil {
		return
	}
	s.logger.LogContext(s.ctx, level, msg, attrs...)
}
func (s *Span) Info(msg string, attrs ...Attr)  { s.Log(InfoLevel, msg, attrs...) }
func (s *Span) Debug(msg string, attrs ...Attr) { s.Log(DebugLevel, msg, attrs...) }
func (s *Span) Error(msg string, attrs ...Attr) { s.Log(ErrorLevel, msg, attrs...) }

func (s *Span) baseAttrs() []Attr {
	if s == nil {
		return nil
	}
	attrs := []Attr{TraceID(s.traceID), SpanID(s.spanID), SpanName(s.name), SpanKind(string(s.kind))}
	if s.parentID != "" {
		attrs = append(attrs, ParentSpanID(s.parentID))
	}
	if s.traceFlags != "" {
		attrs = append(attrs, String("trace_flags", s.traceFlags))
	}
	attrs = append(attrs, s.attrs...)
	return attrs
}

func randomHex(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

func ExtractBaggage(v string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
func InjectBaggage(ctx context.Context, h http.Header) {
	lc, ok := LogContextFromContext(ctx)
	if !ok || len(lc.Baggage) == 0 {
		return
	}
	parts := make([]string, 0, len(lc.Baggage))
	for k, v := range lc.Baggage {
		parts = append(parts, k+"="+v)
	}
	h.Set("baggage", strings.Join(parts, ","))
}
