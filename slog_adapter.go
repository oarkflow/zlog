package zlog

import (
	"context"
	"log/slog"
	"time"
)

type SlogHandler struct {
	l      *Logger
	attrs  []slog.Attr
	groups []string
}

func NewSlogHandler(l *Logger) *SlogHandler { return &SlogHandler{l: l} }
func (h *SlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.l.Enabled(fromSlogLevel(level))
}
func (h *SlogHandler) Handle(ctx context.Context, r slog.Record) error {
	attrs := make([]Attr, 0, r.NumAttrs()+len(h.attrs))
	for _, a := range h.attrs {
		attrs = append(attrs, fromSlogAttr(a))
	}
	r.Attrs(func(a slog.Attr) bool { attrs = append(attrs, fromSlogAttr(a)); return true })
	for i := len(h.groups) - 1; i >= 0; i-- {
		if h.groups[i] != "" {
			attrs = []Attr{Group(h.groups[i], attrs...)}
		}
	}
	rec := Record{Time: r.Time, Level: fromSlogLevel(r.Level), Message: r.Message, Logger: h.l.name}
	if h.l.addSequence {
		rec.Sequence = nextSeq()
	}
	rec.SetAttrs(attrs)
	if rec.Time.IsZero() {
		rec.Time = time.Now()
	}
	return h.l.sink.WriteRecord(rec, h.l.static)
}
func (h *SlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	return &cp
}
func (h *SlogHandler) WithGroup(name string) slog.Handler {
	cp := *h
	cp.groups = append(append([]string(nil), h.groups...), name)
	return &cp
}
func fromSlogLevel(l slog.Level) Level {
	if l <= slog.LevelDebug {
		return DebugLevel
	}
	if l >= slog.LevelError {
		return ErrorLevel
	}
	if l >= slog.LevelWarn {
		return WarnLevel
	}
	return InfoLevel
}
func fromSlogAttr(a slog.Attr) Attr {
	v := a.Value
	switch v.Kind() {
	case slog.KindString:
		return String(a.Key, v.String())
	case slog.KindBool:
		return Bool(a.Key, v.Bool())
	case slog.KindInt64:
		return Int64(a.Key, v.Int64())
	case slog.KindUint64:
		return Uint64(a.Key, v.Uint64())
	case slog.KindFloat64:
		return Float64(a.Key, v.Float64())
	case slog.KindDuration:
		return Duration(a.Key, v.Duration())
	case slog.KindTime:
		return Time(a.Key, v.Time())
	default:
		return Any(a.Key, v.Any())
	}
}
