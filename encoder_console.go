package zlog

import (
	"bytes"
	"time"
)

type ConsoleEncoder struct {
	TimeFormat    string
	Color         bool
	Prettify      bool
	KVSeparator   string
	PairSeparator string
}

func NewConsoleEncoder() *ConsoleEncoder {
	return &ConsoleEncoder{TimeFormat: "15:04:05", Color: true, Prettify: true, KVSeparator: "=", PairSeparator: " "}
}

func (e *ConsoleEncoder) normalize() {
	if e.TimeFormat == "" {
		e.TimeFormat = time.RFC3339Nano
	}
	if e.KVSeparator == "" {
		e.KVSeparator = "="
	}
	if e.PairSeparator == "" {
		e.PairSeparator = " "
	}
}

func (e *ConsoleEncoder) Encode(buf *bytes.Buffer, r Record, static []Attr) error {
	e.normalize()
	appendTime(buf, r.Time, e.TimeFormat)
	buf.WriteByte(' ')
	if e.Color {
		buf.WriteString(levelColor(r.Level))
	}
	buf.WriteString(r.Level.String())
	if e.Color {
		buf.WriteString(colorReset)
	}
	buf.WriteByte(' ')
	if e.Color {
		buf.WriteString(colorMsg)
	}
	buf.WriteString(r.Message)
	if e.Color {
		buf.WriteString(colorReset)
	}
	if r.Logger != "" {
		appendConsoleKVString(buf, e, "logger", r.Logger)
	}
	if r.Sequence != 0 {
		appendConsoleKVUint(buf, e, "sequence", r.Sequence)
	}
	for i := range static {
		appendConsoleAttr(buf, e, static[i])
	}
	for i := 0; i < r.AttrLen(); i++ {
		appendConsoleAttr(buf, e, r.AttrAt(i))
	}
	if r.Caller.File != "" {
		appendConsoleKVString(buf, e, "caller.file", r.Caller.File)
		appendConsoleKVInt(buf, e, "caller.line", int64(r.Caller.Line))
		if r.Caller.Func != "" {
			appendConsoleKVString(buf, e, "caller.func", r.Caller.Func)
		}
	}
	buf.WriteByte('\n')
	return nil
}

const (
	colorReset = "\x1b[0m"
	colorKey   = "\x1b[36m"
	colorSep   = "\x1b[90m"
	colorVal   = "\x1b[32m"
	colorMsg   = "\x1b[37m"
)

func levelColor(l Level) string {
	if l >= ErrorLevel {
		return "\x1b[31m"
	}
	if l >= WarnLevel {
		return "\x1b[33m"
	}
	if l <= DebugLevel {
		return "\x1b[36m"
	}
	return "\x1b[32m"
}

func appendConsoleAttr(buf *bytes.Buffer, e *ConsoleEncoder, a Attr) {
	if a.Kind == KindInvalid || a.Key == "" {
		return
	}
	if a.Kind == KindGroup {
		for i := range a.Group {
			ga := a.Group[i]
			if ga.Key != "" {
				ga.Key = a.Key + "." + ga.Key
			}
			appendConsoleAttr(buf, e, ga)
		}
		return
	}
	buf.WriteString(e.PairSeparator)
	if e.Color {
		buf.WriteString(colorKey)
	}
	buf.WriteString(safeKey(a.Key))
	if e.Color {
		buf.WriteString(colorSep)
	}
	buf.WriteString(e.KVSeparator)
	if e.Color {
		buf.WriteString(colorVal)
	}
	appendLogfmtValue(buf, a)
	if e.Color {
		buf.WriteString(colorReset)
	}
}

func appendConsoleKVString(buf *bytes.Buffer, e *ConsoleEncoder, k, v string) {
	appendConsoleAttr(buf, e, String(k, v))
}
func appendConsoleKVInt(buf *bytes.Buffer, e *ConsoleEncoder, k string, v int64) {
	appendConsoleAttr(buf, e, Int64(k, v))
}
func appendConsoleKVUint(buf *bytes.Buffer, e *ConsoleEncoder, k string, v uint64) {
	appendConsoleAttr(buf, e, Uint64(k, v))
}

var _ = time.RFC3339
