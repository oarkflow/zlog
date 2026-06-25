package zlog

import (
	"bytes"
	"strings"
	"time"
)

type LogfmtEncoder struct{ TimeFormat string }

func NewLogfmtEncoder() *LogfmtEncoder { return &LogfmtEncoder{TimeFormat: time.RFC3339Nano} }
func (e *LogfmtEncoder) Encode(buf *bytes.Buffer, r Record, static []Attr) error {
	buf.WriteString("time=")
	buf.WriteByte('"')
	appendTime(buf, r.Time, e.TimeFormat)
	buf.WriteByte('"')
	buf.WriteString(" level=")
	appendLogfmtString(buf, r.Level.String())
	buf.WriteString(" msg=")
	appendLogfmtString(buf, r.Message)
	if r.Logger != "" {
		buf.WriteString(" logger=")
		appendLogfmtString(buf, r.Logger)
	}
	for i := range static {
		appendLogfmtAttr(buf, static[i])
	}
	for i := 0; i < r.AttrLen(); i++ {
		appendLogfmtAttr(buf, r.AttrAt(i))
	}
	buf.WriteByte('\n')
	return nil
}
func appendLogfmtAttr(buf *bytes.Buffer, a Attr) {
	if a.Kind == KindInvalid || a.Key == "" {
		return
	}
	buf.WriteByte(' ')
	buf.WriteString(safeKey(a.Key))
	buf.WriteByte('=')
	appendLogfmtValue(buf, a)
}
func appendLogfmtValue(buf *bytes.Buffer, a Attr) {
	switch a.Kind {
	case KindString, KindError:
		appendLogfmtString(buf, a.Str)
	case KindBytes:
		appendLogfmtString(buf, string(a.Bytes))
	case KindBool:
		if a.I64 != 0 {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case KindInt64, KindDuration:
		appendInt(buf, a.I64)
	case KindUint64:
		appendUint(buf, a.U64)
	case KindFloat64:
		appendFloat(buf, mathFloat64frombits(a.U64))
	case KindTime:
		if t, ok := a.Any.(time.Time); ok {
			buf.WriteByte('"')
			appendTime(buf, t, time.RFC3339Nano)
			buf.WriteByte('"')
		} else {
			buf.WriteString("null")
		}
	case KindRawJSON:
		appendLogfmtString(buf, string(a.Bytes))
	case KindGroup:
		appendLogfmtString(buf, "<group>")
	case KindAny:
		appendLogfmtString(buf, "<any>")
	default:
		buf.WriteString("null")
	}
}
func appendLogfmtString(buf *bytes.Buffer, s string) {
	if s == "" {
		buf.WriteString(`""`)
		return
	}
	if strings.IndexAny(s, " \t\n\r\"") >= 0 {
		appendQuotedLogfmt(buf, s)
	} else {
		buf.WriteString(s)
	}
}
func safeKey(k string) string {
	k = strings.ReplaceAll(k, " ", "_")
	k = strings.ReplaceAll(k, "=", "_")
	return k
}
