package zlog

import (
	"bytes"
	"encoding/json"
	"time"
)

type JSONEncoder struct {
	TimeFormat string
	Schema     Schema
	Newline    bool
}

func NewJSONEncoder() *JSONEncoder {
	return &JSONEncoder{TimeFormat: time.RFC3339Nano, Schema: SchemaNative, Newline: true}
}

func (e *JSONEncoder) Encode(buf *bytes.Buffer, r Record, static []Attr) error {
	buf.WriteByte('{')
	first := false
	if e.Schema == SchemaNative {
		buf.WriteString(`"time":"`)
		appendTime(buf, r.Time, e.TimeFormat)
		buf.WriteString(`","level":"`)
		buf.WriteString(r.Level.String())
		buf.WriteString(`","message":`)
		appendJSONString(buf, r.Message)
	} else {
		appendJSONFieldPrefix(buf, &first, e.Schema.TimeKey())
		buf.WriteByte('"')
		appendTime(buf, r.Time, e.TimeFormat)
		buf.WriteByte('"')
		appendJSONFieldPrefix(buf, &first, e.Schema.LevelKey())
		appendJSONString(buf, r.Level.String())
		appendJSONFieldPrefix(buf, &first, e.Schema.MessageKey())
		appendJSONString(buf, r.Message)
	}
	first = false // native base already emitted; false means following helper writes comma first via special helper below
	if r.Logger != "" {
		appendJSONFieldPrefixAfterBase(buf, "logger")
		appendJSONString(buf, r.Logger)
	}
	if r.Sequence != 0 {
		appendJSONFieldPrefixAfterBase(buf, "sequence")
		appendUint(buf, r.Sequence)
	}
	if r.Caller.File != "" {
		appendJSONFieldPrefixAfterBase(buf, "caller")
		buf.WriteString(`{"file":`)
		appendJSONString(buf, r.Caller.File)
		buf.WriteString(`,"line":`)
		appendInt(buf, int64(r.Caller.Line))
		if r.Caller.Func != "" {
			buf.WriteString(`,"func":`)
			appendJSONString(buf, r.Caller.Func)
		}
		buf.WriteByte('}')
	}
	for i := range static {
		appendAttrJSONBase(buf, static[i])
	}
	for i := 0; i < r.AttrLen(); i++ {
		appendAttrJSONBase(buf, r.AttrAt(i))
	}
	buf.WriteByte('}')
	if e.Newline {
		buf.WriteByte('\n')
	}
	return nil
}

func appendJSONFieldPrefix(buf *bytes.Buffer, first *bool, k string) {
	if *first {
		buf.WriteByte(',')
	} else {
		*first = true
	}
	appendJSONString(buf, k)
	buf.WriteByte(':')
}
func appendJSONFieldPrefixAfterBase(buf *bytes.Buffer, k string) {
	buf.WriteByte(',')
	appendJSONString(buf, k)
	buf.WriteByte(':')
}

func appendAttrJSONBase(buf *bytes.Buffer, a Attr) {
	if a.Kind == KindInvalid || a.Key == "" {
		return
	}
	buf.WriteByte(',')
	appendJSONString(buf, a.Key)
	buf.WriteByte(':')
	appendValueJSON(buf, a)
}

func appendAttrJSON(buf *bytes.Buffer, first *bool, a Attr) {
	if a.Kind == KindInvalid || a.Key == "" {
		return
	}
	if !*first {
		buf.WriteByte(',')
	}
	*first = false
	appendJSONString(buf, a.Key)
	buf.WriteByte(':')
	appendValueJSON(buf, a)
}

func appendValueJSON(buf *bytes.Buffer, a Attr) {
	switch a.Kind {
	case KindString, KindError:
		appendJSONString(buf, a.Str)
	case KindBytes:
		appendJSONString(buf, string(a.Bytes))
	case KindBool:
		if a.I64 != 0 {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case KindInt64:
		appendInt(buf, a.I64)
	case KindUint64:
		appendUint(buf, a.U64)
	case KindFloat64:
		appendFloat(buf, mathFloat64frombits(a.U64))
	case KindDuration:
		appendInt(buf, a.I64)
	case KindTime:
		if t, ok := a.Any.(time.Time); ok {
			buf.WriteByte('"')
			appendTime(buf, t, time.RFC3339Nano)
			buf.WriteByte('"')
		} else {
			buf.WriteString("null")
		}
	case KindRawJSON:
		if json.Valid(a.Bytes) {
			buf.Write(a.Bytes)
		} else {
			appendJSONString(buf, string(a.Bytes))
		}
	case KindGroup:
		buf.WriteByte('{')
		first := true
		for i := range a.Group {
			appendAttrJSON(buf, &first, a.Group[i])
		}
		buf.WriteByte('}')
	case KindAny:
		b, err := json.Marshal(a.Any)
		if err != nil {
			appendJSONString(buf, "<unsupported>")
		} else {
			buf.Write(b)
		}
	default:
		buf.WriteString("null")
	}
}
