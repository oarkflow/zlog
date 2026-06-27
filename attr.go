package zlog

import (
	"errors"
	"net"
	"net/netip"
	"time"
)

type Kind uint8

const (
	KindInvalid Kind = iota
	KindString
	KindBytes
	KindBool
	KindInt64
	KindUint64
	KindFloat64
	KindDuration
	KindTime
	KindError
	KindGroup
	KindRawJSON
	KindAny
)

type Attr struct {
	Key   string
	Kind  Kind
	I64   int64
	U64   uint64
	Str   string
	Bytes []byte
	Group []Attr
	Any   any
}

func String(k, v string) Attr       { return Attr{Key: k, Kind: KindString, Str: v} }
func Bytes(k string, v []byte) Attr { return Attr{Key: k, Kind: KindBytes, Bytes: v} }
func Bool(k string, v bool) Attr {
	if v {
		return Attr{Key: k, Kind: KindBool, I64: 1}
	}
	return Attr{Key: k, Kind: KindBool}
}
func Int(k string, v int) Attr       { return Attr{Key: k, Kind: KindInt64, I64: int64(v)} }
func Int64(k string, v int64) Attr   { return Attr{Key: k, Kind: KindInt64, I64: v} }
func Uint(k string, v uint) Attr     { return Attr{Key: k, Kind: KindUint64, U64: uint64(v)} }
func Uint64(k string, v uint64) Attr { return Attr{Key: k, Kind: KindUint64, U64: v} }
func Float64(k string, v float64) Attr {
	return Attr{Key: k, Kind: KindFloat64, U64: mathFloat64bits(v)}
}
func Duration(k string, v time.Duration) Attr { return Attr{Key: k, Kind: KindDuration, I64: int64(v)} }
func Time(k string, v time.Time) Attr         { return Attr{Key: k, Kind: KindTime, Any: v} }
func Err(err error) Attr {
	if err == nil {
		return Attr{Key: "error", Kind: KindInvalid}
	}
	return Attr{Key: "error", Kind: KindError, Str: err.Error(), Any: err}
}
func ErrKey(k string, err error) Attr {
	if err == nil {
		return Attr{Key: k, Kind: KindInvalid}
	}
	return Attr{Key: k, Kind: KindError, Str: err.Error(), Any: err}
}
func Group(k string, attrs ...Attr) Attr { return Attr{Key: k, Kind: KindGroup, Group: attrs} }
func RawJSON(k string, raw []byte) Attr  { return Attr{Key: k, Kind: KindRawJSON, Bytes: raw} }
func Any(k string, v any) Attr {
	if err, ok := v.(error); ok {
		return ErrKey(k, err)
	}
	return Attr{Key: k, Kind: KindAny, Any: v}
}
func IP(k string, ip net.IP) Attr       { return String(k, ip.String()) }
func Addr(k string, ip netip.Addr) Attr { return String(k, ip.String()) }
func TraceID(v string) Attr             { return String("trace_id", v) }
func SpanID(v string) Attr              { return String("span_id", v) }
func RequestID(v string) Attr           { return String("request_id", v) }
func CorrelationID(v string) Attr       { return String("correlation_id", v) }
func TenantID(v string) Attr            { return String("tenant_id", v) }
func UserID(v string) Attr              { return String("user_id", v) }

func ErrorChain(err error) Attr {
	if err == nil {
		return Attr{Key: "error_chain", Kind: KindInvalid}
	}
	chain := make([]Attr, 0, 4)
	for err != nil {
		chain = append(chain, String("message", err.Error()))
		err = errors.Unwrap(err)
	}
	return Group("error_chain", chain...)
}

func KV(k, v string) Attr          { return String(k, v) }
func Sensitive(k, v string) Attr   { return String(k, v) }
func Password(v string) Attr       { return String("password", v) }
func Token(v string) Attr          { return String("token", v) }
func APIKey(v string) Attr         { return String("api_key", v) }
func Authorization(v string) Attr  { return String("authorization", v) }
func SessionID(v string) Attr      { return String("session_id", v) }
func EventName(v string) Attr      { return String("event.name", v) }
func EventAction(v string) Attr    { return String("event.action", v) }
func EventOutcome(v string) Attr   { return String("event.outcome", v) }
func ResourceID(v string) Attr     { return String("resource.id", v) }
func ActorID(v string) Attr        { return String("actor.id", v) }
func ServiceName(v string) Attr    { return String("service.name", v) }
func ServiceVersion(v string) Attr { return String("service.version", v) }
func Environment(v string) Attr    { return String("deployment.environment", v) }

func ParentSpanID(v string) Attr { return String("parent_span_id", v) }
func SpanName(v string) Attr     { return String("span.name", v) }
func SpanKind(v string) Attr     { return String("span.kind", v) }
func SpanStatus(v string) Attr   { return String("span.status", v) }
func ToolName(v string) Attr     { return String("tool.name", v) }
func ToolCallID(v string) Attr   { return String("tool.call_id", v) }
func WorkflowID(v string) Attr   { return String("workflow.id", v) }
func TaskID(v string) Attr       { return String("task.id", v) }
