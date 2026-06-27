package zlog

import "context"

type contextKey string

const loggerKey contextKey = "zlog.logger"
const attrsKey contextKey = "zlog.attrs"
const logContextKey contextKey = "zlog.context"

// LogContext stores common correlation dimensions that should travel with a request,
// job, workflow, tool call, or service boundary. The values are emitted as normal
// structured fields so JSON/logfmt/console output and local queries can filter them.
type LogContext struct {
	RequestID      string
	CorrelationID  string
	TraceID        string
	SpanID         string
	ParentSpanID   string
	TraceFlags     string
	UserID         string
	TenantID       string
	ServiceName    string
	ServiceVersion string
	Environment    string
	ToolName       string
	ToolCallID     string
	WorkflowID     string
	TaskID         string
	SessionID      string
	Baggage        map[string]string
	Attrs          []Attr
}

func IntoContext(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, loggerKey, l)
}
func FromContext(ctx context.Context) (*Logger, bool) {
	l, ok := ctx.Value(loggerKey).(*Logger)
	return l, ok
}
func ContextWithAttrs(ctx context.Context, attrs ...Attr) context.Context {
	old, _ := ctx.Value(attrsKey).([]Attr)
	cp := append(append([]Attr(nil), old...), attrs...)
	return context.WithValue(ctx, attrsKey, cp)
}

func ContextWithLogContext(ctx context.Context, lc LogContext) context.Context {
	if old, ok := ctx.Value(logContextKey).(LogContext); ok {
		lc = mergeLogContext(old, lc)
	}
	if lc.TraceID != "" || lc.SpanID != "" || lc.TraceFlags != "" {
		ctx = ContextWithTrace(ctx, TraceContext{TraceID: lc.TraceID, SpanID: lc.SpanID, TraceFlags: lc.TraceFlags})
	}
	return context.WithValue(ctx, logContextKey, lc)
}
func LogContextFromContext(ctx context.Context) (LogContext, bool) {
	lc, ok := ctx.Value(logContextKey).(LogContext)
	if !ok {
		lc = LogContext{}
	}
	if tc, ok := TraceFromContext(ctx); ok {
		if lc.TraceID == "" {
			lc.TraceID = tc.TraceID
		}
		if lc.SpanID == "" {
			lc.SpanID = tc.SpanID
		}
		if lc.TraceFlags == "" {
			lc.TraceFlags = tc.TraceFlags
		}
	}
	return lc, ok || lc.TraceID != "" || lc.SpanID != ""
}
func ContextWithRequestID(ctx context.Context, v string) context.Context {
	return ContextWithLogContext(ctx, LogContext{RequestID: v})
}
func ContextWithCorrelationID(ctx context.Context, v string) context.Context {
	return ContextWithLogContext(ctx, LogContext{CorrelationID: v})
}
func ContextWithUserID(ctx context.Context, v string) context.Context {
	return ContextWithLogContext(ctx, LogContext{UserID: v})
}
func ContextWithTenantID(ctx context.Context, v string) context.Context {
	return ContextWithLogContext(ctx, LogContext{TenantID: v})
}
func ContextWithService(ctx context.Context, name, version, env string) context.Context {
	return ContextWithLogContext(ctx, LogContext{ServiceName: name, ServiceVersion: version, Environment: env})
}
func ContextWithTool(ctx context.Context, name, callID string) context.Context {
	return ContextWithLogContext(ctx, LogContext{ToolName: name, ToolCallID: callID})
}
func ContextWithWorkflow(ctx context.Context, workflowID, taskID string) context.Context {
	return ContextWithLogContext(ctx, LogContext{WorkflowID: workflowID, TaskID: taskID})
}
func ContextWithBaggage(ctx context.Context, k, v string) context.Context {
	lc, _ := LogContextFromContext(ctx)
	if lc.Baggage == nil {
		lc.Baggage = map[string]string{}
	}
	cp := make(map[string]string, len(lc.Baggage)+1)
	for kk, vv := range lc.Baggage {
		cp[kk] = vv
	}
	cp[k] = v
	lc.Baggage = cp
	return ContextWithLogContext(ctx, lc)
}

func mergeLogContext(a, b LogContext) LogContext {
	out := a
	if b.RequestID != "" {
		out.RequestID = b.RequestID
	}
	if b.CorrelationID != "" {
		out.CorrelationID = b.CorrelationID
	}
	if b.TraceID != "" {
		out.TraceID = b.TraceID
	}
	if b.SpanID != "" {
		out.SpanID = b.SpanID
	}
	if b.ParentSpanID != "" {
		out.ParentSpanID = b.ParentSpanID
	}
	if b.TraceFlags != "" {
		out.TraceFlags = b.TraceFlags
	}
	if b.UserID != "" {
		out.UserID = b.UserID
	}
	if b.TenantID != "" {
		out.TenantID = b.TenantID
	}
	if b.ServiceName != "" {
		out.ServiceName = b.ServiceName
	}
	if b.ServiceVersion != "" {
		out.ServiceVersion = b.ServiceVersion
	}
	if b.Environment != "" {
		out.Environment = b.Environment
	}
	if b.ToolName != "" {
		out.ToolName = b.ToolName
	}
	if b.ToolCallID != "" {
		out.ToolCallID = b.ToolCallID
	}
	if b.WorkflowID != "" {
		out.WorkflowID = b.WorkflowID
	}
	if b.TaskID != "" {
		out.TaskID = b.TaskID
	}
	if b.SessionID != "" {
		out.SessionID = b.SessionID
	}
	if len(b.Baggage) > 0 {
		out.Baggage = make(map[string]string, len(a.Baggage)+len(b.Baggage))
		for k, v := range a.Baggage {
			out.Baggage[k] = v
		}
		for k, v := range b.Baggage {
			out.Baggage[k] = v
		}
	}
	if len(b.Attrs) > 0 {
		out.Attrs = append(append([]Attr(nil), a.Attrs...), b.Attrs...)
	}
	return out
}

func (lc LogContext) AttrsList() []Attr {
	attrs := make([]Attr, 0, 20+len(lc.Attrs)+len(lc.Baggage))
	if lc.RequestID != "" {
		attrs = append(attrs, RequestID(lc.RequestID))
	}
	if lc.CorrelationID != "" {
		attrs = append(attrs, CorrelationID(lc.CorrelationID))
	}
	if lc.TraceID != "" {
		attrs = append(attrs, TraceID(lc.TraceID))
	}
	if lc.SpanID != "" {
		attrs = append(attrs, SpanID(lc.SpanID))
	}
	if lc.ParentSpanID != "" {
		attrs = append(attrs, ParentSpanID(lc.ParentSpanID))
	}
	if lc.TraceFlags != "" {
		attrs = append(attrs, String("trace_flags", lc.TraceFlags))
	}
	if lc.UserID != "" {
		attrs = append(attrs, UserID(lc.UserID))
	}
	if lc.TenantID != "" {
		attrs = append(attrs, TenantID(lc.TenantID))
	}
	if lc.ServiceName != "" {
		attrs = append(attrs, ServiceName(lc.ServiceName))
	}
	if lc.ServiceVersion != "" {
		attrs = append(attrs, ServiceVersion(lc.ServiceVersion))
	}
	if lc.Environment != "" {
		attrs = append(attrs, Environment(lc.Environment))
	}
	if lc.ToolName != "" {
		attrs = append(attrs, ToolName(lc.ToolName))
	}
	if lc.ToolCallID != "" {
		attrs = append(attrs, ToolCallID(lc.ToolCallID))
	}
	if lc.WorkflowID != "" {
		attrs = append(attrs, WorkflowID(lc.WorkflowID))
	}
	if lc.TaskID != "" {
		attrs = append(attrs, TaskID(lc.TaskID))
	}
	if lc.SessionID != "" {
		attrs = append(attrs, SessionID(lc.SessionID))
	}
	if len(lc.Baggage) > 0 {
		b := make([]Attr, 0, len(lc.Baggage))
		for k, v := range lc.Baggage {
			b = append(b, String(k, v))
		}
		attrs = append(attrs, Group("baggage", b...))
	}
	attrs = append(attrs, lc.Attrs...)
	return attrs
}

func extractContextAttrs(ctx context.Context) []Attr {
	if ctx == nil {
		return nil
	}
	var out []Attr
	if lc, ok := LogContextFromContext(ctx); ok {
		out = append(out, lc.AttrsList()...)
	}
	attrs, _ := ctx.Value(attrsKey).([]Attr)
	out = append(out, attrs...)
	return out
}
