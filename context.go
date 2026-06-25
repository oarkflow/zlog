package zlog

import "context"

type contextKey string

const loggerKey contextKey = "zlog.logger"
const attrsKey contextKey = "zlog.attrs"

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
func extractContextAttrs(ctx context.Context) []Attr {
	if ctx == nil {
		return nil
	}
	attrs, _ := ctx.Value(attrsKey).([]Attr)
	return attrs
}
