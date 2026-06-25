package zlog

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type HTTPMiddlewareOptions struct {
	Logger          *Logger
	IncludeHeaders  bool
	HeaderAllowList []string // optional exact header names to include when IncludeHeaders is true
	ClientIPHeader  string
}
type responseCapture struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *responseCapture) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }
func (w *responseCapture) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}
func HTTPMiddleware(opts HTTPMiddlewareOptions) func(http.Handler) http.Handler {
	l := opts.Logger
	if l == nil {
		l = NewProduction()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseCapture{ResponseWriter: w}
			defer func() {
				if rec := recover(); rec != nil {
					l.ErrorContext(r.Context(), "http.panic", Any("panic", rec))
					http.Error(w, "internal server error", 500)
				}
				status := rw.status
				if status == 0 {
					status = 200
				}
				attrs := []Attr{String("http.method", r.Method), String("url.path", r.URL.EscapedPath()), String("url.query", safeQueryWithRedactor(r, l.redactor)), Int("http.status_code", status), Duration("duration", time.Since(start)), Int("bytes", rw.bytes), String("user_agent", r.UserAgent()), String("remote_addr", clientIP(r, opts.ClientIPHeader))}
				if rid := r.Header.Get("X-Request-Id"); rid != "" {
					attrs = append(attrs, RequestID(rid))
				}
				if opts.IncludeHeaders {
					attrs = append(attrs, Group("http.request.headers", headerAttrs(r.Header, opts.HeaderAllowList)...))
				}
				lvl := InfoLevel
				if status >= 500 {
					lvl = ErrorLevel
				} else if status >= 400 {
					lvl = WarnLevel
				}
				l.Log(lvl, "http.request", attrs...)
			}()
			next.ServeHTTP(rw, r)
		})
	}
}

func headerAttrs(h http.Header, allow []string) []Attr {
	attrs := make([]Attr, 0, len(h))
	for k, vals := range h {
		if len(allow) > 0 && !headerAllowed(k, allow) {
			continue
		}
		attrs = append(attrs, String(k, strings.Join(vals, ",")))
	}
	return attrs
}

func headerAllowed(k string, allow []string) bool {
	for _, a := range allow {
		if equalFoldASCII(k, a) {
			return true
		}
	}
	return false
}

func safeQuery(r *http.Request) string {
	return safeQueryWithRedactor(r, DefaultRedactor())
}

func safeQueryWithRedactor(r *http.Request, redactor Redactor) string {
	if r == nil || r.URL == nil || r.URL.RawQuery == "" {
		return ""
	}
	redactor = redactor.normalized()
	q := r.URL.Query()
	for k, vals := range q {
		for i, v := range vals {
			attr := String(k, v)
			redactAttrPath(&attr, redactor, "url.query")
			if attr.Kind == KindString && attr.Str != v {
				vals[i] = attr.Str
			}
		}
		q[k] = vals
	}
	return q.Encode()
}

func clientIP(r *http.Request, h string) string {
	if h != "" {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" {
			rid = strconv.FormatInt(time.Now().UnixNano(), 36)
		}
		w.Header().Set("X-Request-Id", rid)
		next.ServeHTTP(w, r.WithContext(ContextWithAttrs(r.Context(), RequestID(rid))))
	})
}
