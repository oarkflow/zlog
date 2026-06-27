package zlog

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type HTTPMiddlewareOptions struct {
	Logger             *Logger
	IncludeHeaders     bool
	HeaderAllowList    []string
	ClientIPHeader     string
	SkipPaths          []string
	RouteName          func(*http.Request) string
	LogResponseHeaders bool
}

type responseCapture struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (w *responseCapture) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.status = code
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}
func (w *responseCapture) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += n
	return n, err
}
func (w *responseCapture) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if !w.wrote {
			w.WriteHeader(http.StatusOK)
		}
		f.Flush()
	}
}
func (w *responseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer does not support hijack")
	}
	return h.Hijack()
}
func (w *responseCapture) Push(target string, opts *http.PushOptions) error {
	p, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return p.Push(target, opts)
}
func (w *responseCapture) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		if !w.wrote {
			w.WriteHeader(http.StatusOK)
		}
		n, err := rf.ReadFrom(r)
		w.bytes += int(n)
		return n, err
	}
	return io.Copy(w, r)
}

func HTTPMiddleware(opts HTTPMiddlewareOptions) func(http.Handler) http.Handler {
	l := opts.Logger
	if l == nil {
		l = NewProduction()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range opts.SkipPaths {
				if r.URL != nil && r.URL.Path == p {
					next.ServeHTTP(w, r)
					return
				}
			}
			start := time.Now()
			rw := &responseCapture{ResponseWriter: w}
			defer func() {
				if rec := recover(); rec != nil {
					l.ErrorContext(r.Context(), "http.panic", PanicStack(rec))
					if !rw.wrote {
						http.Error(rw, "internal server error", 500)
					}
				}
				status := rw.status
				if status == 0 {
					status = 200
				}
				attrs := []Attr{String("http.method", r.Method), String("url.path", r.URL.EscapedPath()), String("url.query", safeQueryWithRedactor(r, l.redactor)), Int("http.status_code", status), Duration("duration", time.Since(start)), Int("bytes", rw.bytes), String("user_agent", r.UserAgent()), String("remote_addr", clientIP(r, opts.ClientIPHeader)), String("network.protocol", r.Proto)}
				if r.TLS != nil {
					attrs = append(attrs, Bool("tls", true), String("tls.server_name", r.TLS.ServerName), String("tls.version", strconv.Itoa(int(r.TLS.Version))))
				}
				if rid := r.Header.Get("X-Request-Id"); rid != "" {
					attrs = append(attrs, RequestID(rid))
				}
				if opts.RouteName != nil {
					if name := opts.RouteName(r); name != "" {
						attrs = append(attrs, String("http.route", name))
					}
				}
				if opts.IncludeHeaders {
					attrs = append(attrs, Group("http.request.headers", headerAttrs(r.Header, opts.HeaderAllowList)...))
				}
				if opts.LogResponseHeaders {
					attrs = append(attrs, Group("http.response.headers", headerAttrs(rw.Header(), nil)...))
				}
				lvl := InfoLevel
				if status >= 500 {
					lvl = ErrorLevel
				} else if status >= 400 {
					lvl = WarnLevel
				}
				l.Log(lvl, "http.request", attrs...)
			}()
			ctx := ContextFromHTTP(r)
			next.ServeHTTP(rw, r.WithContext(ctx))
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
func safeQuery(r *http.Request) string { return safeQueryWithRedactor(r, DefaultRedactor()) }
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
