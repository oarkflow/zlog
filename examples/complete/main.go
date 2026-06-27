package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oarkflow/zlog"
)

const integrityKey = "demo-integrity-key"

type app struct {
	log           *zlog.Logger
	ring          *zlog.RingBufferSink
	logDir        string
	baseURL       string
	collectorDown atomic.Bool
	exported      atomic.Uint64
}

func main() {
	addr := flag.String("addr", ":8085", "HTTP listen address")
	logDir := flag.String("log-dir", "./tmp/zlog-complete", "directory for app.ndjson and durable spool")
	collectorDown := flag.Bool("collector-down", false, "start mock exporter endpoint in failing mode to demonstrate durable spool")
	flag.Parse()

	a, err := newApp(*addr, *logDir, *collectorDown)
	if err != nil {
		panic(err)
	}
	defer a.log.Shutdown(context.Background())

	mux := http.NewServeMux()
	mux.Handle("/_zlog/", a.log.AdminHandler())
	mux.HandleFunc("/", a.index)
	mux.HandleFunc("/api/send-sms", a.sendSMS)
	mux.HandleFunc("/mock/sms-provider", a.mockSMSProvider)
	mux.HandleFunc("/mock/export", a.mockExporter)
	mux.HandleFunc("/mock/export/toggle", a.toggleExporter)
	mux.HandleFunc("/recent", a.recent)

	h := zlog.HTTPMiddleware(zlog.HTTPMiddlewareOptions{
		Logger:          a.log,
		ClientIPHeader:  "X-Forwarded-For",
		SkipPaths:       []string{"/_zlog/health", "/mock/export"},
		RouteName:       routeName,
		IncludeHeaders:  true,
		HeaderAllowList: []string{"X-Request-Id", "X-Correlation-Id", "X-User-Id", "X-Tenant-Id", "X-Service-Name", "X-Tool-Name", "traceparent", "baggage"},
	})(mux)

	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		a.log.Info("example.server.start", zlog.String("addr", *addr), zlog.String("log.file", filepath.Join(*logDir, "app.ndjson")))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("example.server.error", zlog.ErrWithStack(err))
		}
	}()

	fmt.Printf("zlog complete example running on http://127.0.0.1%s\n", strings.TrimPrefix(*addr, "0.0.0.0"))
	fmt.Printf("log file: %s\n", filepath.Join(*logDir, "app.ndjson"))
	fmt.Println("try: curl -s -H 'X-Request-Id: req_demo_001' -H 'X-User-Id: user_42' 'http://127.0.0.1:8085/api/send-sms?to=+9779800000000&message=hello'")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func newApp(addr, logDir string, collectorDown bool) (*app, error) {
	if err := os.MkdirAll(logDir, 0750); err != nil {
		return nil, err
	}
	file, err := zlog.NewRotatingFile(zlog.FileConfig{Path: filepath.Join(logDir, "app.ndjson"), MaxSize: 20 << 20, MaxBackups: 5, Compress: false})
	if err != nil {
		return nil, err
	}

	console := zlog.NewWriterSink(os.Stdout, zlog.NewConsoleEncoder(), zlog.DebugLevel)
	signedFile := zlog.NewWriterSink(file, zlog.NewJSONEncoder(), zlog.TraceLevel)

	baseURL := "http://127.0.0.1" + addr
	endpoint := baseURL + "/mock/export"
	exporter := zlog.NewWebhookSink(endpoint, http.Header{"X-Zlog-Example": []string{"complete"}})
	exporter = zlog.NewCircuitBreakerSink(exporter, zlog.CircuitBreakerOptions{FailureThreshold: 3, ResetAfter: 2 * time.Second})
	exporter = zlog.NewRetrySink(exporter, zlog.RetryOptions{Attempts: 2, MinBackoff: 25 * time.Millisecond, MaxBackoff: 100 * time.Millisecond})
	durableExporter, err := zlog.NewDurableSink(exporter, zlog.DurableSinkOptions{Dir: filepath.Join(logDir, "spool"), Mode: zlog.SpoolOnFailure, DrainInterval: time.Second, BatchSize: 64})
	if err != nil {
		return nil, err
	}

	multi := zlog.NewMultiSink(console, signedFile, durableExporter)
	ring := zlog.NewRingBufferSink(multi, 256)
	log := zlog.New(zlog.Options{
		Level:        zlog.DebugLevel,
		Sink:         ring,
		Async:        true,
		AsyncOptions: zlog.AsyncOptions{Capacity: 4096, BatchSize: 128, DropPolicy: zlog.DropNewest, EmergencyLevel: zlog.ErrorLevel},
		Static: []zlog.Attr{
			zlog.ServiceName("sms-api"),
			zlog.ServiceVersion("1.2.3"),
			zlog.Environment("local"),
		},
		AddHostname:  true,
		AddPID:       true,
		AddCaller:    false,
		AddSequence:  true,
		IntegrityKey: []byte(integrityKey),
	})

	a := &app{log: log, ring: ring, logDir: logDir, baseURL: baseURL}
	a.collectorDown.Store(collectorDown)
	return a, nil
}

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, strings.TrimSpace(`
zlog complete example

Endpoints:
  GET /api/send-sms?to=+9779800000000&message=hello
  GET /recent
  GET /_zlog/stats
  GET /_zlog/metrics
  GET /_zlog/health
  POST /_zlog/level?level=debug
  POST /mock/export/toggle?down=true|false

Useful headers:
  X-Request-Id, X-Correlation-Id, X-User-Id, X-Tenant-Id,
  X-Service-Name, X-Service-Version, X-Tool-Name, X-Tool-Call-Id,
  traceparent, baggage
`)+"\n")
}

func (a *app) sendSMS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ctx = zlog.IntoContext(ctx, a.log)
	ctx = zlog.ContextWithService(ctx, "sms-api", "1.2.3", "local")
	ctx = zlog.ContextWithWorkflow(ctx, "workflow_sms_send", "task_http_request")
	ctx = zlog.ContextWithBaggage(ctx, "example", "complete")
	if r.Header.Get("X-User-Id") == "" {
		ctx = zlog.ContextWithUserID(ctx, valueOr(r.URL.Query().Get("user_id"), "user_42"))
	}
	if r.Header.Get("X-Tenant-Id") == "" {
		ctx = zlog.ContextWithTenantID(ctx, valueOr(r.URL.Query().Get("tenant_id"), "tenant_nepal"))
	}
	if r.Header.Get("X-Correlation-Id") == "" {
		ctx = zlog.ContextWithCorrelationID(ctx, "corr_sms_demo")
	}

	ctx, span := a.log.StartSpan(ctx, "api.send_sms", zlog.WithSpanKind(zlog.SpanKindServer), zlog.WithSpanStartEvent(true), zlog.WithSpanAttrs(zlog.String("http.route", "/api/send-sms")))
	defer span.End()

	to := valueOr(r.URL.Query().Get("to"), "+9779800000000")
	message := valueOr(r.URL.Query().Get("message"), "hello from zlog")
	a.log.InfoContext(ctx, "sms.request.received", zlog.String("sms.to", to), zlog.Int("sms.message_len", len(message)), zlog.Password("super-secret-query-value"))

	if err := a.validate(ctx, to, message); err != nil {
		span.EndError(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	providerID, err := a.callProvider(ctx, to, message)
	if err != nil {
		span.EndError(err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	a.log.Audit("sms.sent", "success", zlog.ActorID(valueOr(r.Header.Get("X-User-Id"), "user_42")), zlog.ResourceID(providerID), zlog.String("channel", "sms"))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "provider_message_id": providerID, "log_query": "go run ./cmd/zlog query --request-id " + valueOr(r.Header.Get("X-Request-Id"), "req_demo_001") + " --sort time " + filepath.Join(a.logDir, "app.ndjson")})
}

func (a *app) validate(ctx context.Context, to, message string) error {
	ctx, span := a.log.StartSpan(ctx, "sms.validate", zlog.WithSpanKind(zlog.SpanKindInternal), zlog.WithSpanStartEvent(true))
	defer span.End(zlog.Bool("sms.valid", true))
	if !strings.HasPrefix(to, "+") {
		err := errors.New("recipient must use international format")
		a.log.WarnContext(ctx, "sms.validation.failed", zlog.Err(err), zlog.String("sms.to", to))
		return err
	}
	if strings.TrimSpace(message) == "" {
		err := errors.New("message must not be empty")
		a.log.WarnContext(ctx, "sms.validation.failed", zlog.Err(err))
		return err
	}
	a.log.DebugContext(ctx, "sms.validation.ok", zlog.Int("sms.message_len", len(message)))
	return nil
}

func (a *app) callProvider(ctx context.Context, to, message string) (string, error) {
	ctx = zlog.ContextWithTool(ctx, "sms_provider_http", "tool_call_"+strconv.FormatInt(time.Now().UnixNano(), 36))
	ctx, span := a.log.StartSpan(ctx, "tool.sms_provider", zlog.WithSpanKind(zlog.SpanKindTool), zlog.WithSpanStartEvent(true), zlog.WithSpanAttrs(zlog.ToolName("sms_provider_http")))
	defer span.End()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/mock/sms-provider", strings.NewReader(`{"to":"`+to+`","message":"`+message+`"}`))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tool-Name", "sms_provider_http")
	req.Header.Set("X-Tool-Call-Id", "provider_call_001")
	zlog.InjectTraceparent(ctx, req.Header)
	zlog.InjectBaggage(ctx, req.Header)
	a.log.InfoContext(ctx, "tool.request.start", zlog.String("http.url", req.URL.String()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		span.EndError(err)
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		err := fmt.Errorf("provider returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		span.EndError(err)
		return "", err
	}
	a.log.InfoContext(ctx, "tool.request.end", zlog.Int("http.status_code", resp.StatusCode), zlog.Int("http.response.bytes", len(body)))
	return "msg_demo_123", nil
}

func (a *app) mockSMSProvider(w http.ResponseWriter, r *http.Request) {
	ctx := zlog.IntoContext(r.Context(), a.log)
	ctx, span := a.log.StartSpan(ctx, "mock.provider.accept", zlog.WithSpanKind(zlog.SpanKindServer), zlog.WithSpanStartEvent(true))
	defer span.End()
	a.log.InfoContext(ctx, "provider.message.accepted", zlog.String("provider", "mock-sms"))
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"id":"msg_demo_123","status":"accepted"}`)
}

func (a *app) mockExporter(w http.ResponseWriter, r *http.Request) {
	if a.collectorDown.Load() {
		http.Error(w, "mock exporter down", http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	if len(body) > 0 {
		a.exported.Add(1)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *app) toggleExporter(w http.ResponseWriter, r *http.Request) {
	down := r.URL.Query().Get("down") == "true"
	a.collectorDown.Store(down)
	_ = json.NewEncoder(w).Encode(map[string]any{"collector_down": down})
}

func (a *app) recent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"records": len(a.ring.Recent()), "exported_batches": a.exported.Load(), "collector_down": a.collectorDown.Load()})
}

func routeName(r *http.Request) string {
	switch {
	case r.URL.Path == "/api/send-sms":
		return "send_sms"
	case r.URL.Path == "/mock/sms-provider":
		return "mock_sms_provider"
	case strings.HasPrefix(r.URL.Path, "/_zlog/"):
		return "zlog_admin"
	default:
		return r.URL.Path
	}
}

func valueOr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
