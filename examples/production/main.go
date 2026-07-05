package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/oarkflow/zlog"
)

func main() {
	store, err := zlog.NewPersistentObservabilityStore(zlog.PersistentObservabilityOptions{
		Dir:       ".zlog-observability",
		Retention: zlog.RetentionPolicy{MaxAge: 24 * time.Hour, MaxRecords: 100000},
	})
	if err != nil {
		panic(err)
	}
	defer store.Close()

	stdout := zlog.NewWriterSink(os.Stdout, zlog.NewJSONEncoder(), zlog.TraceLevel)
	logger := zlog.New(zlog.Options{
		Level:        zlog.InfoLevel,
		Sink:         zlog.NewObservabilitySink(store, stdout),
		Async:        true,
		AsyncOptions: zlog.AsyncOptions{Capacity: 8192, BatchSize: 256},
		AddHostname:  true,
		AddPID:       true,
		IntegrityKey: []byte("replace-me"),
		Redactor:     zlog.EnterpriseRedactor(),
	})
	defer logger.Close()

	zlog.PrintStartupBanner(zlog.StartupBannerOptions{
		AppName: "payments-api", Service: "payments-api", Version: "1.0.0", Environment: "production",
		Level: logger.Level().String(), Format: "json", Async: true, Redaction: true, Integrity: true,
		Sinks: []string{"stdout", "observability"}, DashboardURL: "http://localhost:8080/obs/dashboard", AdminURL: "http://localhost:8080/_zlog/stats", Writer: os.Stdout,
	})

	mux := http.NewServeMux()
	mux.Handle("/_zlog/", zlog.SecureAdminHandler(logger, zlog.AdminAuthOptions{APIKeys: []string{"dev-admin-key"}, AllowCIDRs: []string{"127.0.0.0/8", "::1/128"}, AuditLogger: logger}))
	obs := zlog.NewObservabilityHandler(store)
	obs.Prefix = "/obs/"
	obs.Auth = zlog.AdminAuthOptions{APIKeys: []string{"dev-admin-key"}, AllowCIDRs: []string{"127.0.0.0/8", "::1/128"}, AuditLogger: logger}
	mux.Handle("/obs/", obs)
	mux.Handle("/", zlog.HTTPMiddleware(zlog.HTTPMiddlewareOptions{Logger: logger})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, span := logger.StartSpan(r.Context(), "http.request")
		defer span.End()
		logger.InfoContext(ctx, "request handled", zlog.String("path", r.URL.Path), zlog.String("user_id", "demo-user"))
		_, _ = fmt.Fprintln(w, "ok")
	})))

	am := zlog.AlertManager{Store: store, Logger: logger, Rules: []zlog.AlertRule{{Name: "api-errors", Service: "payments-api", MinErrors: 5, Window: time.Minute}}}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			_, _ = am.Evaluate(context.Background())
		}
	}()

	panic(http.ListenAndServe(":8080", mux))
}
