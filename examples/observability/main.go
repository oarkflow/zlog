package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/oarkflow/zlog"
)

type service struct {
	name    string
	version string
	env     string
	node    string
	tool    string
	log     *zlog.Logger
	store   *zlog.ObservabilityStore
}

func main() {
	addr := flag.String("addr", ":8090", "listen address")
	flag.Parse()

	store := zlog.NewObservabilityStore(zlog.ObservabilityOptions{MaxLogs: 100000, MaxSpans: 100000, MaxMetrics: 200000})
	sink := zlog.NewObservabilitySink(store, zlog.NewWriterSink(os.Stdout, zlog.NewConsoleEncoder(), zlog.InfoLevel))

	base := zlog.New(zlog.Options{
		Level: zlog.DebugLevel,
		Sink:  sink,
		Static: []zlog.Attr{
			zlog.String("deployment.environment", "local"),
			zlog.String("service.instance.id", "demo-instance-1"),
		},
		AddHostname: true,
		AddPID:      true,
	})

	services := []service{
		{name: "api-gateway", version: "1.2.0", env: "local", node: "node-a", tool: "router", log: base.Named("api"), store: store},
		{name: "workflow-engine", version: "2.4.1", env: "local", node: "node-b", tool: "dag-runner", log: base.Named("workflow"), store: store},
		{name: "sms-service", version: "0.9.7", env: "local", node: "node-c", tool: "sms-sender", log: base.Named("sms"), store: store},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, svc := range services {
		go generateServiceTraffic(ctx, svc)
		go generateMetrics(ctx, svc)
	}

	mux := http.NewServeMux()
	obs := zlog.NewObservabilityHandler(store)
	mux.Handle("/", obs)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) })

	fmt.Println("zlog observability demo")
	fmt.Println("dashboard: http://localhost" + *addr)
	fmt.Println("logs API:  http://localhost" + *addr + "/api/v1/logs?service=api-gateway&limit=20&desc=true")
	fmt.Println("spans API: http://localhost" + *addr + "/api/v1/spans?sort=duration&desc=true")
	fmt.Println("metrics:   http://localhost" + *addr + "/api/v1/metrics?name=http_requests_total")
	if err := http.ListenAndServe(*addr, mux); err != nil {
		panic(err)
	}
}

func serviceContext(s service, req int) context.Context {
	ctx := context.Background()
	ctx = zlog.ContextWithRequestID(ctx, fmt.Sprintf("req-%06d", req))
	ctx = zlog.ContextWithCorrelationID(ctx, fmt.Sprintf("corr-%03d", req%20))
	ctx = zlog.ContextWithUserID(ctx, fmt.Sprintf("user-%02d", req%12))
	ctx = zlog.ContextWithTenantID(ctx, fmt.Sprintf("tenant-%02d", req%4))
	ctx = zlog.ContextWithService(ctx, s.name, s.version, s.env)
	ctx = zlog.ContextWithTool(ctx, s.tool, fmt.Sprintf("call-%06d", req))
	ctx = zlog.ContextWithWorkflow(ctx, "notification-workflow", fmt.Sprintf("task-%06d", req))
	ctx = zlog.ContextWithAttrs(ctx, zlog.String("node.name", s.node), zlog.String("service.instance.id", s.name+"-"+s.node))
	return ctx
}

func generateServiceTraffic(ctx context.Context, s service) {
	ticker := time.NewTicker(700 * time.Millisecond)
	defer ticker.Stop()
	i := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			i++
			reqCtx := serviceContext(s, i)
			reqCtx, span := s.log.StartSpan(reqCtx, "handle.request", zlog.WithSpanKind(zlog.SpanKindServer), zlog.WithSpanStartEvent(true))
			s.log.InfoContext(reqCtx, "request.accepted", zlog.String("http.method", "POST"), zlog.String("http.route", "/api/send"))
			childCtx, child := s.log.StartSpan(reqCtx, "call."+s.tool, zlog.WithSpanKind(zlog.SpanKindTool), zlog.WithSpanStartEvent(true))
			time.Sleep(time.Duration(20+rand.Intn(180)) * time.Millisecond)
			if rand.Intn(18) == 0 {
				child.EndError(fmt.Errorf("simulated downstream failure"), zlog.String("error.kind", "demo"))
				s.log.ErrorContext(childCtx, "tool.call.failed", zlog.String("retry", "scheduled"))
				span.EndError(fmt.Errorf("request failed"))
			} else {
				child.Info("tool.call.completed", zlog.Int("items", 1+rand.Intn(5)))
				child.End(zlog.String("result", "ok"))
				span.End(zlog.Int("http.status_code", 200))
			}
		}
	}
}

func generateMetrics(ctx context.Context, s service) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var total float64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			total += float64(20 + rand.Intn(40))
			labels := map[string]string{"service": s.name, "node": s.node, "env": s.env}
			s.store.RecordMetric(zlog.ObsMetric{Time: time.Now(), Service: s.name, Node: s.node, Instance: s.name + "-" + s.node, Name: "http_requests_total", Value: total, Type: "counter", Labels: labels})
			s.store.RecordMetric(zlog.ObsMetric{Time: time.Now(), Service: s.name, Node: s.node, Instance: s.name + "-" + s.node, Name: "cpu_usage_percent", Value: 10 + rand.Float64()*60, Type: "gauge", Unit: "%", Labels: labels})
			s.store.RecordMetric(zlog.ObsMetric{Time: time.Now(), Service: s.name, Node: s.node, Instance: s.name + "-" + s.node, Name: "memory_usage_mb", Value: 128 + rand.Float64()*512, Type: "gauge", Unit: "MB", Labels: labels})
			s.store.RecordMetric(zlog.ObsMetric{Time: time.Now(), Service: s.name, Node: s.node, Instance: s.name + "-" + s.node, Name: "queue_depth", Value: float64(rand.Intn(100)), Type: "gauge", Labels: labels})
		}
	}
}
