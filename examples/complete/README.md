# zlog complete context/span logging example

This example demonstrates the whole platform in one runnable app:

- request, correlation, trace, span, user, tenant, service, workflow, task, tool and baggage context
- parent/child span lifecycle logs with `span.start`, normal `span.end`, and error `span.end`
- HTTP middleware with request/response logs and W3C `traceparent`/`baggage` propagation
- local JSON log file with HMAC integrity chain
- console logging
- async logging
- rotating file output
- durable exporter spool with retry and circuit breaker
- mock webhook exporter endpoint
- admin endpoints and Prometheus metrics
- redaction of sensitive values
- CLI query, sort, filter and integrity verification

## Run

```bash
go run ./examples/complete -addr :8085 -log-dir ./tmp/zlog-complete
```

## Send a correlated request

```bash
curl -s \
  -H 'X-Request-Id: req_demo_001' \
  -H 'X-Correlation-Id: corr_demo_001' \
  -H 'X-User-Id: user_42' \
  -H 'X-Tenant-Id: tenant_np' \
  -H 'baggage: plan=enterprise,tool=sms' \
  'http://127.0.0.1:8085/api/send-sms?to=%2B9779800000000&message=hello'
```

The request produces related records that can be grouped by:

- `request_id=req_demo_001`
- `correlation_id=corr_demo_001`
- `user_id=user_42`
- `tenant_id=tenant_np`
- `service.name=sms-api`
- `workflow.id=workflow_sms_send`
- `task.id=task_http_request`
- `tool.name=sms_provider_http`
- one shared `trace_id`
- parent/child `span_id` and `parent_span_id`

## Query logs

```bash
go run ./cmd/zlog query --request-id req_demo_001 --sort time ./tmp/zlog-complete/app.ndjson

go run ./cmd/zlog query --user-id user_42 --service sms-api --sort time ./tmp/zlog-complete/app.ndjson

go run ./cmd/zlog query --tool sms_provider_http --sort span.duration --desc ./tmp/zlog-complete/app.ndjson

go run ./cmd/zlog query --field workflow.id --value workflow_sms_send --sort time ./tmp/zlog-complete/app.ndjson
```

## Verify integrity

```bash
go run ./cmd/zlog verify --key demo-integrity-key ./tmp/zlog-complete/app.ndjson
```

Expected result after a normal run:

```text
total=17 valid=17 invalid=0 first_bad_line=0
```

## Admin and metrics endpoints

```bash
curl -s http://127.0.0.1:8085/_zlog/stats
curl -s http://127.0.0.1:8085/_zlog/metrics
curl -s http://127.0.0.1:8085/_zlog/health
curl -X POST 'http://127.0.0.1:8085/_zlog/level?level=debug'
```

## Durable spool demo

Start with the mock exporter down:

```bash
go run ./examples/complete -collector-down=true
```

Generate logs, then bring the mock exporter back:

```bash
curl -X POST 'http://127.0.0.1:8085/mock/export/toggle?down=false'
```

The durable sink keeps failed exporter writes in `./tmp/zlog-complete/spool` and drains them when the exporter recovers.
