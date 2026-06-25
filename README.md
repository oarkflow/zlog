# zlog

`zlog` is a stdlib-only, async-first, structured Go logger built for high-throughput services. The common hot paths are designed to benchmark at `0 B/op` and `0 allocs/op` when using typed attributes and built-in encoders/sinks.

## Production-ready features included

- Stdlib only: no third-party dependencies.
- Structured typed attributes: string, bool, ints, uints, float, time, duration, bytes, error, group, raw JSON.
- Fast paths: `Info0`, `Info1`, `Info2`, `Log0`, `Log1`, `Log2` and typed variadic calls.
- Async non-blocking sink with bounded queue, batch drain, flush interval, drop policies, emergency sync fallback, shutdown drain, and drop counters.
- Multi-sink fanout with independent writer levels and formats.
- Encoders: JSON, console, logfmt.
- Console options: time layout, color, prettify, `key=value` coloring, pair separator, key-value separator.
- Time options: logger-level `TimeLayout` / `TimeFormat` propagated into encoders.
- File writer with size rotation, retention by backup count/age, compression, safe default permissions.
- Security redaction enabled by default for sensitive keys and obvious secret-like values.
- Value scanning detects Bearer/Basic credentials, JWT-like tokens, private keys, and Luhn-valid card numbers.
- Redactor supports allow keys, exact keys, substring keys, partial masking, and hashing.
- Audit and security helpers with stable event fields.
- Authentication, authorization, data access, and config-change event helpers.
- Optional tamper-evident HMAC hash chain with `IntegrityKey`.
- Static metadata: service, environment, hostname, process ID.
- Optional caller file/line/function.
- `context.Context` fields for request/trace/correlation IDs.
- HTTP middleware with request logging, panic logging, status, latency, bytes, user-agent, and client IP.
- `slog.Handler` adapter and stdlib `log.Logger` writer adapter.
- Internal stats snapshot, HTTP stats handler, and expvar publishing.
- Sampler support.
- Recovery helper.

## Missing essentials that were added in this hardened build

Earlier versions had the fast logger core but were missing several production controls. This build adds/fixes:

1. Value-based secret redaction, not only key-based redaction.
2. Configurable redaction policy from `Options`.
3. Compliance-ready HMAC hash-chain signing.
4. Async `Flush()` correctness: flush now drains queued records before flushing the wrapped sink.
5. Drop policy accounting in stats.
6. Queue depth in stats.
7. Safer rotating-file retention ordering.
8. Production and compliance option presets.
9. Host and process metadata injection.
10. Standardized auth/authz/data-access/config-change helpers.
11. Tests for value redaction, async flush drain, and integrity signing.

## Install

```bash
go get github.com/oarkflow/zlog
```

## Example

```go
package main

import (
	"context"
	"os"
	"time"

	"github.com/oarkflow/zlog"
)

func main() {
	file, err := zlog.NewRotatingFile(zlog.FileConfig{
		Path:       "./logs/app.log",
		MaxSize:    10 << 20,
		MaxBackups: 5,
		Compress:   true,
	})
	if err != nil {
		panic(err)
	}

	color := true
	pretty := true

	multi := zlog.NewMultiSink(
		zlog.NewWriterSink(os.Stdout, zlog.NewConsoleEncoder(), zlog.DebugLevel),
		zlog.NewWriterSink(file, zlog.NewJSONEncoder(), zlog.InfoLevel),
	)

	log := zlog.New(zlog.Options{
		Level:       zlog.DebugLevel,
		Sink:        multi,
		Async:       true,
		AddCaller:   true,
		TimeLayout:  "2006-01-02 15:04:05.000",
		ConsoleColor: &color,
		Prettify:    &pretty,
		KVSeparator: "=",
		Static: []zlog.Attr{
			zlog.ServiceName("demo"),
			zlog.Environment("dev"),
		},
		AddHostname: true,
		AddPID:      true,
		// IntegrityKey: []byte("replace-with-secret-key"),
	})
	defer log.Shutdown(context.Background())

	ctx := zlog.ContextWithAttrs(context.Background(), zlog.RequestID("req_123"), zlog.TraceID("tr_abc"))
	log.InfoContext(ctx, "user.login",
		zlog.UserID("u_1"),
		zlog.String("password", "secret-will-redact"),
		zlog.Duration("latency", 42*time.Millisecond),
	)
	log.Audit("admin.changed_role", "success", zlog.ActorID("admin_1"), zlog.ResourceID("user:u_1"))
	log.Security("auth.failed", "failure", zlog.String("ip", "127.0.0.1"))
}
```

Console output includes all static, context, caller, and event fields. Sensitive fields render as `[REDACTED]`.

## Production preset

```go
log := zlog.NewProductionLogger("billing-api", "prod")
defer log.Shutdown(context.Background())

log.Info2("invoice.created", zlog.String("invoice.id", "inv_1"), zlog.Int("amount", 100))
```

## Compliance preset with integrity signing

```go
log := zlog.NewComplianceLogger("admin-api", "prod", []byte("hmac-secret"))
defer log.Shutdown(context.Background())

log.DataAccess("user.exported", "admin_1", "user:u_1", "success")
```

Each record receives `log.integrity.hmac`.

## Redaction configuration

```go
redactor := zlog.EnterpriseRedactor()
redactor.Mask = "***"
redactor.MaskPartial = true
redactor.KeepLast = 4
redactor.ExactKeys = append(redactor.ExactKeys, "db.password")
redactor.AllowKeys = append(redactor.AllowKeys, "public_token_hint")

log := zlog.New(zlog.Options{
	Level:    zlog.InfoLevel,
	Sink:     zlog.NewWriterSink(os.Stdout, zlog.NewJSONEncoder(), zlog.TraceLevel),
	Redactor: redactor,
})
```

## Async behavior

`Async: true` wraps the sink with a bounded non-blocking queue. Default production behavior drops newest logs when full and synchronously writes emergency-level logs.

Drop policies:

- `DropBlock`
- `DropNewest`
- `DropOldest`
- `DropDebugFirst`

`Flush()` drains the async queue before flushing the underlying sink. `Shutdown(ctx)` drains until closed or the context expires.

## Benchmarks

Run:

```bash
go test -bench=. -benchmem
```

Current benchmark from this build on the validation machine:

```txt
BenchmarkDisabled-56          17.80 ns/op    0 B/op    0 allocs/op
BenchmarkJSONInfo-56         979.0 ns/op     0 B/op    0 allocs/op
BenchmarkAsyncEnqueue-56     351.0 ns/op     0 B/op    0 allocs/op
BenchmarkDisabled0-56          4.571 ns/op   0 B/op    0 allocs/op
BenchmarkAsyncEnqueue2-56    339.3 ns/op     0 B/op    0 allocs/op
```

Exact ns/op depends on CPU, Go version, redaction policy, caller capture, async queue contention, and sink speed. The target guarantee is `0 B/op` and `0 allocs/op` for typed built-in hot paths.

## Important performance rules

Use typed attrs:

```go
log.Info2("event", zlog.String("user.id", "u1"), zlog.Int("attempt", 1))
```

Avoid slow paths in hot loops:

- `Any`
- `fmt.Sprintf`
- arbitrary maps
- caller capture
- stack capture
- context extraction
- custom encoders that allocate

## Security notes

The default redactor uses a configurable `RedactionDictionary` for secret fields plus optional value scanning. Preset field names are not hidden inside matcher code: they live in `DefaultRedactionDictionary()` and can be replaced or extended from code or JSON config. Use `EnterpriseRedactor()` or `ComplianceRedactor(...)` for PII, HIPAA and PCI dictionaries. This reduces accidental leakage, but it is not a replacement for secure application design. Do not log secrets intentionally. Keep audit logs access-controlled, encrypted at rest where required, and retained according to your policy.

## Enterprise redaction and compliance controls

This build now treats redaction as an end-to-end sink policy and record policy. `Options.Redactor` is propagated into `WriterSink`, `MultiSink`, and wrapped async sinks, so custom policies apply consistently across fanout outputs.

Configurable presets:

- `ComplianceSecrets`: uses `RedactionDictionary.Secrets`.
- `CompliancePII`: uses `RedactionDictionary.PII`.
- `ComplianceHIPAA`: uses `RedactionDictionary.PII` and `RedactionDictionary.HIPAA`. HIPAA compliance still requires operational controls such as access control, retention, encryption, audit review and policy enforcement outside the logger.
- `CompliancePCI`: uses `RedactionDictionary.PCI`.

`request_id`, `trace_id`, `span_id`, `correlation_id`, and `user_id` are not redacted by the default secrets policy. Redact `user_id` or any other identifier by adding it to `ExactKeys`, `SensitiveFields`, or your configured dictionary.

Example with caller-defined sensitive fields:

```go
redactor := zlog.EnterpriseRedactor() // or ComplianceRedactor(ComplianceSecrets, CompliancePII, ComplianceHIPAA)
redactor.Mask = "[hidden]"
redactor = redactor.WithSensitiveFields(true,
    "profile.custom_secret", // exact nested path
    "tenant.internal_code",
)
redactor = redactor.WithSensitiveFields(false,
    "license_key", // substring match
    "medical_notes",
)
redactor.AllowKeys = append(redactor.AllowKeys, "public_token_hint")

log := zlog.New(zlog.Options{
    Level:    zlog.InfoLevel,
    Redactor: redactor,
    Sink:     zlog.NewWriterSink(os.Stdout, zlog.NewJSONEncoder(), zlog.TraceLevel),
})
```


Example with a fully caller-owned dictionary:

```go
dict := zlog.DefaultRedactionDictionary().Merge(zlog.RedactionDictionary{
    PII: []string{"user_id", "account_id"},
    HIPAA: []string{"member_number", "claim_id"},
})

redactor := zlog.EnterpriseRedactor().WithDictionary(dict)
log := zlog.New(zlog.Options{Redactor: redactor})
```

To replace all preset fields instead of extending the starter dictionary:

```go
redactor := zlog.ComplianceRedactor(zlog.ComplianceSecrets).WithDictionary(zlog.RedactionDictionary{
    Secrets: []string{"password", "access_token", "private_key"},
})
```

Redaction now covers:

- normal typed attributes,
- nested `Group` attributes with full path matching,
- `Any` maps, structs, pointers, slices and arrays,
- `RawJSON` objects/arrays by parsing and re-emitting sanitized JSON,
- HTTP query strings and included request headers.

HTTP middleware example:

```go
handler := zlog.HTTPMiddleware(zlog.HTTPMiddlewareOptions{
    Logger: log,
    IncludeHeaders: true,
    HeaderAllowList: []string{"X-Request-Id", "Authorization", "Cookie"},
})(mux)
```

`Authorization`, `Cookie`, `Set-Cookie`, token, secret, PII, HIPAA and PCI-like fields are still redacted before the event is encoded.

### JSON config

```json
{
  "level": "info",
  "format": "json",
  "async": true,
  "file": "./logs/app.log",
  "max_size": 10485760,
  "add_caller": true,
  "compliance": ["secrets", "pii", "hipaa", "pci"],
  "sensitive_fields": ["license_key", "medical_notes"],
  "exact_sensitive_fields": ["profile.custom_secret", "tenant.internal_code"],
  "allow_fields": ["public_token_hint"],
  "redaction_dictionary": {
    "pii": ["user_id", "account_id"],
    "hipaa": ["claim_id"],
    "secrets": ["tenant_secret"]
  },
  "replace_redaction_dictionary": false,
  "value_scan": true,
  "redaction_mask": "[hidden]",
  "mask_partial": true,
  "keep_last": 4
}
```

### Operational controls still required

For enterprise and regulated environments, combine this logger with restricted log access, encryption at rest, transport encryption, short retention for sensitive logs, immutable audit storage where required, centralized review/alerting, and tests that assert representative PII/PHI/PCI examples do not appear in emitted logs.
