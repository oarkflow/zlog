package zlog

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type patientPayload struct {
	PatientID string `json:"patient_id"`
	Email     string `json:"email"`
	Note      string `json:"note"`
}

func TestCustomSensitiveFieldsRedactNestedAnyAndRawJSON(t *testing.T) {
	var buf bytes.Buffer
	r := EnterpriseRedactor().WithSensitiveFields(true, "profile.custom_secret")
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(&buf, NewJSONEncoder(), TraceLevel), Redactor: r})

	log.Info("nested", Any("profile", map[string]any{
		"custom_secret": "open-sesame",
		"email":         "patient@example.com",
		"ok":            "visible",
	}), RawJSON("payload", []byte(`{"patient_id":"p-123","note":"ok"}`)))

	out := buf.String()
	if strings.Contains(out, "open-sesame") || strings.Contains(out, "patient@example.com") || strings.Contains(out, "p-123") {
		t.Fatalf("sensitive data leaked: %s", out)
	}
	if !strings.Contains(out, "visible") || !strings.Contains(out, "ok") {
		t.Fatalf("non-sensitive fields missing: %s", out)
	}
}

func TestStructAnyHIPAARedaction(t *testing.T) {
	var buf bytes.Buffer
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(&buf, NewJSONEncoder(), TraceLevel), Redactor: ComplianceRedactor(ComplianceHIPAA)})
	log.Info("patient", Any("payload", patientPayload{PatientID: "p-123", Email: "patient@example.com", Note: "follow-up"}))
	out := buf.String()
	if strings.Contains(out, "p-123") || strings.Contains(out, "patient@example.com") {
		t.Fatalf("HIPAA/PII field leaked: %s", out)
	}
	if !strings.Contains(out, "follow-up") {
		t.Fatalf("expected non-sensitive note: %s", out)
	}
}

func TestOptionsRedactorPropagatesToMultiSink(t *testing.T) {
	var a, b bytes.Buffer
	redactor := EnterpriseRedactor().WithSensitiveFields(true, "tenant.internal_code")
	log := New(Options{Level: InfoLevel, Redactor: redactor, Sink: NewMultiSink(
		NewWriterSink(&a, NewJSONEncoder(), TraceLevel),
		NewWriterSink(&b, NewJSONEncoder(), TraceLevel),
	)})
	log.Info("x", String("tenant.internal_code", "secret-code"))
	if strings.Contains(a.String(), "secret-code") || strings.Contains(b.String(), "secret-code") {
		t.Fatalf("custom redactor did not propagate: a=%s b=%s", a.String(), b.String())
	}
}

func TestHTTPMiddlewareRedactsHeadersAndQuery(t *testing.T) {
	var buf bytes.Buffer
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(&buf, NewJSONEncoder(), TraceLevel), Redactor: EnterpriseRedactor()})
	h := HTTPMiddleware(HTTPMiddlewareOptions{Logger: log, IncludeHeaders: true})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	req := httptest.NewRequest(http.MethodGet, "/pay?token=abc123secret&email=patient@example.com&ok=yes", nil)
	req.Header.Set("Authorization", "Bearer abc.def.ghi")
	req.Header.Set("X-Request-Id", "req1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	out := buf.String()
	if strings.Contains(out, "abc123secret") || strings.Contains(out, "patient@example.com") || strings.Contains(out, "Bearer") {
		t.Fatalf("HTTP sensitive data leaked: %s", out)
	}
	if !json.Valid([]byte(out)) {
		t.Fatalf("invalid json: %s", out)
	}
}

func TestDefaultRedactorDoesNotRedactObservabilityIDs(t *testing.T) {
	var buf bytes.Buffer
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(&buf, NewJSONEncoder(), TraceLevel)})
	log.Info("user.login", String("service.name", "demo"), String("env", "dev"), String("request_id", "req-123"), String("trace_id", "trace-456"), String("user_id", "user-789"), String("password", "secret"))
	out := buf.String()
	if !strings.Contains(out, "req-123") || !strings.Contains(out, "trace-456") || !strings.Contains(out, "user-789") {
		t.Fatalf("observability/user IDs should not be redacted by default: %s", out)
	}
	if strings.Contains(out, "secret") || !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("password should be redacted: %s", out)
	}
}

func TestConfigurableDictionaryCanRedactUserID(t *testing.T) {
	var buf bytes.Buffer
	r := DefaultRedactor().WithDictionary(DefaultRedactionDictionary().Merge(RedactionDictionary{PII: []string{"user_id"}}))
	r.Presets = []CompliancePreset{CompliancePII}
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(&buf, NewJSONEncoder(), TraceLevel), Redactor: r})
	log.Info("x", String("user_id", "user-789"), String("trace_id", "trace-456"))
	out := buf.String()
	if strings.Contains(out, "user-789") || !strings.Contains(out, "trace-456") {
		t.Fatalf("configured dictionary policy not applied correctly: %s", out)
	}
}
