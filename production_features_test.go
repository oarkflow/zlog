package zlog

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecureHandlerAPIKey(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	h := SecureHandler(next, AdminAuthOptions{APIKeys: []string{"secret"}})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/_zlog/stats", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/_zlog/stats", nil)
	req.Header.Set("X-Zlog-Admin-Key", "secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || strings.TrimSpace(rr.Body.String()) != "ok" {
		t.Fatalf("unexpected response %d %q", rr.Code, rr.Body.String())
	}
}

func TestPersistentObservabilityStoreReloads(t *testing.T) {
	dir := t.TempDir()
	st, err := NewPersistentObservabilityStore(PersistentObservabilityOptions{Dir: dir, SyncWrites: true})
	if err != nil {
		t.Fatal(err)
	}
	st.RecordLog(ObsLog{Time: time.Now(), Level: "error", Message: "boom", Service: "api"})
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st2, err := NewPersistentObservabilityStore(PersistentObservabilityOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	logs := st2.QueryLogs(ObsQuery{Service: "api", Level: "error"})
	if len(logs) != 1 || logs[0].Message != "boom" {
		t.Fatalf("expected reloaded log, got %#v", logs)
	}
}

func TestStartupBanner(t *testing.T) {
	b := StartupBanner(StartupBannerOptions{AppName: "test", Service: "svc", Async: true, Redaction: true})
	if !strings.Contains(b, "test") || !strings.Contains(b, "svc") || !strings.Contains(b, "async") {
		t.Fatalf("bad banner: %s", b)
	}
}

func TestValidateAndLoadYAMLConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "zlog.yaml")
	if err := os.WriteFile(path, []byte("level: info\nformat: json\nasync: true\n"), 0640); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfigAuto(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Level != "info" || !c.Async {
		t.Fatalf("bad config %#v", c)
	}
	if issues := ValidateConfig(c); len(issues) != 0 {
		t.Fatalf("unexpected issues %#v", issues)
	}
}

func TestAlertManager(t *testing.T) {
	st := NewObservabilityStore(ObservabilityOptions{})
	st.RecordLog(ObsLog{Time: time.Now(), Level: "error", Message: "boom", Service: "api"})
	var got []Alert
	am := AlertManager{Store: st, Rules: []AlertRule{{Name: "errors", Service: "api", MinErrors: 1}}, Sinks: []AlertSink{AlertFunc(func(ctx context.Context, a Alert) error { got = append(got, a); return nil })}}
	alerts, err := am.Evaluate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || len(got) != 1 {
		t.Fatalf("expected alert, got %#v %#v", alerts, got)
	}
}

func TestTopNDJSON(t *testing.T) {
	rows, err := TopNDJSON(bytes.NewBufferString(`{"level":"error","service.name":"api"}
{"level":"info","service.name":"api"}
`), "service.name", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["count"].(int) != 2 {
		t.Fatalf("bad rows %#v", rows)
	}
}

func TestEncryptedFileSinkRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secure.ndjson")
	s, err := NewEncryptedFileSink(EncryptedFileOptions{Path: path, Key: []byte("secret"), Level: TraceLevel, SyncWrite: true})
	if err != nil {
		t.Fatal(err)
	}
	l := New(Options{Level: InfoLevel, Sink: s})
	l.Info("secret event", String("password", "should-redact"))
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out bytes.Buffer
	if err := DecryptEncryptedLogFile(f, &out, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "secret event") || strings.Contains(out.String(), "should-redact") {
		t.Fatalf("unexpected decrypted log: %s", out.String())
	}
}
