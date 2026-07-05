package zlog

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ObservabilityBackend is the storage contract used by the dashboard/API.
// ObservabilityStore implements it, and PersistentObservabilityStore adds durable storage.
type ObservabilityBackend interface {
	RecordLog(ObsLog)
	RecordSpan(ObsSpan)
	RecordMetric(ObsMetric)
	QueryLogs(ObsQuery) []ObsLog
	QuerySpans(ObsQuery) []ObsSpan
	QueryMetrics(ObsQuery) []ObsMetric
	Services() []ObsServiceSummary
	Overview() map[string]any
	ChartData(time.Duration) map[string]any
}

// RetentionPolicy applies bounded operational retention across memory and file-backed stores.
type RetentionPolicy struct {
	MaxAge     time.Duration
	MaxRecords int
	MaxBytes   int64
}

// PersistentObservabilityOptions configures the durable local observability backend.
type PersistentObservabilityOptions struct {
	Dir        string
	Memory     ObservabilityOptions
	Retention  RetentionPolicy
	SyncWrites bool
}

// PersistentObservabilityStore is a stdlib-only NDJSON-backed observability store.
// It keeps a bounded in-memory index for fast dashboard queries and appends every event to disk.
type PersistentObservabilityStore struct {
	mem       *ObservabilityStore
	dir       string
	retention RetentionPolicy
	syncWrite bool
	mu        sync.Mutex
	logs      *os.File
	spans     *os.File
	metrics   *os.File
}

func NewPersistentObservabilityStore(opts PersistentObservabilityOptions) (*PersistentObservabilityStore, error) {
	if opts.Dir == "" {
		opts.Dir = ".zlog-observability"
	}
	if err := os.MkdirAll(opts.Dir, 0750); err != nil {
		return nil, err
	}
	p := &PersistentObservabilityStore{mem: NewObservabilityStore(opts.Memory), dir: opts.Dir, retention: opts.Retention, syncWrite: opts.SyncWrites}
	if err := p.loadExisting(); err != nil {
		return nil, err
	}
	var err error
	if p.logs, err = os.OpenFile(filepath.Join(opts.Dir, "logs.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640); err != nil {
		return nil, err
	}
	if p.spans, err = os.OpenFile(filepath.Join(opts.Dir, "spans.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640); err != nil {
		_ = p.logs.Close()
		return nil, err
	}
	if p.metrics, err = os.OpenFile(filepath.Join(opts.Dir, "metrics.ndjson"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640); err != nil {
		_ = p.logs.Close()
		_ = p.spans.Close()
		return nil, err
	}
	_ = p.Compact(context.Background())
	return p, nil
}

func (p *PersistentObservabilityStore) loadExisting() error {
	if err := loadNDJSON(filepath.Join(p.dir, "logs.ndjson"), func(l ObsLog) {
		if p.keepTime(l.Time) {
			p.mem.RecordLog(l)
		}
	}); err != nil {
		return err
	}
	if err := loadNDJSON(filepath.Join(p.dir, "spans.ndjson"), func(s ObsSpan) {
		if p.keepTime(s.Start) {
			p.mem.RecordSpan(s)
		}
	}); err != nil {
		return err
	}
	if err := loadNDJSON(filepath.Join(p.dir, "metrics.ndjson"), func(m ObsMetric) {
		if p.keepTime(m.Time) {
			p.mem.RecordMetric(m)
		}
	}); err != nil {
		return err
	}
	return nil
}

func loadNDJSON[T any](path string, emit func(T)) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var x T
		if json.Unmarshal([]byte(line), &x) == nil {
			emit(x)
		}
	}
	return sc.Err()
}

func (p *PersistentObservabilityStore) keepTime(t time.Time) bool {
	if p.retention.MaxAge <= 0 || t.IsZero() {
		return true
	}
	return t.After(time.Now().Add(-p.retention.MaxAge))
}

func (p *PersistentObservabilityStore) appendJSON(f *os.File, v any) {
	if f == nil {
		return
	}
	_ = json.NewEncoder(f).Encode(v)
	if p.syncWrite {
		_ = f.Sync()
	}
}

func (p *PersistentObservabilityStore) RecordLog(l ObsLog) {
	p.mem.RecordLog(l)
	p.mu.Lock()
	p.appendJSON(p.logs, l)
	p.mu.Unlock()
}
func (p *PersistentObservabilityStore) RecordSpan(s ObsSpan) {
	p.mem.RecordSpan(s)
	p.mu.Lock()
	p.appendJSON(p.spans, s)
	p.mu.Unlock()
}
func (p *PersistentObservabilityStore) RecordMetric(m ObsMetric) {
	p.mem.RecordMetric(m)
	p.mu.Lock()
	p.appendJSON(p.metrics, m)
	p.mu.Unlock()
}
func (p *PersistentObservabilityStore) QueryLogs(q ObsQuery) []ObsLog   { return p.mem.QueryLogs(q) }
func (p *PersistentObservabilityStore) QuerySpans(q ObsQuery) []ObsSpan { return p.mem.QuerySpans(q) }
func (p *PersistentObservabilityStore) QueryMetrics(q ObsQuery) []ObsMetric {
	return p.mem.QueryMetrics(q)
}
func (p *PersistentObservabilityStore) Services() []ObsServiceSummary { return p.mem.Services() }
func (p *PersistentObservabilityStore) Overview() map[string]any      { return p.mem.Overview() }
func (p *PersistentObservabilityStore) ChartData(d time.Duration) map[string]any {
	return p.mem.ChartData(d)
}

func (p *PersistentObservabilityStore) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var first error
	for _, f := range []*os.File{p.logs, p.spans, p.metrics} {
		if f == nil {
			continue
		}
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Compact rewrites NDJSON files according to MaxAge, MaxRecords and MaxBytes retention.
func (p *PersistentObservabilityStore) Compact(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	files := []struct {
		name    string
		current **os.File
	}{{"logs.ndjson", &p.logs}, {"spans.ndjson", &p.spans}, {"metrics.ndjson", &p.metrics}}
	for _, item := range files {
		if *item.current != nil {
			_ = (*item.current).Close()
			*item.current = nil
		}
		path := filepath.Join(p.dir, item.name)
		if err := compactNDJSON(ctx, path, p.retention); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err != nil {
			return err
		}
		*item.current = f
	}
	return nil
}

func compactNDJSON(ctx context.Context, path string, rp RetentionPolicy) error {
	if rp.MaxAge <= 0 && rp.MaxRecords <= 0 && rp.MaxBytes <= 0 {
		return nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	cutoff := time.Time{}
	if rp.MaxAge > 0 {
		cutoff = time.Now().Add(-rp.MaxAge)
	}
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !cutoff.IsZero() && lineOlderThan(line, cutoff) {
			continue
		}
		kept = append(kept, line)
	}
	if rp.MaxRecords > 0 && len(kept) > rp.MaxRecords {
		kept = kept[len(kept)-rp.MaxRecords:]
	}
	if rp.MaxBytes > 0 {
		var total int64
		start := len(kept)
		for i := len(kept) - 1; i >= 0; i-- {
			total += int64(len(kept[i]) + 1)
			if total > rp.MaxBytes {
				break
			}
			start = i
		}
		if start < len(kept) {
			kept = kept[start:]
		}
	}
	tmp := path + ".tmp"
	data := strings.Join(kept, "\n")
	if data != "" {
		data += "\n"
	}
	if err := os.WriteFile(tmp, []byte(data), 0640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func lineOlderThan(line string, cutoff time.Time) bool {
	var m map[string]any
	if json.Unmarshal([]byte(line), &m) != nil {
		return false
	}
	for _, k := range []string{"time", "start"} {
		if s, ok := m[k].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
				return t.Before(cutoff)
			}
		}
	}
	return false
}

// AdminAuthOptions secures admin and observability endpoints.
type AdminAuthOptions struct {
	APIKeys      []string
	BasicUsers   map[string]string
	AllowCIDRs   []string
	AllowIPs     []string
	RequireHTTPS bool
	ReadOnly     bool
	AuditLogger  *Logger
	Realm        string
}

func SecureAdminHandler(l *Logger, opts AdminAuthOptions) http.Handler {
	return SecureHandler(l.AdminHandler(), opts)
}
func SecureHandler(next http.Handler, opts AdminAuthOptions) http.Handler {
	nets, ips := compileAllowList(opts.AllowCIDRs, opts.AllowIPs)
	realm := opts.Realm
	if realm == "" {
		realm = "zlog"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if opts.RequireHTTPS && r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			http.Error(w, "https required", http.StatusUpgradeRequired)
			return
		}
		if len(nets) > 0 || len(ips) > 0 {
			if !allowedRemote(r, nets, ips) {
				auditAdmin(opts.AuditLogger, "admin.denied.ip", r)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		if opts.ReadOnly && r.Method != http.MethodGet && r.Method != http.MethodHead {
			auditAdmin(opts.AuditLogger, "admin.denied.read_only", r)
			http.Error(w, "read only", http.StatusForbidden)
			return
		}
		if len(opts.APIKeys) > 0 || len(opts.BasicUsers) > 0 {
			if !authOK(r, opts) {
				auditAdmin(opts.AuditLogger, "admin.denied.auth", r)
				w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		auditAdmin(opts.AuditLogger, "admin.allowed", r)
		next.ServeHTTP(w, r)
	})
}

func compileAllowList(cidrs, rawIPs []string) ([]*net.IPNet, []net.IP) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	ips := make([]net.IP, 0, len(rawIPs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			nets = append(nets, n)
		}
	}
	for _, s := range rawIPs {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			ips = append(ips, ip)
		}
	}
	return nets, ips
}
func allowedRemote(r *http.Request, nets []*net.IPNet, ips []net.IP) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, x := range ips {
		if x.Equal(ip) {
			return true
		}
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
func authOK(r *http.Request, opts AdminAuthOptions) bool {
	got := r.Header.Get("X-Zlog-Admin-Key")
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	for _, want := range opts.APIKeys {
		if constantStringEqual(got, want) {
			return true
		}
	}
	u, p, ok := r.BasicAuth()
	if ok {
		if want, exists := opts.BasicUsers[u]; exists && constantStringEqual(p, want) {
			return true
		}
	}
	return false
}
func constantStringEqual(a, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func auditAdmin(l *Logger, event string, r *http.Request) {
	if l != nil {
		l.Audit(event, "attempt", String("method", r.Method), String("path", r.URL.Path), String("remote_addr", r.RemoteAddr))
	}
}

// Alerting.
type AlertSeverity string

const (
	AlertInfo     AlertSeverity = "info"
	AlertWarning  AlertSeverity = "warning"
	AlertCritical AlertSeverity = "critical"
)

type AlertRule struct {
	Name       string        `json:"name"`
	Severity   AlertSeverity `json:"severity"`
	Window     time.Duration `json:"window"`
	Service    string        `json:"service,omitempty"`
	Metric     string        `json:"metric,omitempty"`
	ErrorRate  float64       `json:"error_rate,omitempty"`
	MinErrors  int           `json:"min_errors,omitempty"`
	P95Latency time.Duration `json:"p95_latency,omitempty"`
	QueueDepth int64         `json:"queue_depth,omitempty"`
	SilentFor  time.Duration `json:"silent_for,omitempty"`
}

type Alert struct {
	Rule      string        `json:"rule"`
	Severity  AlertSeverity `json:"severity"`
	Message   string        `json:"message"`
	Service   string        `json:"service,omitempty"`
	Value     float64       `json:"value,omitempty"`
	Threshold float64       `json:"threshold,omitempty"`
	Time      time.Time     `json:"time"`
}

type AlertSink interface {
	Alert(context.Context, Alert) error
}
type AlertFunc func(context.Context, Alert) error

func (f AlertFunc) Alert(ctx context.Context, a Alert) error { return f(ctx, a) }

type AlertManager struct {
	Store  ObservabilityBackend
	Rules  []AlertRule
	Sinks  []AlertSink
	Logger *Logger
}

func (m *AlertManager) Evaluate(ctx context.Context) ([]Alert, error) {
	if m == nil || m.Store == nil {
		return nil, nil
	}
	var alerts []Alert
	for _, r := range m.Rules {
		window := r.Window
		if window <= 0 {
			window = 5 * time.Minute
		}
		q := ObsQuery{Service: r.Service, Since: window, Limit: 100000}
		logs := m.Store.QueryLogs(q)
		total, errs := len(logs), 0
		for _, l := range logs {
			if isErrLevel(l.Level) {
				errs++
			}
		}
		if r.MinErrors > 0 && errs >= r.MinErrors {
			alerts = append(alerts, newAlert(r, r.Service, fmt.Sprintf("%d errors in %s", errs, window), float64(errs), float64(r.MinErrors)))
		}
		if r.ErrorRate > 0 && total > 0 {
			rate := float64(errs) / float64(total)
			if rate >= r.ErrorRate {
				alerts = append(alerts, newAlert(r, r.Service, fmt.Sprintf("error rate %.2f exceeded %.2f", rate, r.ErrorRate), rate, r.ErrorRate))
			}
		}
		if r.P95Latency > 0 {
			spans := m.Store.QuerySpans(q)
			ds := make([]int64, 0, len(spans))
			for _, sp := range spans {
				if sp.DurationNS > 0 {
					ds = append(ds, sp.DurationNS)
				}
			}
			if len(ds) > 0 {
				p95 := percentile(ds, .95)
				if p95 >= int64(r.P95Latency) {
					alerts = append(alerts, newAlert(r, r.Service, fmt.Sprintf("p95 latency %s exceeded %s", time.Duration(p95), r.P95Latency), float64(p95), float64(r.P95Latency)))
				}
			}
		}
		if r.SilentFor > 0 {
			svcs := m.Store.Services()
			seen := false
			for _, s := range svcs {
				if (r.Service == "" || s.Service == r.Service) && time.Since(s.LastSeen) <= r.SilentFor {
					seen = true
				}
			}
			if !seen {
				alerts = append(alerts, newAlert(r, r.Service, "service silent", 1, 1))
			}
		}
	}
	for _, a := range alerts {
		for _, s := range m.Sinks {
			if err := s.Alert(ctx, a); err != nil {
				return alerts, err
			}
		}
		if m.Logger != nil {
			m.Logger.Warn("zlog.alert", String("rule", a.Rule), String("severity", string(a.Severity)), String("message", a.Message))
		}
	}
	return alerts, nil
}
func newAlert(r AlertRule, svc, msg string, val, thr float64) Alert {
	sev := r.Severity
	if sev == "" {
		sev = AlertWarning
	}
	return Alert{Rule: r.Name, Severity: sev, Message: msg, Service: svc, Value: val, Threshold: thr, Time: time.Now()}
}

func NewWebhookAlertSink(endpoint string, headers http.Header) AlertSink {
	return AlertFunc(func(ctx context.Context, a Alert) error {
		var b strings.Builder
		_ = json.NewEncoder(&b).Encode(a)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(b.String()))
		if err != nil {
			return err
		}
		for k, vs := range headers {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("alert webhook status %d", resp.StatusCode)
		}
		return nil
	})
}

// StartupBanner returns a compact production startup summary.
type StartupBannerOptions struct {
	AppName, Service, Version, Environment, Level, Format, DashboardURL, AdminURL, SpoolDir string
	Async, Redaction, Integrity                                                             bool
	Sinks                                                                                   []string
	Writer                                                                                  io.Writer
}

func StartupBanner(o StartupBannerOptions) string {
	if o.AppName == "" {
		o.AppName = "zlog"
	}
	if o.Level == "" {
		o.Level = "info"
	}
	if o.Format == "" {
		o.Format = "json"
	}
	host, _ := os.Hostname()
	rows := [][2]string{{"service", o.Service}, {"version", o.Version}, {"env", o.Environment}, {"level", o.Level}, {"format", o.Format}, {"async", boolWord(o.Async)}, {"redaction", boolWord(o.Redaction)}, {"integrity", boolWord(o.Integrity)}, {"sinks", strings.Join(o.Sinks, ",")}, {"spool", o.SpoolDir}, {"dashboard", o.DashboardURL}, {"admin", o.AdminURL}, {"host", host}, {"pid", strconv.Itoa(os.Getpid())}}
	width := 54
	var b strings.Builder
	b.WriteString("┌" + strings.Repeat("─", width) + "┐\n")
	b.WriteString(fmt.Sprintf("│ %-"+strconv.Itoa(width-1)+"s│\n", o.AppName))
	b.WriteString("├" + strings.Repeat("─", width) + "┤\n")
	for _, r := range rows {
		if r[1] != "" {
			line := fmt.Sprintf("%-14s %s", r[0], r[1])
			if len(line) > width-1 {
				line = line[:width-2]
			}
			b.WriteString(fmt.Sprintf("│ %-"+strconv.Itoa(width-1)+"s│\n", line))
		}
	}
	b.WriteString("└" + strings.Repeat("─", width) + "┘\n")
	return b.String()
}
func PrintStartupBanner(o StartupBannerOptions) {
	out := o.Writer
	if out == nil {
		out = os.Stdout
	}
	_, _ = io.WriteString(out, StartupBanner(o))
}
func boolWord(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

// Config validation and non-JSON config loaders.
type ConfigIssue struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func ValidateConfig(c Config) []ConfigIssue {
	var out []ConfigIssue
	if c.Level != "" {
		if _, ok := ParseLevel(c.Level); !ok {
			out = append(out, ConfigIssue{"level", "invalid log level"})
		}
	}
	switch Format(c.Format) {
	case "", FormatJSON, FormatConsole, FormatLogfmt:
	default:
		out = append(out, ConfigIssue{"format", "invalid format"})
	}
	if c.AsyncCapacity < 0 {
		out = append(out, ConfigIssue{"async_capacity", "must be >= 0"})
	}
	if c.AsyncBatchSize < 0 {
		out = append(out, ConfigIssue{"async_batch_size", "must be >= 0"})
	}
	if c.Endpoint != "" && !(strings.HasPrefix(c.Endpoint, "http://") || strings.HasPrefix(c.Endpoint, "https://")) {
		out = append(out, ConfigIssue{"endpoint", "must be http or https URL"})
	}
	if c.File != "" {
		if dir := filepath.Dir(c.File); dir != "." {
			if st, err := os.Stat(dir); err != nil || !st.IsDir() {
				out = append(out, ConfigIssue{"file", "parent directory does not exist"})
			}
		}
	}
	if c.RetryAttempts < 0 {
		out = append(out, ConfigIssue{"retry_attempts", "must be >= 0"})
	}
	return out
}

func LoadConfigAuto(path string) (Config, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		return LoadYAMLConfig(path)
	case ".bcl":
		return LoadBCLConfig(path)
	default:
		return LoadConfig(path)
	}
}
func LoadYAMLConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return parseKVConfig(string(b))
}
func LoadBCLConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	return parseKVConfig(string(b))
}
func parseKVConfig(s string) (Config, error) {
	c := Config{}
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") || line == "{" || line == "}" {
			continue
		}
		line = strings.TrimSuffix(line, ",")
		parts := strings.Fields(line)
		var k, v string
		if strings.Contains(line, ":") {
			kv := strings.SplitN(line, ":", 2)
			k = strings.TrimSpace(kv[0])
			v = strings.TrimSpace(kv[1])
		} else if len(parts) >= 2 {
			k = parts[0]
			v = strings.Join(parts[1:], " ")
		} else {
			continue
		}
		v = strings.Trim(v, " \t\"'")
		setConfigKV(&c, k, v)
	}
	return c, nil
}
func setConfigKV(c *Config, k, v string) {
	switch strings.ToLower(strings.ReplaceAll(k, "-", "_")) {
	case "level":
		c.Level = v
	case "format":
		c.Format = v
	case "async":
		c.Async = parseBool(v)
	case "file":
		c.File = v
	case "max_size":
		c.MaxSize = parseI64(v)
	case "add_caller":
		c.AddCaller = parseBool(v)
	case "disable_redaction":
		c.DisableRedaction = parseBool(v)
	case "integrity_key":
		c.IntegrityKey = v
	case "add_hostname":
		c.AddHostname = parseBool(v)
	case "add_pid":
		c.AddPID = parseBool(v)
	case "async_capacity":
		c.AsyncCapacity = int(parseI64(v))
	case "async_batch_size":
		c.AsyncBatchSize = int(parseI64(v))
	case "durable_spool_dir":
		c.DurableSpoolDir = v
	case "delivery_mode":
		c.DeliveryMode = v
	case "exporter":
		c.Exporter = v
	case "endpoint":
		c.Endpoint = v
	case "retry_attempts":
		c.RetryAttempts = int(parseI64(v))
	case "retry_min_backoff":
		c.RetryMinBackoff = v
	case "retry_max_backoff":
		c.RetryMaxBackoff = v
	case "encrypted_file_key":
		c.EncryptedFileKey = v
	case "encrypted_file_key_id":
		c.EncryptedFileKeyID = v
	case "sync_writes":
		c.SyncWrites = parseBool(v)
	case "observability_dir":
		c.ObservabilityDir = v
	case "retention_max_age":
		c.RetentionMaxAge = v
	case "retention_max_records":
		c.RetentionMaxRecords = int(parseI64(v))
	case "retention_max_bytes":
		c.RetentionMaxBytes = parseI64(v)
	}
}
func parseBool(s string) bool { b, _ := strconv.ParseBool(strings.ToLower(s)); return b }
func parseI64(s string) int64 { n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return n }

// TopNDJSON returns ranked counts by a JSON field from local NDJSON logs.
func TopNDJSON(r io.Reader, field string, limit int) ([]map[string]any, error) {
	if field == "" {
		field = "message"
	}
	counts := map[string]int{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			k := fmt.Sprint(fieldValue(m, field))
			if k != "" && k != "<nil>" {
				counts[k]++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	type kv struct {
		K string
		V int
	}
	xs := make([]kv, 0, len(counts))
	for k, v := range counts {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].V > xs[j].V })
	if limit > 0 && len(xs) > limit {
		xs = xs[:limit]
	}
	out := make([]map[string]any, 0, len(xs))
	for _, x := range xs {
		out = append(out, map[string]any{"name": x.K, "count": x.V})
	}
	return out, nil
}
