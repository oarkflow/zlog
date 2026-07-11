package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oarkflow/zlog"
)

func usage() {
	fmt.Fprintf(os.Stderr, `zlog commands:
  tail <file>
  query [--level error] [--request-id id] [--trace-id id] [--user-id id] [--service name] [--tool name] [--sort time] <file>
  verify --key secret <file>
  redact-check <file>
  config validate <config.json|yaml|bcl>
  config print-effective <config.json|yaml|bcl>
  doctor [--config path] [--log-file path]
  stats <file>
  top-errors [--limit 20] <file>
  top-services [--limit 20] <file>
  export [--format json|ndjson] [--level error] <file>
  serve-dashboard [--addr :8088] [--dir .zlog-observability] [--api-key key]
  compact-observability [--dir .zlog-observability] [--max-age 168h] [--max-records 100000]
  decrypt --key secret <encrypted-log-file>
  secure init|append|verify|proof|checkpoint|export ...
  forensic-verify <bundle.tar.gz>
  legal-hold place|release|list|verify ...
`)
}
func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "tail":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		fatal(tail(os.Args[2]))
	case "query":
		runQuery(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "redact-check":
		runRedactCheck(os.Args[2:])
	case "config":
		runConfig(os.Args[2:])
	case "doctor":
		runDoctor(os.Args[2:])
	case "stats":
		runStats(os.Args[2:])
	case "top-errors":
		runTop(os.Args[2:], "message", true)
	case "top-services":
		runTop(os.Args[2:], "service.name", false)
	case "export":
		runExport(os.Args[2:])
	case "serve-dashboard":
		runServeDashboard(os.Args[2:])
	case "compact-observability":
		runCompact(os.Args[2:])
	case "decrypt":
		runDecrypt(os.Args[2:])
	case "secure":
		runSecure(os.Args[2:])
	case "forensic-verify":
		runForensicVerify(os.Args[2:])
	case "legal-hold":
		runLegalHold(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func runQuery(args []string) {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	level := fs.String("level", "", "")
	field := fs.String("field", "", "")
	value := fs.String("value", "", "")
	contains := fs.String("contains", "", "")
	requestID := fs.String("request-id", "", "")
	correlationID := fs.String("correlation-id", "", "")
	traceID := fs.String("trace-id", "", "")
	spanID := fs.String("span-id", "", "")
	parentSpanID := fs.String("parent-span-id", "", "")
	userID := fs.String("user-id", "", "")
	tenantID := fs.String("tenant-id", "", "")
	service := fs.String("service", "", "")
	tool := fs.String("tool", "", "")
	workflowID := fs.String("workflow-id", "", "")
	taskID := fs.String("task-id", "", "")
	sortBy := fs.String("sort", "", "")
	desc := fs.Bool("desc", false, "")
	limit := fs.Int("limit", 0, "")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	f := mustOpen(fs.Arg(0))
	defer f.Close()
	fatal(zlog.QueryNDJSON(f, os.Stdout, zlog.QueryOptions{Level: *level, Field: *field, Value: *value, Contains: *contains, RequestID: *requestID, CorrelationID: *correlationID, TraceID: *traceID, SpanID: *spanID, ParentSpanID: *parentSpanID, UserID: *userID, TenantID: *tenantID, Service: *service, Tool: *tool, WorkflowID: *workflowID, TaskID: *taskID, SortBy: *sortBy, Desc: *desc, Limit: *limit}))
}
func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	key := fs.String("key", "", "")
	jsonOut := fs.Bool("json", false, "")
	_ = fs.Parse(args)
	if *key == "" || fs.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	f := mustOpen(fs.Arg(0))
	defer f.Close()
	rep, err := zlog.VerifyIntegrityNDJSON(f, []byte(*key))
	fatal(err)
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(rep)
	} else {
		fmt.Printf("total=%d valid=%d invalid=%d first_bad_line=%d\n", rep.Total, rep.Valid, rep.Invalid, rep.FirstBadLine)
	}
	if rep.Invalid > 0 {
		os.Exit(1)
	}
}
func runRedactCheck(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	f := mustOpen(args[0])
	defer f.Close()
	b, err := io.ReadAll(f)
	fatal(err)
	leaks := 0
	for _, word := range []string{"password", "secret", "token", "api_key", "authorization", "private_key", "credit_card"} {
		if containsFold(string(b), word) {
			fmt.Fprintf(os.Stderr, "possible sensitive token found: %s\n", word)
			leaks++
		}
	}
	if leaks > 0 {
		os.Exit(1)
	}
	fmt.Println("no obvious sensitive field names found")
}
func runConfig(args []string) {
	if len(args) < 2 {
		usage()
		os.Exit(2)
	}
	c, err := zlog.LoadConfigAuto(args[1])
	fatal(err)
	issues := zlog.ValidateConfig(c)
	switch args[0] {
	case "validate":
		if len(issues) > 0 {
			_ = json.NewEncoder(os.Stdout).Encode(issues)
			os.Exit(1)
		}
		fmt.Println("config ok")
	case "print-effective":
		_ = json.NewEncoder(os.Stdout).Encode(c)
	default:
		usage()
		os.Exit(2)
	}
}
func runDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfg := fs.String("config", "", "")
	logFile := fs.String("log-file", "", "")
	_ = fs.Parse(args)
	result := map[string]any{"go_mod": fileExists("go.mod"), "cwd": must(os.Getwd()), "time": time.Now().Format(time.RFC3339)}
	if *cfg != "" {
		c, err := zlog.LoadConfigAuto(*cfg)
		result["config_loaded"] = err == nil
		if err != nil {
			result["config_error"] = err.Error()
		} else {
			result["config_issues"] = zlog.ValidateConfig(c)
		}
	}
	if *logFile != "" {
		if st, err := os.Stat(*logFile); err == nil {
			result["log_file_bytes"] = st.Size()
			result["log_file"] = *logFile
		} else {
			result["log_file_error"] = err.Error()
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
func runStats(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	f := mustOpen(args[0])
	defer f.Close()
	rows, err := zlog.TopNDJSON(f, "level", 0)
	fatal(err)
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"by_level": rows})
}
func runTop(args []string, field string, onlyErrors bool) {
	fs := flag.NewFlagSet("top", flag.ExitOnError)
	limit := fs.Int("limit", 20, "")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	path := fs.Arg(0)
	if onlyErrors {
		tmp, err := os.CreateTemp("", "zlog-errors-*.ndjson")
		fatal(err)
		defer os.Remove(tmp.Name())
		f := mustOpen(path)
		fatal(zlog.QueryNDJSON(f, tmp, zlog.QueryOptions{Level: "error"}))
		_ = f.Close()
		_, _ = tmp.Seek(0, 0)
		rows, err := zlog.TopNDJSON(tmp, field, *limit)
		fatal(err)
		_ = json.NewEncoder(os.Stdout).Encode(rows)
		_ = tmp.Close()
		return
	}
	f := mustOpen(path)
	defer f.Close()
	rows, err := zlog.TopNDJSON(f, field, *limit)
	fatal(err)
	_ = json.NewEncoder(os.Stdout).Encode(rows)
}
func runExport(args []string) {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	format := fs.String("format", "ndjson", "")
	level := fs.String("level", "", "")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	f := mustOpen(fs.Arg(0))
	defer f.Close()
	if *format == "json" {
		tmp, err := os.CreateTemp("", "zlog-export-*.ndjson")
		fatal(err)
		defer os.Remove(tmp.Name())
		fatal(zlog.QueryNDJSON(f, tmp, zlog.QueryOptions{Level: *level}))
		_, _ = tmp.Seek(0, 0)
		var arr []map[string]any
		dec := json.NewDecoder(tmp)
		for {
			var m map[string]any
			if err := dec.Decode(&m); err != nil {
				break
			}
			arr = append(arr, m)
		}
		_ = json.NewEncoder(os.Stdout).Encode(arr)
		_ = tmp.Close()
		return
	}
	fatal(zlog.QueryNDJSON(f, os.Stdout, zlog.QueryOptions{Level: *level}))
}
func runServeDashboard(args []string) {
	fs := flag.NewFlagSet("serve-dashboard", flag.ExitOnError)
	addr := fs.String("addr", ":8088", "")
	dir := fs.String("dir", ".zlog-observability", "")
	apiKey := fs.String("api-key", "", "")
	_ = fs.Parse(args)
	store, err := zlog.NewPersistentObservabilityStore(zlog.PersistentObservabilityOptions{Dir: *dir})
	fatal(err)
	defer store.Close()
	h := zlog.NewObservabilityHandler(store)
	if *apiKey != "" {
		h.Auth = zlog.AdminAuthOptions{APIKeys: []string{*apiKey}}
	}
	fmt.Println("zlog dashboard listening on", *addr)
	fatal(http.ListenAndServe(*addr, h))
}
func runCompact(args []string) {
	fs := flag.NewFlagSet("compact-observability", flag.ExitOnError)
	dir := fs.String("dir", ".zlog-observability", "")
	maxAge := fs.Duration("max-age", 0, "")
	maxRecords := fs.Int("max-records", 0, "")
	_ = fs.Parse(args)
	store, err := zlog.NewPersistentObservabilityStore(zlog.PersistentObservabilityOptions{Dir: *dir, Retention: zlog.RetentionPolicy{MaxAge: *maxAge, MaxRecords: *maxRecords}})
	fatal(err)
	defer store.Close()
	fatal(store.Compact(nilContext{}))
	fmt.Println("compacted", *dir)
}

func runDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	key := fs.String("key", "", "")
	_ = fs.Parse(args)
	if *key == "" || fs.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	f := mustOpen(fs.Arg(0))
	defer f.Close()
	fatal(zlog.DecryptEncryptedLogFile(f, os.Stdout, []byte(*key)))
}

type nilContext struct{}

func (nilContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (nilContext) Done() <-chan struct{}       { return nil }
func (nilContext) Err() error                  { return nil }
func (nilContext) Value(any) any               { return nil }

func tail(path string) error {
	var off int64
	for {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		if _, err = f.Seek(off, 0); err != nil {
			_ = f.Close()
			return err
		}
		n, err := io.Copy(os.Stdout, f)
		off += n
		_ = f.Close()
		if err != nil {
			return err
		}
		time.Sleep(time.Second)
	}
}
func mustOpen(path string) *os.File { f, err := os.Open(filepath.Clean(path)); fatal(err); return f }
func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func fileExists(path string) bool { _, err := os.Stat(path); return err == nil }
func must[T any](v T, err error) T {
	if err != nil {
		return v
	}
	return v
}
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

func runSecure(args []string) {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "init":
		fs := flag.NewFlagSet("secure init", flag.ExitOnError)
		configPath := fs.String("config", "zlog-secure.json", "")
		dir := fs.String("dir", "audit-data", "")
		stream := fs.String("stream", "audit", "")
		tenant := fs.String("tenant", "", "")
		force := fs.Bool("force", false, "")
		_ = fs.Parse(args[1:])
		if !*force && fileExists(*configPath) {
			fatal(fmt.Errorf("config already exists: %s", *configPath))
		}
		base := filepath.Dir(*configPath)
		fatal(os.MkdirAll(base, 0700))
		dataKeyPath := filepath.Join(base, "zlog-data.key")
		signerPath := filepath.Join(base, "zlog-signer.pem")
		publicPath := filepath.Join(base, "zlog-signer.pub.pem")
		if !*force {
			for _, p := range []string{dataKeyPath, signerPath, publicPath} {
				if fileExists(p) {
					fatal(fmt.Errorf("file already exists: %s", p))
				}
			}
		}
		key, err := zlog.GenerateAuditDataKey()
		fatal(err)
		fatal(zlog.SaveAuditDataKey(dataKeyPath, key))
		signer, err := zlog.GenerateEd25519CheckpointSigner("zlog-signing-1")
		fatal(err)
		fatal(zlog.SavePrivateSigner(signerPath, signer, 0600))
		pub, err := signer.PublicKeyPEM()
		fatal(err)
		fatal(os.WriteFile(publicPath, pub, 0644))
		cfg := zlog.SecureStoreConfig{Version: "zlog.secure-config.v1", Dir: *dir, StreamID: *stream, TenantID: *tenant, DataKeyFile: filepath.Base(dataKeyPath), DataKeyID: "zlog-data-1", SignerPrivateKeyFile: filepath.Base(signerPath), SignerPublicKeyFile: filepath.Base(publicPath), SignerKeyID: signer.KeyID(), SignatureAlgorithm: signer.Algorithm(), CheckpointEvery: 1024, SegmentMaxRecords: 100000, SegmentMaxBytes: 128 << 20, MaxRecordBytes: 4 << 20, SyncPolicy: zlog.SyncAlways, RecoverPartial: true}
		fatal(zlog.SaveSecureStoreConfig(*configPath, cfg))
		fmt.Printf("initialized config=%s data_key=%s signer=%s public_key=%s\n", *configPath, dataKeyPath, signerPath, publicPath)
	case "append":
		fs := flag.NewFlagSet("secure append", flag.ExitOnError)
		configPath := fs.String("config", "zlog-secure.json", "")
		recordPath := fs.String("record", "-", "")
		_ = fs.Parse(args[1:])
		cfg, err := zlog.LoadSecureStoreConfig(*configPath)
		fatal(err)
		store, err := cfg.Open(false)
		fatal(err)
		defer store.Close()
		var r io.Reader = os.Stdin
		if *recordPath != "-" {
			f := mustOpen(*recordPath)
			defer f.Close()
			r = f
		}
		dec := json.NewDecoder(io.LimitReader(r, int64(cfg.MaxRecordBytes)+1))
		dec.DisallowUnknownFields()
		var rec zlog.AuditRecord
		fatal(dec.Decode(&rec))
		var extra any
		if err = dec.Decode(&extra); err == nil {
			fatal(fmt.Errorf("record contains trailing JSON"))
		} else if err != io.EOF {
			fatal(err)
		}
		receipt, err := store.Append(context.Background(), rec)
		fatal(err)
		_ = json.NewEncoder(os.Stdout).Encode(receipt)
	case "verify":
		fs := flag.NewFlagSet("secure verify", flag.ExitOnError)
		configPath := fs.String("config", "zlog-secure.json", "")
		_ = fs.Parse(args[1:])
		cfg, err := zlog.LoadSecureStoreConfig(*configPath)
		fatal(err)
		store, err := cfg.Open(true)
		fatal(err)
		defer store.Close()
		rep, err := store.Verify(context.Background(), zlog.VerifyOptions{DecryptContent: true, Strict: true})
		fatal(err)
		_ = json.NewEncoder(os.Stdout).Encode(rep)
		if !rep.Valid {
			os.Exit(1)
		}
	case "proof":
		fs := flag.NewFlagSet("secure proof", flag.ExitOnError)
		configPath := fs.String("config", "zlog-secure.json", "")
		recordID := fs.String("record-id", "", "")
		_ = fs.Parse(args[1:])
		if *recordID == "" {
			fatal(fmt.Errorf("--record-id is required"))
		}
		cfg, err := zlog.LoadSecureStoreConfig(*configPath)
		fatal(err)
		store, err := cfg.Open(false)
		fatal(err)
		defer store.Close()
		proof, err := store.InclusionProof(context.Background(), *recordID)
		fatal(err)
		_ = json.NewEncoder(os.Stdout).Encode(proof)
	case "checkpoint":
		fs := flag.NewFlagSet("secure checkpoint", flag.ExitOnError)
		configPath := fs.String("config", "zlog-secure.json", "")
		_ = fs.Parse(args[1:])
		cfg, err := zlog.LoadSecureStoreConfig(*configPath)
		fatal(err)
		store, err := cfg.Open(false)
		fatal(err)
		defer store.Close()
		cp, err := store.LatestCheckpoint(context.Background())
		fatal(err)
		_ = json.NewEncoder(os.Stdout).Encode(cp)
	case "export":
		fs := flag.NewFlagSet("secure export", flag.ExitOnError)
		configPath := fs.String("config", "zlog-secure.json", "")
		records := fs.String("record-ids", "", "")
		output := fs.String("output", "zlog-forensic.tar.gz", "")
		caseID := fs.String("case-id", "", "")
		reason := fs.String("reason", "forensic export", "")
		exporter := fs.String("exporter", "zlog-cli", "")
		_ = fs.Parse(args[1:])
		if strings.TrimSpace(*records) == "" {
			fatal(fmt.Errorf("--record-ids is required"))
		}
		cfg, err := zlog.LoadSecureStoreConfig(*configPath)
		fatal(err)
		store, err := cfg.Open(false)
		fatal(err)
		defer store.Close()
		signer, err := zlog.LoadPrivateSigner(cfg.SignerPrivateKeyFile, cfg.SignerKeyID)
		fatal(err)
		f, err := os.OpenFile(*output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		fatal(err)
		_, err = zlog.ExportForensicBundle(context.Background(), store, f, zlog.ForensicExportOptions{RecordIDs: splitNonEmpty(*records), CaseID: *caseID, Reason: *reason, ExporterID: *exporter, Signer: signer})
		closeErr := f.Close()
		fatal(err)
		fatal(closeErr)
		fmt.Println(*output)
	default:
		usage()
		os.Exit(2)
	}
}

func runForensicVerify(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	f := mustOpen(args[0])
	defer f.Close()
	rep, err := zlog.VerifyForensicBundle(context.Background(), f, 1<<30)
	fatal(err)
	_ = json.NewEncoder(os.Stdout).Encode(rep)
	if !rep.Valid {
		os.Exit(1)
	}
}

func runLegalHold(args []string) {
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet("legal-hold", flag.ExitOnError)
	configPath := fs.String("config", "zlog-secure.json", "")
	ledgerPath := fs.String("ledger", "legal-holds.jsonl", "")
	holdID := fs.String("hold-id", "", "")
	caseID := fs.String("case-id", "", "")
	reason := fs.String("reason", "", "")
	actor := fs.String("actor", "zlog-cli", "")
	recordIDs := fs.String("record-ids", "", "")
	_ = fs.Parse(args[1:])
	cfg, err := zlog.LoadSecureStoreConfig(*configPath)
	fatal(err)
	signer, err := zlog.LoadPrivateSigner(cfg.SignerPrivateKeyFile, cfg.SignerKeyID)
	fatal(err)
	reg := zlog.NewPublicKeyRegistry()
	pub, err := signer.PublicKeyPEM()
	fatal(err)
	fatal(reg.RegisterPEM(signer.KeyID(), signer.Algorithm(), pub))
	if !filepath.IsAbs(*ledgerPath) {
		*ledgerPath = filepath.Join(filepath.Dir(*configPath), *ledgerPath)
	}
	ledger, err := zlog.OpenLegalHoldLedger(*ledgerPath, signer, reg)
	fatal(err)
	switch args[0] {
	case "place":
		if *reason == "" {
			fatal(fmt.Errorf("--reason is required"))
		}
		e, err := ledger.Place(context.Background(), zlog.ActiveLegalHold{HoldID: *holdID, StreamID: cfg.StreamID, RecordIDs: splitNonEmpty(*recordIDs), CaseID: *caseID, Reason: *reason, ActorID: *actor})
		fatal(err)
		_ = json.NewEncoder(os.Stdout).Encode(e)
	case "release":
		if *holdID == "" || *reason == "" {
			fatal(fmt.Errorf("--hold-id and --reason are required"))
		}
		e, err := ledger.Release(context.Background(), *holdID, *actor, *reason)
		fatal(err)
		_ = json.NewEncoder(os.Stdout).Encode(e)
	case "list":
		_ = json.NewEncoder(os.Stdout).Encode(ledger.Active())
	case "verify":
		n, err := ledger.Verify(context.Background())
		fatal(err)
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"valid": true, "entries": n})
	default:
		usage()
		os.Exit(2)
	}
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
