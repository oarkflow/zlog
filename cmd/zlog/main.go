package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/oarkflow/zlog"
)

func usage() {
	fmt.Fprintf(os.Stderr, "zlog commands:\n  tail <file>\n  query [--level error] [--request-id id] [--trace-id id] [--user-id id] [--service name] [--tool name] [--sort time] <file>\n  verify --key secret <file>\n  redact-check <file>\n")
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
		if err := tail(os.Args[2]); err != nil {
			fatal(err)
		}
	case "query":
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
		_ = fs.Parse(os.Args[2:])
		if fs.NArg() < 1 {
			usage()
			os.Exit(2)
		}
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		fatalIf(zlog.QueryNDJSON(f, os.Stdout, zlog.QueryOptions{Level: *level, Field: *field, Value: *value, Contains: *contains, RequestID: *requestID, CorrelationID: *correlationID, TraceID: *traceID, SpanID: *spanID, ParentSpanID: *parentSpanID, UserID: *userID, TenantID: *tenantID, Service: *service, Tool: *tool, WorkflowID: *workflowID, TaskID: *taskID, SortBy: *sortBy, Desc: *desc, Limit: *limit}))
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		key := fs.String("key", "", "")
		_ = fs.Parse(os.Args[2:])
		if *key == "" || fs.NArg() < 1 {
			usage()
			os.Exit(2)
		}
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		rep, err := zlog.VerifyIntegrityNDJSON(f, []byte(*key))
		if err != nil {
			fatal(err)
		}
		fmt.Printf("total=%d valid=%d invalid=%d first_bad_line=%d\n", rep.Total, rep.Valid, rep.Invalid, rep.FirstBadLine)
		if rep.Invalid > 0 {
			os.Exit(1)
		}
	case "redact-check":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		f, err := os.Open(os.Args[2])
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		b, err := io.ReadAll(f)
		if err != nil {
			fatal(err)
		}
		r := zlog.EnterpriseRedactor()
		leaks := 0
		for _, word := range []string{"password", "secret", "token", "api_key", "authorization"} {
			if zlogContainsSensitive(string(b), word) {
				fmt.Fprintf(os.Stderr, "possible sensitive token found: %s\n", word)
				leaks++
			}
		}
		_ = r
		if leaks > 0 {
			os.Exit(1)
		}
		fmt.Println("no obvious sensitive field names found")
	default:
		usage()
		os.Exit(2)
	}
}
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
func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func fatalIf(err error) {
	if err != nil {
		fatal(err)
	}
}
func zlogContainsSensitive(s, needle string) bool {
	return len(s) >= len(needle) && (containsFold(s, needle))
}
func containsFold(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			a := s[i+j]
			b := sub[j]
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
