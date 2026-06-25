package main

import (
	"context"
	"os"
	"time"

	"github.com/oarkflow/zlog"
)

func main() {
	file, err := zlog.NewRotatingFile(zlog.FileConfig{Path: "./logs/app.log", MaxSize: 10 << 20, MaxBackups: 5, Compress: true})
	if err != nil {
		panic(err)
	}
	multi := zlog.NewMultiSink(
		zlog.NewWriterSink(os.Stdout, zlog.NewConsoleEncoder(), zlog.DebugLevel),
		zlog.NewWriterSink(file, zlog.NewJSONEncoder(), zlog.InfoLevel),
	)
	color := true
	pretty := true
	log := zlog.New(zlog.Options{
		Level:         zlog.DebugLevel,
		Sink:          multi,
		Async:         true,
		TimeLayout:    "2006-01-02 15:04:05.000",
		ConsoleColor:  &color,
		Prettify:      &pretty,
		KVSeparator:   "=",
		PairSeparator: " ",
		Static:        []zlog.Attr{zlog.String("service.name", "demo"), zlog.String("env", "dev")},
	})
	defer log.Shutdown(context.Background())

	ctx := zlog.ContextWithAttrs(context.Background(), zlog.RequestID("req_123"), zlog.TraceID("tr_abc"))
	log.InfoContext(ctx, "user.login", zlog.UserID("u_1"), zlog.String("password", "secret-will-redact"), zlog.Duration("latency", 42*time.Millisecond))
	log.Audit("admin.changed_role", "success", zlog.String("actor", "admin_1"), zlog.String("resource", "user:u_1"))
	log.Security("auth.failed", "failure", zlog.String("ip", "127.0.0.1"))
}
