package zlog

import (
	"io"
	"testing"
)

func BenchmarkDisabled(b *testing.B) {
	log := New(Options{Level: ErrorLevel, Sink: NewWriterSink(io.Discard, NewJSONEncoder(), TraceLevel)})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Info("skip", String("k", "v"))
	}
}
func BenchmarkJSONInfo(b *testing.B) {
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(io.Discard, NewJSONEncoder(), TraceLevel)})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Info("event", String("user", "u1"), Int("attempt", 1), Bool("ok", true))
	}
}
func BenchmarkAsyncEnqueue(b *testing.B) {
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(io.Discard, NewJSONEncoder(), TraceLevel), Async: true, AsyncOptions: AsyncOptions{Capacity: 65536, DropPolicy: DropNewest}})
	b.Cleanup(func() { _ = log.Close() })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Info("event", String("user", "u1"), Int("attempt", 1))
	}
}
func BenchmarkDisabled0(b *testing.B) {
	log := New(Options{Level: ErrorLevel, Sink: NewWriterSink(io.Discard, NewJSONEncoder(), TraceLevel)})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Info0("skip")
	}
}
func BenchmarkAsyncEnqueue2(b *testing.B) {
	log := New(Options{Level: InfoLevel, Sink: NewWriterSink(io.Discard, NewJSONEncoder(), TraceLevel), Async: true, AsyncOptions: AsyncOptions{Capacity: 65536, DropPolicy: DropNewest}})
	b.Cleanup(func() { _ = log.Close() })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		log.Info2("event", String("user", "u1"), Int("attempt", 1))
	}
}
