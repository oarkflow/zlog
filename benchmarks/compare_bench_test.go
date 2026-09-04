package benchmarks

import (
	"io"
	"testing"

	halojson "github.com/go-gen-ecosystem/halolog/adapters/formatters/json"
	haloasync "github.com/go-gen-ecosystem/halolog/adapters/outputs/asyncring"
	haloconsole "github.com/go-gen-ecosystem/halolog/adapters/outputs/console"
	halocore "github.com/go-gen-ecosystem/halolog/core"
	halotypes "github.com/go-gen-ecosystem/halolog/types"
	"github.com/oarkflow/zlog"
)

const message = "request handled"

var (
	zKey  = zlog.NewFieldKey("key")
	zKeys = []zlog.FieldKey{zlog.NewFieldKey("k1"), zlog.NewFieldKey("k2"), zlog.NewFieldKey("k3"), zlog.NewFieldKey("k4"), zlog.NewFieldKey("k5"), zlog.NewFieldKey("k6"), zlog.NewFieldKey("k7"), zlog.NewFieldKey("k8"), zlog.NewFieldKey("k9"), zlog.NewFieldKey("k10")}
	hKey  = &halotypes.FieldKey{Name: "key", JSONFragment: halojson.KeyFragment("key")}
	hKeys = []*halotypes.FieldKey{
		{Name: "k1", JSONFragment: halojson.KeyFragment("k1")}, {Name: "k2", JSONFragment: halojson.KeyFragment("k2")},
		{Name: "k3", JSONFragment: halojson.KeyFragment("k3")}, {Name: "k4", JSONFragment: halojson.KeyFragment("k4")},
		{Name: "k5", JSONFragment: halojson.KeyFragment("k5")}, {Name: "k6", JSONFragment: halojson.KeyFragment("k6")},
		{Name: "k7", JSONFragment: halojson.KeyFragment("k7")}, {Name: "k8", JSONFragment: halojson.KeyFragment("k8")},
		{Name: "k9", JSONFragment: halojson.KeyFragment("k9")}, {Name: "k10", JSONFragment: halojson.KeyFragment("k10")},
	}
)

func newHalo(level halotypes.LogLevel) *halocore.Logger {
	return halocore.NewLogger(halocore.Config{
		Level: level,
		Adapters: []halotypes.Adapter{
			haloconsole.NewWithWriter(io.Discard, halojson.NewJsonFormatter()),
		},
	})
}

func newZlog(level zlog.Level) *zlog.Logger {
	return zlog.New(zlog.Options{
		Level:            level,
		Sink:             zlog.NewWriterSink(io.Discard, zlog.NewJSONEncoder(), zlog.TraceLevel),
		DisableRedaction: true,
		CachedTime:       true,
		DisableStats:     true,
	})
}

func haloOne(l *halocore.Logger) {
	l.Typed().Str(hKey, "value").Info(message)
}

func zlogOne(l *zlog.Logger) {
	l.Info1(message, zKey.String("value"))
}

func haloTen(l *halocore.Logger) {
	l.Typed().WithString("k1", "v1").WithString("k2", "v2").
		WithInt("k3", 3).WithInt("k4", 4).WithInt("k5", 5).
		WithInt("k6", 6).WithInt("k7", 7).WithInt("k8", 8).
		WithBool("k9", true).WithBool("k10", false).Info(message)
}

func zlogTen(l *zlog.Logger) {
	l.Info10Primitive(message, "k1", "v1", "k2", "v2", "k3", 3, "k4", 4, "k5", 5, "k6", 6, "k7", 7, "k8", 8, "k9", true, "k10", false)
}

func haloContext(l *halocore.Logger) *halocore.Logger {
	c := l.With().WithString("svc", "auth").WithString("region", "eu-west-1").
		WithString("pod", "auth-7f9c").WithInt("shard", 7).WithString("ver", "1.4.2")
	return c.Logger()
}

func zlogContext(l *zlog.Logger) *zlog.Logger {
	return l.With(
		zlog.String("svc", "auth"), zlog.String("region", "eu-west-1"),
		zlog.String("pod", "auth-7f9c"), zlog.Int("shard", 7), zlog.String("ver", "1.4.2"),
	)
}

// BenchmarkAppleToApple compares the same log records, fields, output target,
// and enabled/disabled states in both libraries. It intentionally excludes
// competitor-specific APIs and features.
func BenchmarkAppleToApple(b *testing.B) {
	b.Run("Disabled/Both", func(b *testing.B) {
		h := newHalo(halotypes.ErrorLevel)
		z := newZlog(zlog.ErrorLevel)
		b.Run("HaloLog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				h.Info(message)
			}
		})
		b.Run("zlog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				z.Info0(message)
			}
		})
	})

	b.Run("JSON/BareMessage", func(b *testing.B) {
		h := newHalo(halotypes.InfoLevel)
		z := newZlog(zlog.InfoLevel)
		b.Run("HaloLog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				h.Info(message)
			}
		})
		b.Run("zlog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				z.Info0(message)
			}
		})
	})

	b.Run("JSON/OneField", func(b *testing.B) {
		h := newHalo(halotypes.InfoLevel)
		z := newZlog(zlog.InfoLevel)
		b.Run("HaloLog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				haloOne(h)
			}
		})
		b.Run("zlog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				zlogOne(z)
			}
		})
	})

	b.Run("JSON/TenFields", func(b *testing.B) {
		h := newHalo(halotypes.InfoLevel)
		z := newZlog(zlog.InfoLevel)
		b.Run("HaloLog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				haloTen(h)
			}
		})
		b.Run("zlog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				zlogTen(z)
			}
		})
	})

	b.Run("JSON/BoundContextPlusOneField", func(b *testing.B) {
		h := haloContext(newHalo(halotypes.InfoLevel))
		z := zlogContext(newZlog(zlog.InfoLevel))
		b.Run("HaloLog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				h.Typed().WithInt("status", 200).Info(message)
			}
		})
		b.Run("zlog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				z.Info(message, zlog.Int("status", 200))
			}
		})
	})

	b.Run("Async/Enqueue", func(b *testing.B) {
		hRing, err := haloasync.New(haloasync.Options{Writer: io.Discard, Formatter: halojson.NewJsonFormatter(), Capacity: 65536, OnFull: haloasync.Drop})
		if err != nil {
			b.Fatal(err)
		}
		h := halocore.NewLogger(halocore.Config{Level: halotypes.InfoLevel, Adapters: []halotypes.Adapter{hRing}})
		z := newZlog(zlog.InfoLevel)
		zAsync := zlog.New(zlog.Options{Level: zlog.InfoLevel, Sink: zlog.NewWriterSink(io.Discard, zlog.NewJSONEncoder(), zlog.TraceLevel), Async: true, AsyncOptions: zlog.AsyncOptions{Capacity: 65536, DropPolicy: zlog.DropNewest, DisableStats: true}, DisableRedaction: true, CachedTime: true, DisableStats: true})
		b.Run("HaloLog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				h.Info(message)
			}
			b.StopTimer()
			b.ReportMetric(float64(hRing.Dropped()), "drops")
		})
		b.Run("zlog", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				zAsync.Info0(message)
			}
			b.StopTimer()
			_ = z.Flush()
			b.ReportMetric(float64(0), "drops")
		})
		_ = h.Close()
		_ = z.Close()
		_ = zAsync.Close()
	})
}
