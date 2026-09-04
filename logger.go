package zlog

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

type Logger struct {
	name        string
	level       *AtomicLevel
	sink        Sink
	static      []Attr
	addCaller   atomic.Bool
	callerSkip  int
	redactor    Redactor
	fatalExit   func(int)
	signer      *IntegritySigner
	addSequence bool
	cachedTime  bool
	fastStatic  []byte
}

type Options struct {
	Level            Level
	Sink             Sink
	Async            bool
	AsyncOptions     AsyncOptions
	Name             string
	AddCaller        bool
	Static           []Attr
	FatalExit        func(int)
	Redactor         Redactor
	IntegrityKey     []byte
	AddHostname      bool
	AddPID           bool
	TimeLayout       string
	TimeFormat       string
	CachedTime       bool
	DisableStats     bool
	ConsoleColor     *bool
	Prettify         *bool
	KVSeparator      string
	PairSeparator    string
	AddSequence      bool
	DisableRedaction bool
}

func New(opts Options) *Logger {
	lvl := NewAtomicLevel(opts.Level)
	sink := opts.Sink
	if sink == nil {
		sink = NewWriterSink(os.Stdout, NewJSONEncoder(), TraceLevel)
	}
	applyEncoderOptions(sink, opts)
	if opts.Async {
		sink = NewAsyncSink(sink, opts.AsyncOptions)
	}
	redactor := opts.Redactor
	if opts.DisableRedaction {
		redactor = NoRedaction()
	} else if redactor.isZero() {
		redactor = DefaultRedactor().normalized()
	} else {
		redactor = redactor.normalized()
	}
	applySinkRedactor(sink, redactor)
	static := append([]Attr(nil), opts.Static...)
	if opts.AddHostname {
		if host, err := os.Hostname(); err == nil && host != "" {
			static = append(static, String("host.name", host))
		}
	}
	if opts.AddPID {
		static = append(static, Int("process.pid", os.Getpid()))
	}
	redactor.RedactAttrs(static)
	l := &Logger{name: opts.Name, level: lvl, sink: sink, static: static, callerSkip: 6, redactor: redactor, fatalExit: os.Exit, addSequence: opts.AddSequence || len(opts.IntegrityKey) > 0, cachedTime: opts.CachedTime}
	l.fastStatic = encodeStaticAttrs(static)
	if opts.FatalExit != nil {
		l.fatalExit = opts.FatalExit
	}
	if len(opts.IntegrityKey) > 0 {
		l.signer = NewIntegritySigner(opts.IntegrityKey)
	}
	l.addCaller.Store(opts.AddCaller)
	return l
}
func NewProduction() *Logger {
	return New(Options{Level: InfoLevel, Async: true, Sink: NewWriterSink(os.Stdout, NewJSONEncoder(), TraceLevel), AsyncOptions: AsyncOptions{Capacity: 8192, BatchSize: 256, DropPolicy: DropNewest, EmergencyLevel: ErrorLevel}, AddHostname: true, AddPID: true})
}
func NewDevelopment() *Logger {
	return New(Options{Level: DebugLevel, Async: false, Sink: NewWriterSink(os.Stderr, NewConsoleEncoder(), TraceLevel), AddCaller: true})
}

// NewUltraFast returns a minimal logger intended for benchmark-critical hot paths.
// It disables async, caller and redaction; callers should only log non-sensitive data.
func NewUltraFast() *Logger {
	sink := NewWriterSink(os.Stdout, NewJSONEncoder(), TraceLevel).Redactor(Redactor{})
	return New(Options{Level: InfoLevel, Sink: sink, DisableRedaction: true})
}
func (l *Logger) Enabled(level Level) bool { return l != nil && l.level.Enabled(level) }
func (l *Logger) SetLevel(level Level)     { l.level.Set(level) }
func (l *Logger) Level() Level             { return l.level.Get() }
func (l *Logger) clone() *Logger {
	cp := &Logger{
		name: l.name, level: l.level, sink: l.sink,
		static: append([]Attr(nil), l.static...), callerSkip: l.callerSkip,
		redactor: l.redactor, fatalExit: l.fatalExit, signer: l.signer,
		addSequence: l.addSequence,
		cachedTime:  l.cachedTime,
		fastStatic:  append([]byte(nil), l.fastStatic...),
	}
	cp.addCaller.Store(l.addCaller.Load())
	return cp
}

func (l *Logger) now() time.Time {
	if l.cachedTime {
		return cachedNow()
	}
	return time.Now()
}

func (l *Logger) timestamp() (time.Time, string) {
	if l.cachedTime {
		return cachedTimestamp()
	}
	return time.Now(), ""
}
func (l *Logger) With(attrs ...Attr) *Logger {
	cp := l.clone()
	cp.static = append(cp.static, attrs...)
	cp.fastStatic = encodeStaticAttrs(cp.static)
	return cp
}
func (l *Logger) Named(name string) *Logger {
	cp := l.clone()
	if cp.name == "" {
		cp.name = name
	} else {
		cp.name += "." + name
	}
	return cp
}
func (l *Logger) WithGroup(name string) *Logger { return l.With(Group(name)) }
func (l *Logger) AddCaller(v bool)              { l.addCaller.Store(v) }
func (l *Logger) Log(level Level, msg string, attrs ...Attr) {
	if !l.Enabled(level) {
		return
	}
	l.write(level, msg, attrs...)
}

func (l *Logger) Log0(level Level, msg string) {
	if !l.Enabled(level) {
		return
	}
	l.writeSlice(level, msg, nil)
}

func (l *Logger) Log1(level Level, msg string, a Attr) {
	if !l.Enabled(level) {
		return
	}
	l.write1(level, msg, a)
}

func (l *Logger) Log2(level Level, msg string, a, b Attr) {
	if !l.Enabled(level) {
		return
	}
	l.write2(level, msg, a, b)
}
func (l *Logger) LogAttrs(level Level, msg string, attrs ...Attr) { l.Log(level, msg, attrs...) }
func (l *Logger) Trace(msg string, attrs ...Attr) {
	if !l.Enabled(TraceLevel) {
		return
	}
	l.writeSlice(TraceLevel, msg, attrs)
}
func (l *Logger) Debug(msg string, attrs ...Attr) {
	if !l.Enabled(DebugLevel) {
		return
	}
	l.writeSlice(DebugLevel, msg, attrs)
}
func (l *Logger) Info(msg string, attrs ...Attr) {
	if !l.Enabled(InfoLevel) {
		return
	}
	l.writeSlice(InfoLevel, msg, attrs)
}
func (l *Logger) Info0(msg string) {
	if !l.level.Enabled(InfoLevel) {
		return
	}
	l.writeSlice(InfoLevel, msg, nil)
}
func (l *Logger) Info1(msg string, a Attr) {
	if !l.level.Enabled(InfoLevel) {
		return
	}
	if s, ok := l.sink.(*WriterSink); ok && s.fastJSON && fastValueSupported(a) && !l.addCaller.Load() && l.signer == nil && !l.redactor.Enabled && s.sampler == nil {
		_, ts := l.timestamp()
		if ts != "" {
			_ = s.writeFast1(InfoLevel, msg, a, l.fastStatic, ts)
			return
		}
	}
	l.write1(InfoLevel, msg, a)
}

func (l *Logger) Info10(msg string, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10 Attr) {
	if !l.level.Enabled(InfoLevel) {
		return
	}
	if s, ok := l.sink.(*WriterSink); ok && s.fastJSON && fastValueSupported(a1) && fastValueSupported(a2) && fastValueSupported(a3) && fastValueSupported(a4) && fastValueSupported(a5) && fastValueSupported(a6) && fastValueSupported(a7) && fastValueSupported(a8) && fastValueSupported(a9) && fastValueSupported(a10) && !l.addCaller.Load() && l.signer == nil && !l.redactor.Enabled && s.sampler == nil {
		_, ts := l.timestamp()
		if ts != "" {
			_ = s.writeFast10(InfoLevel, msg, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, l.fastStatic, ts)
			return
		}
	}
	l.Info(msg, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
}

// Info10Primitive emits a fixed ten-field primitive record without generic
// attribute dispatch. It is useful for stable, high-volume record shapes.
func (l *Logger) Info10Primitive(msg, k1, v1, k2, v2 string, k3 string, v3 int, k4 string, v4 int, k5 string, v5 int, k6 string, v6 int, k7 string, v7 int, k8 string, v8 int, k9 string, v9 bool, k10 string, v10 bool) {
	if !l.level.Enabled(InfoLevel) {
		return
	}
	if s, ok := l.sink.(*WriterSink); ok && s.fastJSON && !l.addCaller.Load() && l.signer == nil && !l.redactor.Enabled && s.sampler == nil {
		_, ts := l.timestamp()
		if ts != "" {
			_ = s.writeFast10Primitive(InfoLevel, msg, k1, v1, k2, v2, k3, v3, k4, v4, k5, v5, k6, v6, k7, v7, k8, v8, k9, v9, k10, v10, l.fastStatic, ts)
			return
		}
	}
	l.Info(msg, String(k1, v1), String(k2, v2), Int(k3, v3), Int(k4, v4), Int(k5, v5), Int(k6, v6), Int(k7, v7), Int(k8, v8), Bool(k9, v9), Bool(k10, v10))
}
func (l *Logger) Info2(msg string, a, b Attr) {
	if !l.Enabled(InfoLevel) {
		return
	}
	l.write2(InfoLevel, msg, a, b)
}

func (l *Logger) Notice(msg string, attrs ...Attr) {
	if !l.Enabled(NoticeLevel) {
		return
	}
	l.writeSlice(NoticeLevel, msg, attrs)
}
func (l *Logger) Warn(msg string, attrs ...Attr) {
	if !l.Enabled(WarnLevel) {
		return
	}
	l.writeSlice(WarnLevel, msg, attrs)
}
func (l *Logger) Error(msg string, attrs ...Attr) {
	if !l.Enabled(ErrorLevel) {
		return
	}
	l.writeSlice(ErrorLevel, msg, attrs)
}
func (l *Logger) Critical(msg string, attrs ...Attr) {
	if !l.Enabled(CriticalLevel) {
		return
	}
	l.writeSlice(CriticalLevel, msg, attrs)
}
func (l *Logger) Fatal(msg string, attrs ...Attr) {
	l.Log(FatalLevel, msg, attrs...)
	_ = l.Flush()
	if l.fatalExit != nil {
		l.fatalExit(1)
	}
}
func (l *Logger) Panic(msg string, attrs ...Attr) {
	l.Log(PanicLevel, msg, attrs...)
	_ = l.Flush()
	panic(msg)
}
func (l *Logger) LogContext(ctx context.Context, level Level, msg string, attrs ...Attr) {
	if !l.Enabled(level) {
		return
	}
	l.writeSlice(level, msg, append(extractContextAttrs(ctx), attrs...))
}
func (l *Logger) TraceContext(ctx context.Context, msg string, attrs ...Attr) {
	l.LogContext(ctx, TraceLevel, msg, attrs...)
}
func (l *Logger) DebugContext(ctx context.Context, msg string, attrs ...Attr) {
	l.LogContext(ctx, DebugLevel, msg, attrs...)
}
func (l *Logger) InfoContext(ctx context.Context, msg string, attrs ...Attr) {
	l.LogContext(ctx, InfoLevel, msg, attrs...)
}
func (l *Logger) NoticeContext(ctx context.Context, msg string, attrs ...Attr) {
	l.LogContext(ctx, NoticeLevel, msg, attrs...)
}
func (l *Logger) WarnContext(ctx context.Context, msg string, attrs ...Attr) {
	l.LogContext(ctx, WarnLevel, msg, attrs...)
}
func (l *Logger) ErrorContext(ctx context.Context, msg string, attrs ...Attr) {
	l.LogContext(ctx, ErrorLevel, msg, attrs...)
}
func (l *Logger) CriticalContext(ctx context.Context, msg string, attrs ...Attr) {
	l.LogContext(ctx, CriticalLevel, msg, attrs...)
}
func (l *Logger) write(level Level, msg string, attrs ...Attr) {
	l.writeSlice(level, msg, attrs)
}

func (l *Logger) writeSlice(level Level, msg string, attrs []Attr) {
	l.writeSliceSkip(level, msg, attrs, l.callerSkip)
}

func (l *Logger) writeSliceSkip(level Level, msg string, attrs []Attr, skip int) {
	if a, ok := l.sink.(*AsyncSink); ok && a.ringMode && len(attrs) == 0 && len(l.static) == 0 && !l.addCaller.Load() && l.signer == nil && !l.redactor.Enabled {
		now, timeText := l.timestamp()
		if timeText != "" {
			_ = a.WriteFast(level, msg, now, timeText, nil)
			return
		}
	}
	if s, ok := l.sink.(*WriterSink); ok && s.fastJSON && !l.addCaller.Load() && l.signer == nil && !l.redactor.Enabled && s.sampler == nil {
		_, timeText := l.timestamp()
		if timeText != "" {
			_ = s.writeFast(level, msg, attrs, l.fastStatic, timeText)
			return
		}
	}
	now, timeText := l.timestamp()
	r := Record{Time: now, TimeText: timeText, Level: level, Message: msg, Logger: l.name}
	if l.addSequence {
		r.Sequence = nextSeq()
	}
	r.SetAttrs(attrs)
	if l.signer != nil {
		r.Redact(l.redactor)
		r.AddAttr(l.signer.SignRecord(r, l.static))
	}
	if l.addCaller.Load() {
		r.Caller = captureCaller(skip)
	}
	_ = l.sink.WriteRecord(r, l.static)
}

func (l *Logger) write1(level Level, msg string, a Attr) {
	if s, ok := l.sink.(*WriterSink); ok && s.fastJSON && !l.addCaller.Load() && l.signer == nil && !l.redactor.Enabled && s.sampler == nil {
		_, timeText := l.timestamp()
		if timeText != "" {
			attrs := [1]Attr{a}
			_ = s.writeFast(level, msg, attrs[:], l.fastStatic, timeText)
			return
		}
	}
	now, timeText := l.timestamp()
	r := Record{Time: now, TimeText: timeText, Level: level, Message: msg, Logger: l.name}
	if l.addSequence {
		r.Sequence = nextSeq()
	}
	if a.Kind != KindInvalid && a.Key != "" {
		r.Attrs[0] = a
		r.AttrCount = 1
	}
	if l.signer != nil {
		r.Redact(l.redactor)
		r.AddAttr(l.signer.SignRecord(r, l.static))
	}
	if l.addCaller.Load() {
		r.Caller = captureCaller(l.callerSkip)
	}
	_ = l.sink.WriteRecord(r, l.static)
}

func (l *Logger) write2(level Level, msg string, a, b Attr) {
	now, timeText := l.timestamp()
	r := Record{Time: now, TimeText: timeText, Level: level, Message: msg, Logger: l.name}
	if l.addSequence {
		r.Sequence = nextSeq()
	}
	n := 0
	if a.Kind != KindInvalid && a.Key != "" {
		r.Attrs[n] = a
		n++
	}
	if b.Kind != KindInvalid && b.Key != "" {
		r.Attrs[n] = b
		n++
	}
	r.AttrCount = n
	if l.signer != nil {
		r.Redact(l.redactor)
		r.AddAttr(l.signer.SignRecord(r, l.static))
	}
	if l.addCaller.Load() {
		r.Caller = captureCaller(l.callerSkip)
	}
	_ = l.sink.WriteRecord(r, l.static)
}

func (l *Logger) Flush() error { return l.sink.Flush() }
func (l *Logger) Close() error { return l.sink.Close() }
func (l *Logger) Shutdown(ctx context.Context) error {
	if s, ok := l.sink.(interface{ Shutdown(context.Context) error }); ok {
		return s.Shutdown(ctx)
	}
	return l.Close()
}
func (l *Logger) Stats() SinkStats          { return l.sink.Stats() }
func (l *Logger) SlogHandler() slog.Handler { return NewSlogHandler(l) }
