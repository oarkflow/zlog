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
	l := &Logger{name: opts.Name, level: lvl, sink: sink, static: static, callerSkip: 6, redactor: redactor, fatalExit: os.Exit, addSequence: opts.AddSequence || len(opts.IntegrityKey) > 0}
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
func (l *Logger) With(attrs ...Attr) *Logger {
	cp := *l
	cp.static = append(append([]Attr(nil), l.static...), attrs...)
	return &cp
}
func (l *Logger) Named(name string) *Logger {
	cp := *l
	if cp.name == "" {
		cp.name = name
	} else {
		cp.name += "." + name
	}
	return &cp
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
func (l *Logger) Info0(msg string)         { l.Log0(InfoLevel, msg) }
func (l *Logger) Info1(msg string, a Attr) { l.Log1(InfoLevel, msg, a) }
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
	r := Record{Time: time.Now(), Level: level, Message: msg, Logger: l.name}
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
	r := Record{Time: time.Now(), Level: level, Message: msg, Logger: l.name}
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
	r := Record{Time: time.Now(), Level: level, Message: msg, Logger: l.name}
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
