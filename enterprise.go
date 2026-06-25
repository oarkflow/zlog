package zlog

import "os"

// ProductionOptions returns safe defaults: async non-blocking JSON logs,
// default redaction, host/process metadata, and error-level emergency fallback.
func ProductionOptions(service, env string) Options {
	static := make([]Attr, 0, 4)
	if service != "" {
		static = append(static, ServiceName(service))
	}
	if env != "" {
		static = append(static, Environment(env))
	}
	return Options{
		Level:        InfoLevel,
		Sink:         NewWriterSink(os.Stdout, NewJSONEncoder(), TraceLevel),
		Async:        true,
		AsyncOptions: AsyncOptions{Capacity: 8192, BatchSize: 256, FlushInterval: 500000000, DropPolicy: DropNewest, EmergencyLevel: ErrorLevel},
		Static:       static,
		Redactor:     EnterpriseRedactor(),
		AddHostname:  true,
		AddPID:       true,
	}
}

func NewProductionLogger(service, env string) *Logger { return New(ProductionOptions(service, env)) }

// ComplianceOptions enables caller, integrity signing, redaction, and larger async buffers.
func ComplianceOptions(service, env string, integrityKey []byte) Options {
	opts := ProductionOptions(service, env)
	opts.AddCaller = true
	opts.IntegrityKey = integrityKey
	opts.AsyncOptions.Capacity = 32768
	opts.AsyncOptions.EmergencyLevel = WarnLevel
	return opts
}

func NewComplianceLogger(service, env string, integrityKey []byte) *Logger {
	return New(ComplianceOptions(service, env, integrityKey))
}

func (l *Logger) Auth(event, user, outcome string, attrs ...Attr) {
	if user != "" {
		base := [5]Attr{String("event.kind", "security"), String("event.category", "authentication"), String("event.name", event), String("event.outcome", outcome), UserID(user)}
		l.logWithPrefix(WarnLevel, event, base[:], attrs)
		return
	}
	base := [4]Attr{String("event.kind", "security"), String("event.category", "authentication"), String("event.name", event), String("event.outcome", outcome)}
	l.logWithPrefix(WarnLevel, event, base[:], attrs)
}

func (l *Logger) Authorization(event, actor, resource, outcome string, attrs ...Attr) {
	base := [6]Attr{String("event.kind", "security"), String("event.category", "authorization"), String("event.name", event), ActorID(actor), ResourceID(resource), String("event.outcome", outcome)}
	l.logWithPrefix(WarnLevel, event, base[:], attrs)
}

func (l *Logger) DataAccess(event, actor, resource, outcome string, attrs ...Attr) {
	base := [6]Attr{String("event.kind", "audit"), String("event.category", "data_access"), String("event.name", event), ActorID(actor), ResourceID(resource), String("event.outcome", outcome)}
	l.logWithPrefix(InfoLevel, event, base[:], attrs)
}

func (l *Logger) ConfigChange(event, actor, resource, outcome string, attrs ...Attr) {
	base := [6]Attr{String("event.kind", "audit"), String("event.category", "configuration"), String("event.name", event), ActorID(actor), ResourceID(resource), String("event.outcome", outcome)}
	l.logWithPrefix(InfoLevel, event, base[:], attrs)
}
