package zlog

// Audit writes an enterprise audit event. Pass actor/resource/action as attrs when needed:
//
//	log.Audit("admin.changed_role", "success", zlog.String("actor", "admin_1"))
func (l *Logger) Audit(event, outcome string, attrs ...Attr) {
	base := [3]Attr{String("event.kind", "audit"), String("event.name", event), String("event.outcome", outcome)}
	l.logWithPrefix(InfoLevel, event, base[:], attrs)
}

// AuditAction is the expanded audit helper for actor/action/resource heavy events.
func (l *Logger) AuditAction(event, actor, action, resource, outcome string, attrs ...Attr) {
	base := [6]Attr{String("event.kind", "audit"), String("event.name", event), String("actor.id", actor), String("event.action", action), String("resource.id", resource), String("event.outcome", outcome)}
	l.logWithPrefix(InfoLevel, event, base[:], attrs)
}

func (l *Logger) Security(event, outcome string, attrs ...Attr) {
	base := [3]Attr{String("event.kind", "security"), String("event.name", event), String("event.outcome", outcome)}
	l.logWithPrefix(WarnLevel, event, base[:], attrs)
}

func (l *Logger) logWithPrefix(level Level, msg string, prefix []Attr, attrs []Attr) {
	if !l.Enabled(level) {
		return
	}
	var fixed [16]Attr
	n := copy(fixed[:], prefix)
	if n < len(fixed) {
		n += copy(fixed[n:], attrs)
	}
	if len(attrs)+len(prefix) <= len(fixed) {
		l.writeSliceSkip(level, msg, fixed[:n], 4)
		return
	}
	merged := make([]Attr, 0, len(prefix)+len(attrs))
	merged = append(merged, prefix...)
	merged = append(merged, attrs...)
	l.writeSliceSkip(level, msg, merged, 4)
}
