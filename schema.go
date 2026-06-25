package zlog

type Schema int

const (
	SchemaNative Schema = iota
	SchemaSlog
	SchemaOpenTelemetry
	SchemaECS
	SchemaKubernetes
	SchemaAudit
)

func (s Schema) TimeKey() string {
	switch s {
	case SchemaECS:
		return "@timestamp"
	case SchemaOpenTelemetry:
		return "time_unix_nano"
	default:
		return "time"
	}
}
func (s Schema) LevelKey() string {
	switch s {
	case SchemaOpenTelemetry:
		return "severity_text"
	case SchemaECS:
		return "log.level"
	default:
		return "level"
	}
}
func (s Schema) MessageKey() string {
	switch s {
	case SchemaOpenTelemetry:
		return "body"
	case SchemaECS:
		return "message"
	default:
		return "msg"
	}
}
