package zlog

import (
	"encoding/json"
	"net/http"
	"os"
	"time"
)

type Config struct {
	Level             string              `json:"level"`
	Format            string              `json:"format"`
	Async             bool                `json:"async"`
	File              string              `json:"file"`
	MaxSize           int64               `json:"max_size"`
	AddCaller         bool                `json:"add_caller"`
	DisableRedaction  bool                `json:"disable_redaction"`
	SensitiveFields   []string            `json:"sensitive_fields"`       // substring field/path matches
	ExactFields       []string            `json:"exact_sensitive_fields"` // exact field/path matches
	AllowFields       []string            `json:"allow_fields"`           // exact field/path allow-list
	RedactionMask     string              `json:"redaction_mask"`
	HashRedaction     bool                `json:"hash_redaction"`
	MaskPartial       bool                `json:"mask_partial"`
	KeepLast          int                 `json:"keep_last"`
	Compliance        []string            `json:"compliance"` // pii, hipaa, pci, secrets
	Dictionary        RedactionDictionary `json:"redaction_dictionary"`
	ReplaceDictionary bool                `json:"replace_redaction_dictionary"`
	ValueScan         *bool               `json:"value_scan"`
	IntegrityKey      string              `json:"integrity_key"`
	AddHostname       bool                `json:"add_hostname"`
	AddPID            bool                `json:"add_pid"`
	AsyncCapacity     int                 `json:"async_capacity"`
	AsyncBatchSize    int                 `json:"async_batch_size"`
	DurableSpoolDir   string              `json:"durable_spool_dir"`
	DeliveryMode      string              `json:"delivery_mode"`
	Exporter          string              `json:"exporter"` // http, otlp_http, loki, opensearch, webhook
	Endpoint          string              `json:"endpoint"`
	Headers           map[string]string   `json:"headers"`
	RetryAttempts     int                 `json:"retry_attempts"`
	RetryMinBackoff   string              `json:"retry_min_backoff"`
	RetryMaxBackoff   string              `json:"retry_max_backoff"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(b, &c)
	return c, err
}
func FromConfig(c Config) (*Logger, error) {
	lvl, _ := ParseLevel(c.Level)
	var enc Encoder
	switch Format(c.Format) {
	case FormatConsole:
		enc = NewConsoleEncoder()
	case FormatLogfmt:
		enc = NewLogfmtEncoder()
	default:
		enc = NewJSONEncoder()
	}
	var sink Sink
	if c.Endpoint != "" {
		headers := http.Header{}
		for k, v := range c.Headers {
			headers.Set(k, v)
		}
		switch c.Exporter {
		case "otlp_http", "otlp":
			sink = NewOTLPHTTPExporter(c.Endpoint, headers)
		case "loki":
			sink = NewLokiSink(c.Endpoint, headers)
		case "opensearch", "elasticsearch":
			sink = NewOpenSearchSink(c.Endpoint, headers)
		case "webhook", "http", "":
			sink = NewWebhookSink(c.Endpoint, headers)
		default:
			sink = NewWebhookSink(c.Endpoint, headers)
		}
	} else if c.File != "" {
		f, err := NewRotatingFile(FileConfig{Path: c.File, MaxSize: c.MaxSize, Compress: true, MaxBackups: 10})
		if err != nil {
			return nil, err
		}
		sink = NewWriterSink(f, enc, TraceLevel)
	} else {
		sink = NewWriterSink(os.Stdout, enc, TraceLevel)
	}
	if c.RetryAttempts > 0 {
		minBackoff, _ := time.ParseDuration(c.RetryMinBackoff)
		maxBackoff, _ := time.ParseDuration(c.RetryMaxBackoff)
		sink = NewRetrySink(sink, RetryOptions{Attempts: c.RetryAttempts, MinBackoff: minBackoff, MaxBackoff: maxBackoff})
	}
	if c.DurableSpoolDir != "" {
		mode := SpoolOnFailure
		if c.DeliveryMode == "audit_strict" {
			mode = AuditStrict
		}
		d, err := NewDurableSink(sink, DurableSinkOptions{Dir: c.DurableSpoolDir, Mode: mode})
		if err != nil {
			return nil, err
		}
		sink = d
	}
	redactor := redactorFromConfig(c)
	return New(Options{Level: lvl, Sink: sink, Async: c.Async, AsyncOptions: AsyncOptions{Capacity: c.AsyncCapacity, BatchSize: c.AsyncBatchSize}, AddCaller: c.AddCaller, Redactor: redactor, DisableRedaction: c.DisableRedaction, IntegrityKey: []byte(c.IntegrityKey), AddHostname: c.AddHostname, AddPID: c.AddPID}), nil
}

func redactorFromConfig(c Config) Redactor {
	if c.DisableRedaction {
		return NoRedaction()
	}
	r := EnterpriseRedactor()
	if c.RedactionMask != "" {
		r.Mask = c.RedactionMask
	}
	if !c.Dictionary.isZero() {
		if c.ReplaceDictionary {
			r.Dictionary = c.Dictionary
		} else {
			r.Dictionary = r.Dictionary.Merge(c.Dictionary)
		}
	}
	if c.ValueScan != nil {
		r.ValueScan = *c.ValueScan
	}
	r.Keys = append(r.Keys, c.SensitiveFields...)
	r.ExactKeys = append(r.ExactKeys, c.ExactFields...)
	r.AllowKeys = append(r.AllowKeys, c.AllowFields...)
	r.Hash = c.HashRedaction
	r.MaskPartial = c.MaskPartial
	r.KeepLast = c.KeepLast
	if len(c.Compliance) > 0 {
		r.Presets = r.Presets[:0]
		for _, p := range c.Compliance {
			switch p {
			case string(CompliancePII):
				r.Presets = append(r.Presets, CompliancePII)
			case string(ComplianceHIPAA):
				r.Presets = append(r.Presets, ComplianceHIPAA)
			case string(CompliancePCI):
				r.Presets = append(r.Presets, CompliancePCI)
			case string(ComplianceSecrets):
				r.Presets = append(r.Presets, ComplianceSecrets)
			}
		}
	}
	return r
}
