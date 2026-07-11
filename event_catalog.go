package zlog

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type AttributeRule struct {
	Name        string   `json:"name"`
	Type        string   `json:"type,omitempty"` // string, bool, int, uint, float, time, bytes, object, array, any
	Required    bool     `json:"required,omitempty"`
	MaxLength   int      `json:"max_length,omitempty"`
	Allowed     []string `json:"allowed,omitempty"`
	Sensitive   bool     `json:"sensitive,omitempty"`
	Description string   `json:"description,omitempty"`
}

type EventDefinition struct {
	Name           string          `json:"name"`
	Version        string          `json:"version"`
	Required       []string        `json:"required,omitempty"`
	Optional       []string        `json:"optional,omitempty"`
	Forbidden      []string        `json:"forbidden,omitempty"`
	Compliance     []string        `json:"compliance,omitempty"`
	Rules          []AttributeRule `json:"rules,omitempty"`
	DefaultKind    string          `json:"default_kind,omitempty"`
	DefaultOutcome string          `json:"default_outcome,omitempty"`
	Retention      string          `json:"retention,omitempty"`
	Classification string          `json:"classification,omitempty"`
	Owner          string          `json:"owner,omitempty"`
	Description    string          `json:"description,omitempty"`
	Deprecated     bool            `json:"deprecated,omitempty"`
}

type EventCatalog struct {
	mu   sync.RWMutex
	defs map[string]EventDefinition
}

func NewEventCatalog(defs ...EventDefinition) *EventCatalog {
	c := &EventCatalog{defs: map[string]EventDefinition{}}
	for _, d := range defs {
		_ = c.RegisterChecked(d)
	}
	return c
}
func (c *EventCatalog) Register(d EventDefinition) { _ = c.RegisterChecked(d) }
func (c *EventCatalog) RegisterChecked(d EventDefinition) error {
	if d.Name == "" {
		return errors.New("zlog: event name is required")
	}
	if d.Version == "" {
		d.Version = "1"
	}
	d.Required = uniqueSorted(d.Required)
	d.Optional = uniqueSorted(d.Optional)
	d.Forbidden = uniqueSorted(d.Forbidden)
	d.Compliance = uniqueSorted(d.Compliance)
	seen := make(map[string]struct{})
	for i := range d.Rules {
		r := &d.Rules[i]
		if r.Name == "" {
			return fmt.Errorf("zlog: event %q has unnamed attribute rule", d.Name)
		}
		if _, ok := seen[r.Name]; ok {
			return fmt.Errorf("zlog: event %q has duplicate rule %q", d.Name, r.Name)
		}
		seen[r.Name] = struct{}{}
		if r.Type == "" {
			r.Type = "any"
		}
		if !validRuleType(r.Type) {
			return fmt.Errorf("zlog: event %q rule %q has invalid type %q", d.Name, r.Name, r.Type)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.defs == nil {
		c.defs = map[string]EventDefinition{}
	}
	c.defs[d.Name] = cloneEventDefinition(d)
	return nil
}
func (c *EventCatalog) Get(name string) (EventDefinition, bool) {
	c.mu.RLock()
	d, ok := c.defs[name]
	c.mu.RUnlock()
	return cloneEventDefinition(d), ok
}
func (c *EventCatalog) Definitions() []EventDefinition {
	c.mu.RLock()
	out := make([]EventDefinition, 0, len(c.defs))
	for _, d := range c.defs {
		out = append(out, cloneEventDefinition(d))
	}
	c.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (c *EventCatalog) Validate(name string, attrs []Attr) error {
	d, ok := c.Get(name)
	if !ok {
		return fmt.Errorf("zlog event %q is not registered", name)
	}
	have := make(map[string]Attr, len(attrs))
	for _, a := range attrs {
		if a.Kind == KindInvalid || a.Key == "" {
			continue
		}
		if _, exists := have[a.Key]; exists {
			return fmt.Errorf("zlog event %q has duplicate attr %q", name, a.Key)
		}
		have[a.Key] = a
	}
	for _, k := range d.Required {
		if _, ok := have[k]; !ok {
			return fmt.Errorf("zlog event %q missing required attr %q", name, k)
		}
	}
	for _, k := range d.Forbidden {
		if _, ok := have[k]; ok {
			return fmt.Errorf("zlog event %q contains forbidden attr %q", name, k)
		}
	}
	for _, rule := range d.Rules {
		a, present := have[rule.Name]
		if rule.Required && !present {
			return fmt.Errorf("zlog event %q missing required attr %q", name, rule.Name)
		}
		if !present {
			continue
		}
		if err := validateAttrRule(a, rule); err != nil {
			return fmt.Errorf("zlog event %q attr %q: %w", name, rule.Name, err)
		}
	}
	return nil
}
func (l *Logger) Event(c *EventCatalog, level Level, name string, attrs ...Attr) error {
	if c != nil {
		if err := c.Validate(name, attrs); err != nil {
			return err
		}
	}
	l.Log(level, name, append([]Attr{EventName(name)}, attrs...)...)
	return nil
}

func validRuleType(s string) bool {
	switch s {
	case "any", "string", "bool", "int", "uint", "float", "time", "duration", "bytes", "object", "array":
		return true
	}
	return false
}
func validateAttrRule(a Attr, r AttributeRule) error {
	ok := r.Type == "any"
	switch r.Type {
	case "string":
		ok = a.Kind == KindString || a.Kind == KindError
	case "bool":
		ok = a.Kind == KindBool
	case "int":
		ok = a.Kind == KindInt64
	case "uint":
		ok = a.Kind == KindUint64
	case "float":
		ok = a.Kind == KindFloat64
	case "time":
		ok = a.Kind == KindTime
	case "duration":
		ok = a.Kind == KindDuration
	case "bytes":
		ok = a.Kind == KindBytes
	case "object":
		ok = a.Kind == KindGroup || a.Kind == KindAny
	case "array":
		ok = a.Kind == KindAny
	}
	if !ok {
		return fmt.Errorf("expected %s", r.Type)
	}
	if r.Required && (a.Kind == KindString || a.Kind == KindError) && strings.TrimSpace(a.Str) == "" {
		return errors.New("required string must not be empty")
	}
	if r.MaxLength > 0 {
		n := 0
		switch a.Kind {
		case KindString, KindError:
			n = len(a.Str)
		case KindBytes, KindRawJSON:
			n = len(a.Bytes)
		}
		if n > r.MaxLength {
			return fmt.Errorf("length %d exceeds %d", n, r.MaxLength)
		}
	}
	if len(r.Allowed) > 0 {
		v := ""
		if a.Kind == KindString || a.Kind == KindError {
			v = a.Str
		}
		found := false
		for _, x := range r.Allowed {
			if v == x {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("value %q is not allowed", v)
		}
	}
	return nil
}
func cloneEventDefinition(d EventDefinition) EventDefinition {
	d.Required = append([]string(nil), d.Required...)
	d.Optional = append([]string(nil), d.Optional...)
	d.Forbidden = append([]string(nil), d.Forbidden...)
	d.Compliance = append([]string(nil), d.Compliance...)
	d.Rules = append([]AttributeRule(nil), d.Rules...)
	for i := range d.Rules {
		d.Rules[i].Allowed = append([]string(nil), d.Rules[i].Allowed...)
	}
	return d
}

type SignedCatalogManifest struct {
	Version     string            `json:"version"`
	Definitions []EventDefinition `json:"definitions"`
	SignerKeyID string            `json:"signer_key_id"`
	Algorithm   string            `json:"algorithm"`
	Signature   string            `json:"signature"`
}

func (m SignedCatalogManifest) signingPayload() SignedCatalogManifest { m.Signature = ""; return m }
func (c *EventCatalog) Sign(ctx context.Context, signer CheckpointSigner) (SignedCatalogManifest, error) {
	if signer == nil {
		return SignedCatalogManifest{}, errors.New("zlog: catalog signer required")
	}
	m := SignedCatalogManifest{Version: "zlog.event-catalog.v1", Definitions: c.Definitions(), SignerKeyID: signer.KeyID(), Algorithm: signer.Algorithm()}
	b, e := CanonicalJSON(m.signingPayload())
	if e != nil {
		return m, e
	}
	sig, e := signer.Sign(ctx, b)
	if e != nil {
		return m, e
	}
	m.Signature = signatureB64(sig)
	return m, nil
}
func VerifyCatalogManifest(ctx context.Context, m SignedCatalogManifest, v SignatureVerifier) (*EventCatalog, error) {
	if m.Version != "zlog.event-catalog.v1" || v == nil {
		return nil, errors.New("zlog: invalid catalog manifest")
	}
	b, e := CanonicalJSON(m.signingPayload())
	if e != nil {
		return nil, e
	}
	sig, e := decodeSignature(m.Signature)
	if e != nil {
		return nil, e
	}
	if e = v.VerifySignature(ctx, m.SignerKeyID, m.Algorithm, b, sig); e != nil {
		return nil, e
	}
	c := NewEventCatalog()
	for _, d := range m.Definitions {
		if e = c.RegisterChecked(d); e != nil {
			return nil, e
		}
	}
	return c, nil
}

// AuditEventBuilder creates a validated AuditRecord and commits it to an AuditStore.
type AuditEventBuilder struct {
	store   AuditStore
	catalog *EventCatalog
	record  AuditRecord
	err     error
}

func NewAuditEvent(store AuditStore, name string) *AuditEventBuilder {
	return &AuditEventBuilder{store: store, record: AuditRecord{Name: name, Kind: "audit", Attributes: map[string]any{}}}
}
func (b *AuditEventBuilder) Catalog(c *EventCatalog) *AuditEventBuilder { b.catalog = c; return b }
func (b *AuditEventBuilder) Stream(v string) *AuditEventBuilder         { b.record.StreamID = v; return b }
func (b *AuditEventBuilder) Tenant(v string) *AuditEventBuilder         { b.record.TenantID = v; return b }
func (b *AuditEventBuilder) Kind(v string) *AuditEventBuilder           { b.record.Kind = v; return b }
func (b *AuditEventBuilder) Category(v string) *AuditEventBuilder       { b.record.Category = v; return b }
func (b *AuditEventBuilder) Actor(v string) *AuditEventBuilder          { b.record.ActorID = v; return b }
func (b *AuditEventBuilder) Subject(v string) *AuditEventBuilder        { b.record.SubjectID = v; return b }
func (b *AuditEventBuilder) Action(v string) *AuditEventBuilder         { b.record.Action = v; return b }
func (b *AuditEventBuilder) Resource(kind, id string) *AuditEventBuilder {
	b.record.ResourceType = kind
	b.record.ResourceID = id
	return b
}
func (b *AuditEventBuilder) Outcome(v string) *AuditEventBuilder { b.record.Outcome = v; return b }
func (b *AuditEventBuilder) Reason(v string) *AuditEventBuilder  { b.record.Reason = v; return b }
func (b *AuditEventBuilder) Correlation(request, correlation, trace, span string) *AuditEventBuilder {
	b.record.RequestID = request
	b.record.CorrelationID = correlation
	b.record.TraceID = trace
	b.record.SpanID = span
	return b
}
func (b *AuditEventBuilder) Schema(name, version string) *AuditEventBuilder {
	b.record.SchemaName = name
	b.record.SchemaVersion = version
	return b
}
func (b *AuditEventBuilder) Policy(retention, classification string) *AuditEventBuilder {
	b.record.Retention = retention
	b.record.Classification = classification
	return b
}
func (b *AuditEventBuilder) Attr(k string, v any) *AuditEventBuilder {
	if b.record.Attributes == nil {
		b.record.Attributes = map[string]any{}
	}
	if k == "" {
		b.err = errors.New("zlog: empty audit attribute key")
		return b
	}
	if _, ok := b.record.Attributes[k]; ok {
		b.err = fmt.Errorf("zlog: duplicate audit attribute %q", k)
		return b
	}
	b.record.Attributes[k] = v
	return b
}
func (b *AuditEventBuilder) Commit(ctx context.Context) (AppendReceipt, error) {
	if b.err != nil {
		return AppendReceipt{}, b.err
	}
	if b.store == nil {
		return AppendReceipt{}, errors.New("zlog: audit store is required")
	}
	if b.catalog != nil {
		attrs := make([]Attr, 0, len(b.record.Attributes)+8)
		for k, v := range b.record.Attributes {
			attrs = append(attrs, Any(k, v))
		}
		attrs = append(attrs, String("actor.id", b.record.ActorID), String("event.action", b.record.Action), String("resource.id", b.record.ResourceID), String("event.outcome", b.record.Outcome))
		if err := b.catalog.Validate(b.record.Name, attrs); err != nil {
			return AppendReceipt{}, err
		}
		if d, ok := b.catalog.Get(b.record.Name); ok {
			if b.record.Kind == "audit" && d.DefaultKind != "" {
				b.record.Kind = d.DefaultKind
			}
			if b.record.Outcome == "" {
				b.record.Outcome = d.DefaultOutcome
			}
			if b.record.Retention == "" {
				b.record.Retention = d.Retention
			}
			if b.record.Classification == "" {
				b.record.Classification = d.Classification
			}
			b.record.SchemaName = d.Name
			b.record.SchemaVersion = d.Version
		}
	}
	return b.store.Append(ctx, b.record)
}

var _ = strings.Builder{}
