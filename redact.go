package zlog

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"unicode"
)

// CompliancePreset adds conservative field dictionaries for regulated logs.
// These are intentionally key-name based. They reduce accidental leakage but do
// not make an application compliant by themselves.
type CompliancePreset string

const (
	CompliancePII     CompliancePreset = "pii"
	ComplianceHIPAA   CompliancePreset = "hipaa"
	CompliancePCI     CompliancePreset = "pci"
	ComplianceSecrets CompliancePreset = "secrets"
)

// Redactor controls sensitive-data protection. It is intentionally stdlib-only.
// The hot path remains allocation-free for normal key based masking. Hashing,
// value scanning, raw JSON parsing and Any sanitization are compliance features
// and cost more CPU.
type Redactor struct {
	Enabled     bool
	Mask        string
	Keys        []string // substring match, case-insensitive; supports nested paths such as user.email
	ExactKeys   []string // exact key/path match, case-insensitive
	AllowKeys   []string // exact key/path values that must never be redacted
	ValueScan   bool     // detect obvious secrets/PII by value, not only by key
	KeepLast    int      // keep last N chars when MaskPartial is true
	MaskPartial bool
	Hash        bool
	HashKey     []byte
	Presets     []CompliancePreset  // pii, hipaa, pci, secrets
	Dictionary  RedactionDictionary // caller/config supplied field dictionaries for presets
	matcher     *redactionMatcher
	MaxDepth    int // recursion cap for Any/RawJSON/Group sanitization; default 8
}

func DefaultRedactor() Redactor {
	return Redactor{
		Enabled:    true,
		Mask:       "[REDACTED]",
		ValueScan:  true,
		Presets:    []CompliancePreset{ComplianceSecrets},
		Dictionary: DefaultRedactionDictionary(),
		MaxDepth:   8,
	}
}

func NoRedaction() Redactor { return Redactor{} }

func (r Redactor) isZero() bool {
	return !r.Enabled && r.Mask == "" && len(r.Keys) == 0 && len(r.ExactKeys) == 0 && len(r.AllowKeys) == 0 && !r.ValueScan && r.KeepLast == 0 && !r.MaskPartial && !r.Hash && len(r.HashKey) == 0 && len(r.Presets) == 0 && r.Dictionary.isZero() && r.matcher == nil && r.MaxDepth == 0
}

// WithSensitiveFields returns a copy with caller-defined field names/paths added.
// Use exact=true for strict key/path matching, false for substring matching.
func (r Redactor) WithSensitiveFields(exact bool, fields ...string) Redactor {
	if exact {
		r.ExactKeys = append(r.ExactKeys, fields...)
	} else {
		r.Keys = append(r.Keys, fields...)
	}
	return r
}

// ComplianceRedactor returns a redactor with selected regulatory dictionaries.
func ComplianceRedactor(presets ...CompliancePreset) Redactor {
	r := DefaultRedactor()
	if len(presets) > 0 {
		r.Presets = append([]CompliancePreset(nil), presets...)
	}
	return r
}

// WithDictionary returns a copy using caller-supplied preset dictionaries.
// Empty dictionary slices inherit DefaultRedactionDictionary during normalization.
func (r Redactor) WithDictionary(d RedactionDictionary) Redactor {
	r.Dictionary = d
	return r
}

// EnterpriseRedactor enables the full conservative dictionary for secrets, PII, HIPAA and PCI.
// Use this for compliance-sensitive services; DefaultRedactor keeps only the low-cost secrets preset.
func EnterpriseRedactor() Redactor {
	r := DefaultRedactor()
	r.Presets = []CompliancePreset{ComplianceSecrets, CompliancePII, ComplianceHIPAA, CompliancePCI}
	return r
}

func (r Redactor) normalized() Redactor {
	if r.Mask == "" {
		r.Mask = "[REDACTED]"
	}
	if r.MaxDepth <= 0 {
		r.MaxDepth = 8
	}
	if len(r.Presets) > 0 {
		if r.Dictionary.isZero() {
			r.Dictionary = DefaultRedactionDictionary()
		}
		if r.matcher == nil {
			r.matcher = newRedactionMatcher(r.Dictionary)
		}
	}
	return r
}

func (r Redactor) RedactAttrs(attrs []Attr) []Attr {
	if !r.Enabled {
		return attrs
	}
	r = r.normalized()
	for i := range attrs {
		redactAttrPath(&attrs[i], r, "")
	}
	return attrs
}

func redactAttr(a *Attr, r Redactor)         { redactAttrPath(a, r.normalized(), "") }
func redactAttrPrepared(a *Attr, r Redactor) { redactAttrPath(a, r, "") }

func redactAttrPath(a *Attr, r Redactor, parent string) {
	if a.Kind == KindInvalid {
		return
	}
	path := joinPath(parent, a.Key)
	if a.Kind == KindGroup {
		if shouldRedactKeyPath(a.Key, path, r) {
			maskAttr(a, r)
			return
		}
		for i := range a.Group {
			redactAttrPath(&a.Group[i], r, path)
		}
		return
	}
	if shouldRedactKeyPath(a.Key, path, r) || shouldRedactValue(*a, r) {
		maskAttr(a, r)
		return
	}
	switch a.Kind {
	case KindAny:
		a.Any = sanitizeAny(a.Any, a.Key, path, r, r.MaxDepth)
	case KindRawJSON:
		a.Bytes = sanitizeRawJSON(a.Bytes, a.Key, path, r)
	}
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	if key == "" {
		return parent
	}
	return parent + "." + key
}

func shouldRedactKey(key string, r Redactor) bool {
	return shouldRedactKeyPath(key, key, r.normalized())
}

func shouldRedactKeyPath(key, path string, r Redactor) bool {
	if key == "" && path == "" {
		return false
	}
	for _, allow := range r.AllowKeys {
		if equalFoldASCII(key, allow) || equalFoldASCII(path, allow) {
			return false
		}
	}
	for _, exact := range r.ExactKeys {
		if equalFoldASCII(key, exact) || equalFoldASCII(path, exact) {
			return true
		}
	}
	if shouldRedactPresetKey(key, path, r) {
		return true
	}
	for _, k := range r.Keys {
		if k != "" && (containsFoldASCII(key, k) || containsFoldASCII(path, k)) {
			return true
		}
	}
	return false
}

func shouldRedactPresetKey(key, path string, r Redactor) bool {
	if len(r.Presets) == 0 {
		return false
	}
	m := r.matcher
	if m == nil {
		d := r.Dictionary
		if d.isZero() {
			d = DefaultRedactionDictionary()
		}
		m = newRedactionMatcher(d)
	}
	for _, p := range r.Presets {
		switch p {
		case ComplianceSecrets:
			if m.secrets.match(key, path) {
				return true
			}
		case CompliancePII:
			if m.pii.match(key, path) {
				return true
			}
		case ComplianceHIPAA:
			if m.pii.match(key, path) || m.hipaa.match(key, path) {
				return true
			}
		case CompliancePCI:
			if m.pci.match(key, path) {
				return true
			}
		}
	}
	return false
}

func tokenMatchFold(key string, fn func(string) bool) bool {
	start := 0
	for i := 0; i <= len(key); i++ {
		if i == len(key) || key[i] == '.' || key[i] == '_' || key[i] == '-' || key[i] == '/' || key[i] == ' ' {
			if i > start && fn(key[start:i]) {
				return true
			}
			start = i + 1
		}
	}
	return false
}

func shouldRedactValue(a Attr, r Redactor) bool {
	if !r.ValueScan {
		return false
	}
	var s string
	switch a.Kind {
	case KindString, KindError:
		s = a.Str
	case KindBytes:
		s = string(a.Bytes)
	default:
		return false
	}
	return shouldRedactStringValue(s, r)
}

func shouldRedactStringValue(s string, r Redactor) bool {
	lo, hi := trimSpaceBounds(s)
	if hi <= lo {
		return false
	}
	s = s[lo:hi]
	if len(s) < 6 {
		return false
	}
	if hasPrefixFoldASCII(s, "bearer ") || hasPrefixFoldASCII(s, "basic ") || hasPrefixFoldASCII(s, "token ") {
		return true
	}
	if len(s) > 32 && looksLikeJWT(s) {
		return true
	}
	if len(s) >= 13 && len(s) <= 32 && looksLikeCardNumber(s) {
		return true
	}
	if len(s) > 40 && containsFoldASCIIWhole(s, "-----begin ") && containsFoldASCIIWhole(s, "private key-----") {
		return true
	}
	for _, preset := range r.Presets {
		switch preset {
		case CompliancePII, ComplianceHIPAA:
			if looksLikeEmail(s) || looksLikeSSN(s) {
				return true
			}
		}
	}
	return false
}

func maskAttr(a *Attr, r Redactor) {
	old := attrPlainString(*a)
	mask := maskValue(old, r)
	a.Kind = KindString
	a.Str = mask
	a.Bytes = nil
	a.Any = nil
	a.Group = nil
	a.I64 = 0
	a.U64 = 0
}

func attrPlainString(a Attr) string {
	switch a.Kind {
	case KindString, KindError:
		return a.Str
	case KindBytes, KindRawJSON:
		return string(a.Bytes)
	case KindAny:
		if a.Any == nil {
			return ""
		}
		return strings.TrimSpace(reflect.ValueOf(a.Any).String())
	default:
		return ""
	}
}

func maskValue(old string, r Redactor) string {
	mask := r.Mask
	if mask == "" {
		mask = "[REDACTED]"
	}
	if r.Hash {
		return hashMaskedValue(old, r.HashKey)
	}
	if r.MaskPartial && r.KeepLast > 0 && len(old) > r.KeepLast {
		return mask + old[len(old)-r.KeepLast:]
	}
	return mask
}

func hashMaskedValue(v string, key []byte) string {
	if len(key) > 0 {
		m := hmac.New(sha256.New, key)
		_, _ = m.Write([]byte(v))
		return "sha256:" + hex.EncodeToString(m.Sum(nil))
	}
	s := sha256.Sum256([]byte(v))
	return "sha256:" + hex.EncodeToString(s[:])
}

func sanitizeRawJSON(raw []byte, key, path string, r Redactor) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	v = sanitizeJSONValue(v, key, path, r, r.MaxDepth)
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

func sanitizeAny(v any, key, path string, r Redactor, depth int) any {
	if v == nil || depth <= 0 {
		return v
	}
	if shouldRedactKeyPath(key, path, r) {
		return maskValue(anyString(v), r)
	}
	switch x := v.(type) {
	case string:
		if shouldRedactStringValue(x, r) {
			return maskValue(x, r)
		}
		return x
	case []byte:
		if shouldRedactStringValue(string(x), r) {
			return []byte(maskValue(string(x), r))
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			p := joinPath(path, k)
			out[k] = sanitizeAny(vv, k, p, r, depth-1)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = sanitizeAny(x[i], key, path, r, depth-1)
		}
		return out
	}
	return sanitizeReflect(reflect.ValueOf(v), key, path, r, depth)
}

func sanitizeJSONValue(v any, key, path string, r Redactor, depth int) any {
	return sanitizeAny(v, key, path, r, depth)
}

func sanitizeReflect(rv reflect.Value, key, path string, r Redactor, depth int) any {
	if !rv.IsValid() || depth <= 0 {
		return anyFromValue(rv)
	}
	for rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.String:
		s := rv.String()
		if shouldRedactStringValue(s, r) {
			return maskValue(s, r)
		}
		return s
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return anyFromValue(rv)
		}
		out := make(map[string]any, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			k := iter.Key().String()
			p := joinPath(path, k)
			out[k] = sanitizeAny(iter.Value().Interface(), k, p, r, depth-1)
		}
		return out
	case reflect.Slice, reflect.Array:
		if rv.Type().Elem().Kind() == reflect.Uint8 {
			b := rv.Bytes()
			if shouldRedactStringValue(string(b), r) {
				return maskValue(string(b), r)
			}
			return anyFromValue(rv)
		}
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			out[i] = sanitizeAny(rv.Index(i).Interface(), key, path, r, depth-1)
		}
		return out
	case reflect.Struct:
		out := make(map[string]any, rv.NumField())
		t := rv.Type()
		for i := 0; i < rv.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" { // unexported
				continue
			}
			name := jsonFieldName(f)
			if name == "-" || name == "" {
				continue
			}
			p := joinPath(path, name)
			out[name] = sanitizeAny(rv.Field(i).Interface(), name, p, r, depth-1)
		}
		return out
	default:
		return anyFromValue(rv)
	}
}

func anyFromValue(rv reflect.Value) any {
	if !rv.IsValid() || !rv.CanInterface() {
		return nil
	}
	return rv.Interface()
}

func anyString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func jsonFieldName(f reflect.StructField) string {
	name := f.Name
	if tag := f.Tag.Get("json"); tag != "" {
		if idx := strings.IndexByte(tag, ','); idx >= 0 {
			tag = tag[:idx]
		}
		if tag != "" {
			name = tag
		}
	}
	return name
}

func looksLikeJWT(s string) bool {
	parts := 0
	for _, c := range s {
		if c == '.' {
			parts++
			continue
		}
		if !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' && c != '_' {
			return false
		}
	}
	return parts == 2 && len(s) > 32
}

func looksLikeCardNumber(s string) bool {
	digits := [20]int{}
	n := 0
	for _, r := range s {
		if unicode.IsDigit(r) {
			if n >= len(digits) {
				return false
			}
			digits[n] = int(r - '0')
			n++
		} else if r != ' ' && r != '-' {
			return false
		}
	}
	if n < 13 || n > 19 {
		return false
	}
	sum := 0
	double := false
	for i := n - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func looksLikeEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at != strings.LastIndexByte(s, '@') || at >= len(s)-3 {
		return false
	}
	dot := strings.LastIndexByte(s[at+1:], '.')
	return dot > 0 && at+1+dot < len(s)-1 && !strings.ContainsAny(s, " \t\n\r")
}

func looksLikeSSN(s string) bool {
	if len(s) != 11 || s[3] != '-' || s[6] != '-' {
		return false
	}
	for i, c := range s {
		if i == 3 || i == 6 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
