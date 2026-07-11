package zlog

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// CanonicalJSON returns deterministic JSON suitable for hashing and signing.
// It rejects NaN/Inf, cycles, unsupported values, duplicate object keys and
// trailing JSON values. Object keys are ordered lexicographically.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	seen := make(map[visit]bool)
	if err := appendCanonical(&buf, reflect.ValueOf(v), seen, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func CanonicalizeJSON(raw []byte) ([]byte, error) {
	v, err := decodeStrictJSON(raw)
	if err != nil {
		return nil, err
	}
	return CanonicalJSON(v)
}

type visit struct {
	typ reflect.Type
	ptr uintptr
}

func appendCanonical(buf *bytes.Buffer, rv reflect.Value, seen map[visit]bool, depth int) error {
	if depth > 64 {
		return errors.New("zlog: canonical value nesting exceeds 64")
	}
	if !rv.IsValid() {
		buf.WriteString("null")
		return nil
	}
	if rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			buf.WriteString("null")
			return nil
		}
		return appendCanonical(buf, rv.Elem(), seen, depth+1)
	}
	if rv.CanInterface() {
		switch x := rv.Interface().(type) {
		case json.RawMessage:
			canon, err := CanonicalizeJSON(x)
			if err != nil {
				return err
			}
			buf.Write(canon)
			return nil
		case json.Number:
			return appendCanonicalNumber(buf, string(x))
		case time.Time:
			appendCanonicalJSONString(buf, x.UTC().Format(time.RFC3339Nano))
			return nil
		case time.Duration:
			buf.WriteString(strconv.FormatInt(int64(x), 10))
			return nil
		case []byte:
			appendCanonicalJSONString(buf, base64.RawStdEncoding.EncodeToString(x))
			return nil
		}
	}
	switch rv.Kind() {
	case reflect.Pointer:
		if rv.IsNil() {
			buf.WriteString("null")
			return nil
		}
		key := visit{rv.Type(), rv.Pointer()}
		if seen[key] {
			return errors.New("zlog: cycle in canonical value")
		}
		seen[key] = true
		err := appendCanonical(buf, rv.Elem(), seen, depth+1)
		delete(seen, key)
		return err
	case reflect.Bool:
		if rv.Bool() {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case reflect.String:
		if !utf8.ValidString(rv.String()) {
			return errors.New("zlog: invalid UTF-8 string")
		}
		appendCanonicalJSONString(buf, rv.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		buf.WriteString(strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		buf.WriteString(strconv.FormatUint(rv.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		f := rv.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return errors.New("zlog: non-finite number")
		}
		bits := rv.Type().Bits()
		buf.WriteString(strconv.FormatFloat(f, 'g', -1, bits))
	case reflect.Slice:
		if rv.IsNil() {
			buf.WriteString("null")
			return nil
		}
		key := visit{rv.Type(), rv.Pointer()}
		if rv.Pointer() != 0 {
			if seen[key] {
				return errors.New("zlog: cycle in canonical value")
			}
			seen[key] = true
			defer delete(seen, key)
		}
		fallthrough
	case reflect.Array:
		buf.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := appendCanonical(buf, rv.Index(i), seen, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case reflect.Map:
		if rv.IsNil() {
			buf.WriteString("null")
			return nil
		}
		if rv.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("zlog: map key %s is not a string", rv.Type().Key())
		}
		key := visit{rv.Type(), rv.Pointer()}
		if rv.Pointer() != 0 {
			if seen[key] {
				return errors.New("zlog: cycle in canonical value")
			}
			seen[key] = true
			defer delete(seen, key)
		}
		keys := rv.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		buf.WriteByte('{')
		for i, k := range keys {
			if !utf8.ValidString(k.String()) {
				return errors.New("zlog: invalid UTF-8 object key")
			}
			if i > 0 {
				buf.WriteByte(',')
			}
			appendCanonicalJSONString(buf, k.String())
			buf.WriteByte(':')
			if err := appendCanonical(buf, rv.MapIndex(k), seen, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case reflect.Struct:
		t := rv.Type()
		type field struct {
			name  string
			value reflect.Value
		}
		fields := make([]field, 0, rv.NumField())
		for i := 0; i < rv.NumField(); i++ {
			sf := t.Field(i)
			if sf.PkgPath != "" {
				continue
			}
			tag := sf.Tag.Get("json")
			name, opts, _ := strings.Cut(tag, ",")
			if name == "-" {
				continue
			}
			if name == "" {
				name = sf.Name
			}
			fv := rv.Field(i)
			if strings.Contains(opts, "omitempty") && isEmptyCanonical(fv) {
				continue
			}
			fields = append(fields, field{name, fv})
		}
		sort.Slice(fields, func(i, j int) bool { return fields[i].name < fields[j].name })
		for i := 1; i < len(fields); i++ {
			if fields[i-1].name == fields[i].name {
				return fmt.Errorf("zlog: duplicate canonical struct field %q", fields[i].name)
			}
		}
		buf.WriteByte('{')
		for i, f := range fields {
			if i > 0 {
				buf.WriteByte(',')
			}
			appendCanonicalJSONString(buf, f.name)
			buf.WriteByte(':')
			if err := appendCanonical(buf, f.value, seen, depth+1); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("zlog: unsupported canonical type %s", rv.Type())
	}
	return nil
}

func appendCanonicalJSONString(buf *bytes.Buffer, s string) {
	b, _ := json.Marshal(s)
	buf.Write(b)
}

func appendCanonicalNumber(buf *bytes.Buffer, s string) error {
	if strings.ContainsAny(s, ".eE") {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("zlog: invalid number %q", s)
		}
		buf.WriteString(strconv.FormatFloat(f, 'g', -1, 64))
		return nil
	}
	if strings.HasPrefix(s, "-") {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		buf.WriteString(strconv.FormatInt(v, 10))
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return err
	}
	buf.WriteString(strconv.FormatUint(v, 10))
	return nil
}

func isEmptyCanonical(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.String, reflect.Array:
		return v.Len() == 0
	case reflect.Map, reflect.Slice:
		return v.IsNil() || v.Len() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	case reflect.Struct:
		return v.IsZero()
	}
	return false
}

func decodeStrictJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("zlog: invalid UTF-8 JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeJSONValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("zlog: unexpected trailing JSON")
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("zlog: trailing JSON value")
	} else if err != io.EOF {
		return nil, err
	}
	return v, nil
}

func decodeJSONValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("zlog: JSON nesting exceeds 64")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := make(map[string]any)
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("zlog: invalid object key")
				}
				if _, exists := m[k]; exists {
					return nil, fmt.Errorf("zlog: duplicate JSON key %q", k)
				}
				v, err := decodeJSONValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("zlog: invalid object termination")
			}
			return m, nil
		case '[':
			var a []any
			for dec.More() {
				v, err := decodeJSONValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("zlog: invalid array termination")
			}
			return a, nil
		}
		return nil, errors.New("zlog: unexpected delimiter")
	default:
		return tok, nil
	}
}

func domainHash(domain string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	for _, p := range parts {
		var lenbuf [8]byte
		// Write an unambiguous 64-bit big-endian length without importing binary.
		n := uint64(len(p))
		for i := 7; i >= 0; i-- {
			lenbuf[i] = byte(n)
			n >>= 8
		}
		h.Write(lenbuf[:])
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func newSecureID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func validateAuditValue(v any, depth, maxDepth, maxAttrs int) error {
	if v == nil {
		return nil
	}
	if depth > maxDepth {
		return fmt.Errorf("zlog: audit attributes exceed nesting depth %d", maxDepth)
	}
	switch x := v.(type) {
	case map[string]any:
		if len(x) > maxAttrs {
			return fmt.Errorf("zlog: audit attributes exceed %d entries", maxAttrs)
		}
		for k, val := range x {
			if k == "" || len(k) > 512 {
				return errors.New("zlog: invalid audit attribute key")
			}
			if err := validateAuditValue(val, depth+1, maxDepth, maxAttrs); err != nil {
				return err
			}
		}
	case []any:
		if len(x) > maxAttrs {
			return fmt.Errorf("zlog: audit array exceeds %d entries", maxAttrs)
		}
		for _, val := range x {
			if err := validateAuditValue(val, depth+1, maxDepth, maxAttrs); err != nil {
				return err
			}
		}
	case string:
		if len(x) > 1<<20 {
			return errors.New("zlog: audit string exceeds 1 MiB")
		}
	case []byte:
		if len(x) > 1<<20 {
			return errors.New("zlog: audit bytes exceed 1 MiB")
		}
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return errors.New("zlog: non-finite audit number")
		}
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number, time.Time, time.Duration:
		return nil
	default:
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.Map || rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array || rv.Kind() == reflect.Struct || rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Interface {
			_, err := CanonicalJSON(v)
			return err
		}
		return fmt.Errorf("zlog: unsupported audit attribute type %T", v)
	}
	return nil
}
