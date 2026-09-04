package zlog

// FieldKey is a predeclared JSON field name. Reusing a FieldKey avoids
// re-escaping the same key on every structured log call.
type FieldKey struct {
	name string
	json string
}

func NewFieldKey(name string) FieldKey {
	key := appendFastString(nil, name)
	key = append(key, ':')
	return FieldKey{name: name, json: string(key)}
}

func (k FieldKey) String(value string) Attr {
	return Attr{Key: k.name, Kind: KindString, Str: value, keyJSON: k.json}
}
func (k FieldKey) Int(value int) Attr {
	return Attr{Key: k.name, Kind: KindInt64, I64: int64(value), keyJSON: k.json}
}
func (k FieldKey) Bool(value bool) Attr { return Attr{Key: k.name, Kind: KindBool, keyJSON: k.json} }
