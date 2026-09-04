package zlog

import (
	"strconv"
	"unicode/utf8"
)

func appendFastString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '\\' && c != '"' {
				i++
				continue
			}
			dst = append(dst, s[start:i]...)
			switch c {
			case '\\', '"':
				dst = append(dst, '\\', c)
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			case '\b':
				dst = append(dst, '\\', 'b')
			case '\f':
				dst = append(dst, '\\', 'f')
			default:
				const hex = "0123456789abcdef"
				dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			dst = append(dst, s[start:i]...)
			dst = append(dst, '\\', 'u', 'f', 'f', 'f', 'd')
			i++
			start = i
			continue
		}
		i += size
	}
	dst = append(dst, s[start:]...)
	return append(dst, '"')
}

func appendFastValue(dst []byte, a Attr) []byte {
	switch a.Kind {
	case KindString, KindError:
		return appendFastString(dst, a.Str)
	case KindBool:
		if a.I64 != 0 {
			return append(dst, "true"...)
		}
		return append(dst, "false"...)
	case KindInt64, KindDuration:
		return strconv.AppendInt(dst, a.I64, 10)
	case KindUint64:
		return strconv.AppendUint(dst, a.U64, 10)
	case KindFloat64:
		return strconv.AppendFloat(dst, mathFloat64frombits(a.U64), 'g', -1, 64)
	case KindRawJSON:
		return append(dst, a.Bytes...)
	default:
		return nil
	}
}

func fastValueSupported(a Attr) bool {
	switch a.Kind {
	case KindInvalid, KindString, KindError, KindBool, KindInt64, KindDuration, KindUint64, KindFloat64, KindRawJSON:
		return true
	default:
		return false
	}
}

func appendFastAttr(dst []byte, a Attr) []byte {
	if a.Kind == KindInvalid || a.Key == "" {
		return dst
	}
	dst = append(dst, ',')
	if a.keyJSON != "" {
		dst = append(dst, a.keyJSON...)
	} else {
		dst = appendFastString(dst, a.Key)
		dst = append(dst, ':')
	}
	return appendFastValue(dst, a)
}

func appendFastKeyString(dst []byte, key, value string) []byte {
	dst = append(dst, ',', '"')
	dst = append(dst, key...)
	dst = append(dst, '"', ':')
	return appendFastString(dst, value)
}

func appendFastKeyInt(dst []byte, key string, value int) []byte {
	dst = append(dst, ',', '"')
	dst = append(dst, key...)
	dst = append(dst, '"', ':')
	return strconv.AppendInt(dst, int64(value), 10)
}

func appendFastKeyBool(dst []byte, key string, value bool) []byte {
	dst = append(dst, ',', '"')
	dst = append(dst, key...)
	dst = append(dst, '"', ':')
	if value {
		return append(dst, "true"...)
	}
	return append(dst, "false"...)
}
