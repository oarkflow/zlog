package zlog

import (
	"bytes"
	"strconv"
	"time"
	"unicode/utf8"
)

func appendInt(buf *bytes.Buffer, v int64) {
	var tmp [20]byte
	buf.Write(strconv.AppendInt(tmp[:0], v, 10))
}
func appendUint(buf *bytes.Buffer, v uint64) {
	var tmp [20]byte
	buf.Write(strconv.AppendUint(tmp[:0], v, 10))
}
func appendFloat(buf *bytes.Buffer, v float64) {
	var tmp [32]byte
	buf.Write(strconv.AppendFloat(tmp[:0], v, 'g', -1, 64))
}
func appendTime(buf *bytes.Buffer, t time.Time, layout string) {
	var tmp [96]byte
	buf.Write(t.AppendFormat(tmp[:0], layout))
}

func appendJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '\\' && c != '"' {
				i++
				continue
			}
			if start < i {
				buf.WriteString(s[start:i])
			}
			switch c {
			case '\\', '"':
				buf.WriteByte('\\')
				buf.WriteByte(c)
			case '\n':
				buf.WriteString(`\n`)
			case '\r':
				buf.WriteString(`\r`)
			case '\t':
				buf.WriteString(`\t`)
			case '\b':
				buf.WriteString(`\b`)
			case '\f':
				buf.WriteString(`\f`)
			default:
				buf.WriteString(`\u00`)
				const hex = "0123456789abcdef"
				buf.WriteByte(hex[c>>4])
				buf.WriteByte(hex[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, sz := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && sz == 1 {
			if start < i {
				buf.WriteString(s[start:i])
			}
			buf.WriteString(`\ufffd`)
			i++
			start = i
			continue
		}
		i += sz
	}
	if start < len(s) {
		buf.WriteString(s[start:])
	}
	buf.WriteByte('"')
}

func appendQuotedLogfmt(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' || c == '"' || c == '\n' || c == '\r' || c == '\t' {
			if start < i {
				buf.WriteString(s[start:i])
			}
			switch c {
			case '\\', '"':
				buf.WriteByte('\\')
				buf.WriteByte(c)
			case '\n':
				buf.WriteString(`\n`)
			case '\r':
				buf.WriteString(`\r`)
			case '\t':
				buf.WriteString(`\t`)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		buf.WriteString(s[start:])
	}
	buf.WriteByte('"')
}
