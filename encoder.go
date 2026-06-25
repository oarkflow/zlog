package zlog

import "bytes"

type Encoder interface {
	Encode(*bytes.Buffer, Record, []Attr) error
}

type Format string

const (
	FormatJSON    Format = "json"
	FormatConsole Format = "console"
	FormatLogfmt  Format = "logfmt"
)
