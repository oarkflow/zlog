//go:build windows

package zlog

import "errors"

// SyslogPriority mirrors log/syslog.Priority's underlying type so callers on
// Windows can still compile a call to NewSyslogSink (it always fails: there
// is no syslog daemon to dial on this platform, and the standard library's
// log/syslog package does not build here at all).
type SyslogPriority int

// NewSyslogSink always fails on Windows; see syslog_unix.go.
func NewSyslogSink(network, raddr, tag string, priority SyslogPriority) (Sink, error) {
	return nil, errors.New("zlog: syslog is not supported on windows (log/syslog does not build on this platform)")
}
