//go:build !windows

package zlog

import "log/syslog"

// NewSyslogSink dials a syslog daemon and returns a Sink that writes to it.
//
// log/syslog is itself Unix/Plan9/JS-only in the standard library (Windows has
// no syslog protocol), so this is built only on those platforms; see
// syslog_windows.go for the Windows stub.
func NewSyslogSink(network, raddr, tag string, priority syslog.Priority) (Sink, error) {
	w, err := syslog.Dial(network, raddr, priority, tag)
	if err != nil {
		return nil, err
	}
	return NewWriterSink(w, NewLogfmtEncoder(), TraceLevel), nil
}
