package zlog

import "log"

type logWriter struct {
	l     *Logger
	level Level
}

func (w logWriter) Write(p []byte) (int, error) {
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	w.l.Log(w.level, msg)
	return len(p), nil
}
func (l *Logger) StandardLogger(level Level) *log.Logger {
	return log.New(logWriter{l: l, level: level}, "", 0)
}
