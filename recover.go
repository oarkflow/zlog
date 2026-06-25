package zlog

import "runtime/debug"

func (l *Logger) Recover(msg string) {
	if rec := recover(); rec != nil {
		l.Error(msg, Any("panic", rec), Bytes("stack", debug.Stack()))
	}
}
