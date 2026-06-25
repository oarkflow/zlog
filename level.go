package zlog

import (
	"strconv"
	"strings"
	"sync/atomic"
)

type Level int8

const (
	TraceLevel     Level = -8
	DebugLevel     Level = -4
	InfoLevel      Level = 0
	NoticeLevel    Level = 2
	WarnLevel      Level = 4
	ErrorLevel     Level = 8
	CriticalLevel  Level = 10
	AlertLevel     Level = 12
	EmergencyLevel Level = 14
	FatalLevel     Level = 16
	PanicLevel     Level = 18
	DisabledLevel  Level = 127
)

func (l Level) String() string {
	switch l {
	case TraceLevel:
		return "TRACE"
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case NoticeLevel:
		return "NOTICE"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case CriticalLevel:
		return "CRITICAL"
	case AlertLevel:
		return "ALERT"
	case EmergencyLevel:
		return "EMERGENCY"
	case FatalLevel:
		return "FATAL"
	case PanicLevel:
		return "PANIC"
	case DisabledLevel:
		return "DISABLED"
	default:
		return "LEVEL(" + strconv.Itoa(int(l)) + ")"
	}
}

func ParseLevel(s string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return TraceLevel, true
	case "debug":
		return DebugLevel, true
	case "info", "":
		return InfoLevel, true
	case "notice":
		return NoticeLevel, true
	case "warn", "warning":
		return WarnLevel, true
	case "error", "err":
		return ErrorLevel, true
	case "critical", "crit":
		return CriticalLevel, true
	case "alert":
		return AlertLevel, true
	case "emergency", "emerg":
		return EmergencyLevel, true
	case "fatal":
		return FatalLevel, true
	case "panic":
		return PanicLevel, true
	case "disabled", "off":
		return DisabledLevel, true
	default:
		i, err := strconv.Atoi(s)
		if err == nil {
			return Level(i), true
		}
		return InfoLevel, false
	}
}

type AtomicLevel struct{ v atomic.Int32 }

func NewAtomicLevel(l Level) *AtomicLevel   { a := &AtomicLevel{}; a.Set(l); return a }
func (a *AtomicLevel) Set(l Level)          { a.v.Store(int32(l)) }
func (a *AtomicLevel) Get() Level           { return Level(a.v.Load()) }
func (a *AtomicLevel) Enabled(l Level) bool { return l >= a.Get() && a.Get() != DisabledLevel }
