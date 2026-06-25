package zlog

var global = NewProduction()

func Default() *Logger { return global }
func SetDefault(l *Logger) {
	if l != nil {
		global = l
	}
}
func Trace(msg string, attrs ...Attr) { global.Trace(msg, attrs...) }
func Debug(msg string, attrs ...Attr) { global.Debug(msg, attrs...) }
func Info(msg string, attrs ...Attr)  { global.Info(msg, attrs...) }
func Warn(msg string, attrs ...Attr)  { global.Warn(msg, attrs...) }
func Error(msg string, attrs ...Attr) { global.Error(msg, attrs...) }
func Close() error                    { return global.Close() }
func Flush() error                    { return global.Flush() }
