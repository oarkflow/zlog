package zlog

import (
	"encoding/json"
	"expvar"
	"net/http"
)

type StatsSnapshot struct {
	Sink       SinkStats `json:"sink"`
	Dropped    uint64    `json:"dropped,omitempty"`
	QueueDepth int64     `json:"queue_depth,omitempty"`
}

func (l *Logger) Snapshot() StatsSnapshot {
	ss := StatsSnapshot{Sink: l.sink.Stats()}
	if a, ok := l.sink.(*AsyncSink); ok {
		ss.Dropped = a.Dropped()
		ss.QueueDepth = a.QueueDepth()
	}
	return ss
}
func (l *Logger) StatsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(l.Snapshot())
	})
}
func (l *Logger) PublishExpvar(name string) {
	expvar.Publish(name, expvar.Func(func() any { return l.Snapshot() }))
}
