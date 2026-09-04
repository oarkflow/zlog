package zlog

import (
	"sync/atomic"
	"time"
)

// cachedClock keeps coarse timestamps off the logging hot path when requested.
var cachedClock atomic.Int64
var cachedClockText atomic.Value

func init() {
	cachedClock.Store(time.Now().UnixNano())
	cachedClockText.Store(time.Now().Format(time.RFC3339Nano))
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for now := range t.C {
			cachedClock.Store(now.UnixNano())
			cachedClockText.Store(now.Format(time.RFC3339Nano))
		}
	}()
}

func cachedNow() time.Time { return time.Unix(0, cachedClock.Load()) }
func cachedTimestamp() (time.Time, string) {
	return cachedNow(), cachedClockText.Load().(string)
}
