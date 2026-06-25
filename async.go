package zlog

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type DropPolicy int

const (
	DropBlock DropPolicy = iota
	DropNewest
	DropOldest
	DropDebugFirst
)

type AsyncOptions struct {
	Capacity       int
	BatchSize      int
	FlushInterval  time.Duration
	DropPolicy     DropPolicy
	EmergencyLevel Level
}

type asyncItem struct {
	r      Record
	static []Attr
}

type flushReq struct{ done chan error }

type AsyncSink struct {
	sink    Sink
	slots   []asyncItem
	free    chan int
	ready   chan int
	flushCh chan flushReq
	opts    AsyncOptions
	done    chan struct{}
	closed  atomic.Bool
	dropped atomic.Uint64
	queued  atomic.Int64
	wg      sync.WaitGroup
}

func NewAsyncSink(s Sink, opts AsyncOptions) *AsyncSink {
	if opts.Capacity <= 0 {
		opts.Capacity = 8192
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 256
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = time.Second
	}
	if opts.EmergencyLevel == 0 {
		opts.EmergencyLevel = FatalLevel
	}
	a := &AsyncSink{sink: s, slots: make([]asyncItem, opts.Capacity), free: make(chan int, opts.Capacity), ready: make(chan int, opts.Capacity), flushCh: make(chan flushReq), opts: opts, done: make(chan struct{})}
	for i := 0; i < opts.Capacity; i++ {
		a.free <- i
	}
	a.wg.Add(1)
	go a.loop()
	return a
}

func (a *AsyncSink) WriteRecord(r Record, static []Attr) error {
	if a.closed.Load() {
		return ErrClosed
	}
	switch a.opts.DropPolicy {
	case DropBlock:
		idx := <-a.free
		a.slots[idx] = asyncItem{r: r, static: static}
		a.ready <- idx
		a.queued.Add(1)
		return nil
	case DropDebugFirst:
		if r.Level <= DebugLevel {
			select {
			case idx := <-a.free:
				a.slots[idx] = asyncItem{r: r, static: static}
				a.ready <- idx
				a.queued.Add(1)
			default:
				a.dropped.Add(1)
			}
			return nil
		}
		fallthrough
	case DropOldest:
		select {
		case idx := <-a.free:
			a.slots[idx] = asyncItem{r: r, static: static}
			a.ready <- idx
			a.queued.Add(1)
			return nil
		default:
			select {
			case idx := <-a.ready:
				a.queued.Add(-1)
				a.dropped.Add(1)
				a.slots[idx] = asyncItem{r: r, static: static}
				a.ready <- idx
				a.queued.Add(1)
			default:
				a.dropped.Add(1)
				if r.Level >= a.opts.EmergencyLevel {
					return a.sink.WriteRecord(r, static)
				}
			}
			return nil
		}
	case DropNewest:
		fallthrough
	default:
		select {
		case idx := <-a.free:
			a.slots[idx] = asyncItem{r: r, static: static}
			a.ready <- idx
			a.queued.Add(1)
			return nil
		default:
			a.dropped.Add(1)
			if r.Level >= a.opts.EmergencyLevel {
				return a.sink.WriteRecord(r, static)
			}
			return nil
		}
	}
}

func (a *AsyncSink) loop() {
	defer a.wg.Done()
	t := time.NewTicker(a.opts.FlushInterval)
	defer t.Stop()
	for {
		select {
		case idx := <-a.ready:
			a.writeIndex(idx)
			a.drainBatch(a.opts.BatchSize - 1)
		case req := <-a.flushCh:
			a.drainAll()
			req.done <- a.sink.Flush()
		case <-t.C:
			a.drainBatch(a.opts.BatchSize)
			_ = a.sink.Flush()
		case <-a.done:
			a.drainAll()
			_ = a.sink.Flush()
			return
		}
	}
}
func (a *AsyncSink) writeIndex(idx int) {
	it := a.slots[idx]
	a.slots[idx] = asyncItem{}
	a.queued.Add(-1)
	_ = a.sink.WriteRecord(it.r, it.static)
	a.free <- idx
}
func (a *AsyncSink) drainBatch(n int) {
	for ; n > 0; n-- {
		select {
		case idx := <-a.ready:
			a.writeIndex(idx)
		default:
			return
		}
	}
}
func (a *AsyncSink) drainAll() {
	for {
		select {
		case idx := <-a.ready:
			a.writeIndex(idx)
		default:
			return
		}
	}
}
func (a *AsyncSink) Flush() error {
	if a.closed.Load() {
		return a.sink.Flush()
	}
	done := make(chan error, 1)
	a.flushCh <- flushReq{done: done}
	return <-done
}
func (a *AsyncSink) Close() error {
	if a.closed.Swap(true) {
		return nil
	}
	close(a.done)
	a.wg.Wait()
	return a.sink.Close()
}
func (a *AsyncSink) Shutdown(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- a.Close() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (a *AsyncSink) Stats() SinkStats {
	st := a.sink.Stats()
	st.Dropped += a.dropped.Load()
	st.QueueDepth = a.queued.Load()
	return st
}
func (a *AsyncSink) Dropped() uint64   { return a.dropped.Load() }
func (a *AsyncSink) QueueDepth() int64 { return a.queued.Load() }
