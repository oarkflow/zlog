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
	DisableStats   bool
}

type asyncItem struct {
	r        Record
	static   []Attr
	fast     bool
	level    Level
	msg      string
	time     time.Time
	timeText string
}

type asyncCell struct {
	seq  atomic.Uint64
	item asyncItem
}

type flushReq struct{ done chan error }

type AsyncSink struct {
	sink     Sink
	slots    []asyncItem
	free     chan int
	ready    chan int
	flushCh  chan flushReq
	opts     AsyncOptions
	done     chan struct{}
	closed   atomic.Bool
	dropped  atomic.Uint64
	queued   atomic.Int64
	wg       sync.WaitGroup
	ringMode bool
	ring     []asyncCell
	ringMask uint64
	writePos atomic.Uint64
	readPos  atomic.Uint64
	ringWake chan struct{}
	statsOn  bool
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
	a.statsOn = !opts.DisableStats
	if opts.DropPolicy == DropNewest && opts.Capacity&(opts.Capacity-1) == 0 {
		a.ringMode = true
		a.ring = make([]asyncCell, opts.Capacity)
		a.ringMask = uint64(opts.Capacity - 1)
		a.ringWake = make(chan struct{}, 1)
		for i := range a.ring {
			a.ring[i].seq.Store(uint64(i))
		}
	}
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
	if a.ringMode {
		return a.writeRing(r, static)
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

func (a *AsyncSink) writeRing(r Record, static []Attr) error {
	return a.writeRingItem(asyncItem{r: r, static: static})
}

func (a *AsyncSink) WriteFast(level Level, msg string, now time.Time, timeText string, static []Attr) error {
	return a.writeRingItem(asyncItem{fast: true, level: level, msg: msg, time: now, timeText: timeText, static: static})
}

func (a *AsyncSink) writeRingItem(item asyncItem) error {
	for pos := a.writePos.Load(); ; pos = a.writePos.Load() {
		cell := &a.ring[pos&a.ringMask]
		seq := cell.seq.Load()
		dif := int64(seq - pos)
		if dif == 0 {
			wasEmpty := a.readPos.Load() == pos
			if !a.writePos.CompareAndSwap(pos, pos+1) {
				continue
			}
			if item.fast {
				cell.item.fast = true
				cell.item.level = item.level
				cell.item.msg = item.msg
				cell.item.time = item.time
				cell.item.timeText = item.timeText
				cell.item.static = item.static
			} else {
				cell.item = item
			}
			cell.seq.Store(pos + 1)
			if a.statsOn {
				a.queued.Add(1)
			}
			if wasEmpty {
				select {
				case a.ringWake <- struct{}{}:
				default:
				}
			}
			return nil
		}
		if dif < 0 {
			if a.statsOn {
				a.dropped.Add(1)
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
		case <-a.ringWake:
			a.drainRing(a.opts.BatchSize)
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
	if a.ringMode {
		for a.drainRing(a.opts.BatchSize) > 0 {
		}
		return
	}
	for {
		select {
		case idx := <-a.ready:
			a.writeIndex(idx)
		default:
			return
		}
	}
}

func (a *AsyncSink) drainRing(n int) int {
	count := 0
	for count < n {
		pos := a.readPos.Load()
		cell := &a.ring[pos&a.ringMask]
		if cell.seq.Load() != pos+1 {
			return count
		}
		if !a.readPos.CompareAndSwap(pos, pos+1) {
			continue
		}
		it := cell.item
		cell.item = asyncItem{}
		cell.seq.Store(pos + uint64(len(a.ring)))
		if a.statsOn {
			a.queued.Add(-1)
		}
		if it.fast {
			_ = a.sink.WriteRecord(Record{Time: it.time, TimeText: it.timeText, Level: it.level, Message: it.msg}, it.static)
		} else {
			_ = a.sink.WriteRecord(it.r, it.static)
		}
		count++
	}
	return count
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
