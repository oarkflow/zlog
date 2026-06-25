package zlog

import (
	"runtime"
	"sync/atomic"
	"time"
)

const maxInlineAttrs = 4

type Caller struct {
	PC   uintptr
	File string
	Line int
	Func string
}

type Record struct {
	Time      time.Time
	Level     Level
	Message   string
	Logger    string
	Attrs     [maxInlineAttrs]Attr
	AttrCount int
	Extra     []Attr
	Caller    Caller
	Sequence  uint64
	Redacted  bool
}

func (r *Record) SetAttrs(attrs []Attr) {
	if len(attrs) <= maxInlineAttrs {
		r.AttrCount = copy(r.Attrs[:], attrs)
		r.Extra = nil
		return
	}
	r.AttrCount = maxInlineAttrs
	copy(r.Attrs[:], attrs[:maxInlineAttrs])
	r.Extra = append([]Attr(nil), attrs[maxInlineAttrs:]...)
}

func (r *Record) AttrLen() int { return r.AttrCount + len(r.Extra) }

func (r *Record) AddAttr(a Attr) {
	if a.Kind == KindInvalid || a.Key == "" {
		return
	}
	if r.AttrCount < maxInlineAttrs {
		r.Attrs[r.AttrCount] = a
		r.AttrCount++
		return
	}
	r.Extra = append(r.Extra, a)
}

func (r *Record) AttrAt(i int) Attr {
	if i < r.AttrCount {
		return r.Attrs[i]
	}
	return r.Extra[i-r.AttrCount]
}

func (r *Record) Redact(redactor Redactor) {
	if r.Redacted || !redactor.Enabled {
		return
	}
	redactor = redactor.normalized()
	for i := 0; i < r.AttrCount; i++ {
		redactAttrPrepared(&r.Attrs[i], redactor)
	}
	for i := range r.Extra {
		redactAttrPrepared(&r.Extra[i], redactor)
	}
	r.Redacted = true
}

var globalSeq atomic.Uint64

func nextSeq() uint64 { return globalSeq.Add(1) }

func captureCaller(skip int) Caller {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return Caller{}
	}
	fn := runtime.FuncForPC(pc)
	name := ""
	if fn != nil {
		name = fn.Name()
	}
	return Caller{PC: pc, File: file, Line: line, Func: name}
}
