package zlog

import "sync/atomic"

type Sampler interface{ Allow(Level, string) bool }
type EveryNSampler struct {
	N        uint64
	c        atomic.Uint64
	MinLevel Level
}

func (s *EveryNSampler) Allow(l Level, _ string) bool {
	if s == nil || s.N == 0 || l >= s.MinLevel {
		return true
	}
	return s.c.Add(1)%s.N == 0
}
