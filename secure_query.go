package zlog

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

type AuditQuery struct {
	RecordIDs       []string          `json:"record_ids,omitempty"`
	Name            string            `json:"name,omitempty"`
	Kind            string            `json:"kind,omitempty"`
	Category        string            `json:"category,omitempty"`
	ActorID         string            `json:"actor_id,omitempty"`
	SubjectID       string            `json:"subject_id,omitempty"`
	ResourceType    string            `json:"resource_type,omitempty"`
	ResourceID      string            `json:"resource_id,omitempty"`
	Outcome         string            `json:"outcome,omitempty"`
	RequestID       string            `json:"request_id,omitempty"`
	CorrelationID   string            `json:"correlation_id,omitempty"`
	TraceID         string            `json:"trace_id,omitempty"`
	SequenceFrom    uint64            `json:"sequence_from,omitempty"`
	SequenceTo      uint64            `json:"sequence_to,omitempty"`
	TimeFrom        time.Time         `json:"time_from,omitempty"`
	TimeTo          time.Time         `json:"time_to,omitempty"`
	AttributeEquals map[string]string `json:"attribute_equals,omitempty"`
	TextContains    string            `json:"text_contains,omitempty"`
	Limit           int               `json:"limit,omitempty"`
	Descending      bool              `json:"descending,omitempty"`
}

type AuditQueryResult struct {
	Records []AuditRecord `json:"records"`
	Scanned uint64        `json:"scanned"`
	Matched uint64        `json:"matched"`
	Limited bool          `json:"limited"`
}

// Query decrypts and filters records in sequence order. It is intentionally
// bounded and authoritative; external search indexes may accelerate discovery
// but should resolve final evidence through this method.
func (s *SecureAuditStore) Query(ctx context.Context, q AuditQuery) (AuditQueryResult, error) {
	if q.Limit <= 0 {
		q.Limit = 1000
	}
	if q.Limit > 10000 {
		return AuditQueryResult{}, fmt.Errorf("zlog: query limit %d exceeds 10000", q.Limit)
	}
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return AuditQueryResult{}, ErrAuditStoreClosed
	}
	locs := make([]struct {
		id  string
		loc recordLocator
	}, 0, len(s.index))
	if len(q.RecordIDs) > 0 {
		for _, id := range uniqueSorted(q.RecordIDs) {
			if loc, ok := s.index[id]; ok {
				locs = append(locs, struct {
					id  string
					loc recordLocator
				}{id, loc})
			}
		}
	} else {
		for id, loc := range s.index {
			locs = append(locs, struct {
				id  string
				loc recordLocator
			}{id, loc})
		}
	}
	s.mu.RUnlock()
	sort.Slice(locs, func(i, j int) bool {
		if q.Descending {
			return locs[i].loc.seq > locs[j].loc.seq
		}
		return locs[i].loc.seq < locs[j].loc.seq
	})
	res := AuditQueryResult{}
	for _, item := range locs {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}
		if q.SequenceFrom > 0 && item.loc.seq < q.SequenceFrom {
			continue
		}
		if q.SequenceTo > 0 && item.loc.seq > q.SequenceTo {
			continue
		}
		res.Scanned++
		rec, _, err := s.Get(ctx, item.id)
		if err != nil {
			return res, err
		}
		if !matchesAuditQuery(rec, q) {
			continue
		}
		res.Matched++
		if len(res.Records) < q.Limit {
			res.Records = append(res.Records, rec)
		} else {
			res.Limited = true
			break
		}
	}
	return res, nil
}
func matchesAuditQuery(r AuditRecord, q AuditQuery) bool {
	if q.Name != "" && r.Name != q.Name || q.Kind != "" && r.Kind != q.Kind || q.Category != "" && r.Category != q.Category || q.ActorID != "" && r.ActorID != q.ActorID || q.SubjectID != "" && r.SubjectID != q.SubjectID || q.ResourceType != "" && r.ResourceType != q.ResourceType || q.ResourceID != "" && r.ResourceID != q.ResourceID || q.Outcome != "" && r.Outcome != q.Outcome || q.RequestID != "" && r.RequestID != q.RequestID || q.CorrelationID != "" && r.CorrelationID != q.CorrelationID || q.TraceID != "" && r.TraceID != q.TraceID {
		return false
	}
	if !q.TimeFrom.IsZero() && r.EventTime.Before(q.TimeFrom) || !q.TimeTo.IsZero() && r.EventTime.After(q.TimeTo) {
		return false
	}
	for k, want := range q.AttributeEquals {
		v, ok := r.Attributes[k]
		if !ok || fmt.Sprint(v) != want {
			return false
		}
	}
	if q.TextContains != "" {
		needle := strings.ToLower(q.TextContains)
		hay := strings.ToLower(r.Name + " " + r.Action + " " + r.Reason + " " + r.ActorID + " " + r.ResourceID + " " + fmt.Sprint(r.Attributes))
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	return true
}
