package zlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SecureAPICredential struct {
	ID          string
	Secret      string
	Permissions []string
}

type SecureAuditHTTPOptions struct {
	Store               *SecureAuditStore
	ForensicSigner      CheckpointSigner
	LegalHolds          *LegalHoldLedger
	Credentials         []SecureAPICredential
	RequireTLS          bool
	AllowedCIDRs        []string
	MaxBodyBytes        int64
	RequestsPerMinute   int
	AuditAdministrative bool
}

type securePrincipal struct {
	id          string
	permissions map[string]struct{}
}
type rateWindow struct {
	start time.Time
	count int
}

type SecureAuditHandler struct {
	opts        SecureAuditHTTPOptions
	credentials map[string]securePrincipal
	prefixes    []netip.Prefix
	rateMu      sync.Mutex
	rates       map[string]rateWindow
}

func NewSecureAuditHandler(opts SecureAuditHTTPOptions) (*SecureAuditHandler, error) {
	if opts.Store == nil {
		return nil, errors.New("zlog: secure HTTP store is required")
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 4 << 20
	}
	if opts.RequestsPerMinute <= 0 {
		opts.RequestsPerMinute = 600
	}
	h := &SecureAuditHandler{opts: opts, credentials: make(map[string]securePrincipal), rates: make(map[string]rateWindow)}
	for _, c := range opts.Credentials {
		if c.ID == "" || len(c.Secret) < 24 {
			return nil, fmt.Errorf("zlog: credential %q must have an id and secret of at least 24 characters", c.ID)
		}
		sum := sha256.Sum256([]byte(c.Secret))
		key := hex.EncodeToString(sum[:])
		if _, exists := h.credentials[key]; exists {
			return nil, errors.New("zlog: duplicate API credential")
		}
		p := securePrincipal{id: c.ID, permissions: make(map[string]struct{})}
		for _, perm := range c.Permissions {
			p.permissions[perm] = struct{}{}
		}
		h.credentials[key] = p
	}
	for _, raw := range opts.AllowedCIDRs {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("zlog: invalid allowed CIDR %q: %w", raw, err)
		}
		h.prefixes = append(h.prefixes, p)
	}
	return h, nil
}

func (h *SecureAuditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecureHeaders(w)
	if h.opts.RequireTLS && r.TLS == nil {
		writeAPIError(w, http.StatusUpgradeRequired, "tls_required", "TLS is required")
		return
	}
	ip, ok := remoteIP(r.RemoteAddr)
	if !ok || !h.allowedIP(ip) {
		writeAPIError(w, http.StatusForbidden, "source_denied", "source address is not allowed")
		return
	}
	principal, ok := h.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="zlog"`)
		writeAPIError(w, http.StatusUnauthorized, "unauthorized", "valid bearer credential required")
		return
	}
	if !h.allowRate(principal.id + "|" + ip.String()) {
		w.Header().Set("Retry-After", "60")
		writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "request rate exceeded")
		return
	}
	start := time.Now()
	status := http.StatusOK
	action := ""
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/audit":
		action = "audit.append"
		status = h.handleAppend(w, r, principal)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/records/"):
		action = "audit.read"
		status = h.handleGet(w, r, principal)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/proofs/"):
		action = "audit.proof"
		status = h.handleProof(w, r, principal)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/checkpoints/latest":
		action = "audit.checkpoint"
		status = h.handleCheckpoint(w, r, principal)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/verify":
		action = "audit.verify"
		status = h.handleVerify(w, r, principal)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/stats":
		action = "audit.stats"
		status = h.handleStats(w, r, principal)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/query":
		action = "audit.query"
		status = h.handleQuery(w, r, principal)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/forensic/export":
		action = "audit.export"
		status = h.handleExport(w, r, principal)
	case r.Method == http.MethodGet && r.URL.Path == "/v1/legal-holds":
		action = "legal_hold.list"
		status = h.handleHolds(w, r, principal)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/legal-holds":
		action = "legal_hold.place"
		status = h.handlePlaceHold(w, r, principal)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/legal-holds/") && strings.HasSuffix(r.URL.Path, "/release"):
		action = "legal_hold.release"
		status = h.handleReleaseHold(w, r, principal)
	default:
		status = http.StatusNotFound
		writeAPIError(w, status, "not_found", "endpoint not found")
	}
	if h.opts.AuditAdministrative && action != "" && action != "audit.append" {
		outcome := "success"
		if status >= 400 {
			outcome = "failure"
		}
		_, _ = h.opts.Store.Append(context.Background(), AuditRecord{Name: "zlog.admin.request", Kind: "administrative", Action: action, Outcome: outcome, ActorID: principal.id, SourceIP: ip.String(), RequestID: r.Header.Get("X-Request-ID"), Attributes: map[string]any{"method": r.Method, "path": r.URL.Path, "status": status, "duration_ns": time.Since(start).Nanoseconds()}})
	}
}

func (h *SecureAuditHandler) handleAppend(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if !p.can("audit:write") {
		writeAPIError(w, 403, "forbidden", "audit:write permission required")
		return 403
	}
	var rec AuditRecord
	if err := decodeBoundedJSON(w, r, &rec, h.opts.MaxBodyBytes); err != nil {
		writeAPIError(w, 400, "invalid_record", err.Error())
		return 400
	}
	receipt, err := h.opts.Store.Append(r.Context(), rec)
	if err != nil {
		writeAPIError(w, 422, "append_failed", err.Error())
		return 422
	}
	writeSecureJSON(w, 201, receipt)
	return 201
}
func (h *SecureAuditHandler) handleGet(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if !p.can("audit:read") {
		writeAPIError(w, 403, "forbidden", "audit:read permission required")
		return 403
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/records/")
	if id == "" || strings.Contains(id, "/") {
		writeAPIError(w, 400, "invalid_id", "invalid record id")
		return 400
	}
	rec, env, err := h.opts.Store.Get(r.Context(), id)
	if errors.Is(err, ErrRecordNotFound) {
		writeAPIError(w, 404, "not_found", "record not found")
		return 404
	}
	if err != nil {
		writeAPIError(w, 500, "read_failed", err.Error())
		return 500
	}
	writeSecureJSON(w, 200, map[string]any{"record": rec, "envelope": env})
	return 200
}
func (h *SecureAuditHandler) handleProof(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if !p.can("audit:verify") {
		writeAPIError(w, 403, "forbidden", "audit:verify permission required")
		return 403
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/proofs/")
	proof, err := h.opts.Store.InclusionProof(r.Context(), id)
	if errors.Is(err, ErrRecordNotFound) {
		writeAPIError(w, 404, "not_found", "record not found")
		return 404
	}
	if err != nil {
		writeAPIError(w, 500, "proof_failed", err.Error())
		return 500
	}
	writeSecureJSON(w, 200, proof)
	return 200
}
func (h *SecureAuditHandler) handleCheckpoint(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if !p.can("audit:verify") {
		writeAPIError(w, 403, "forbidden", "audit:verify permission required")
		return 403
	}
	cp, err := h.opts.Store.LatestCheckpoint(r.Context())
	if err != nil {
		writeAPIError(w, 500, "checkpoint_failed", err.Error())
		return 500
	}
	writeSecureJSON(w, 200, cp)
	return 200
}
func (h *SecureAuditHandler) handleVerify(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if !p.can("audit:verify") {
		writeAPIError(w, 403, "forbidden", "audit:verify permission required")
		return 403
	}
	rep, err := h.opts.Store.Verify(r.Context(), VerifyOptions{DecryptContent: true, Strict: true})
	if err != nil {
		writeAPIError(w, 500, "verify_failed", err.Error())
		return 500
	}
	status := 200
	if !rep.Valid {
		status = 409
	}
	writeSecureJSON(w, status, rep)
	return status
}
func (h *SecureAuditHandler) handleQuery(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if !p.can("audit:read") {
		writeAPIError(w, http.StatusForbidden, "forbidden", "audit:read permission required")
		return http.StatusForbidden
	}
	var q AuditQuery
	if err := decodeBoundedJSON(w, r, &q, h.opts.MaxBodyBytes); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_query", err.Error())
		return http.StatusBadRequest
	}
	result, err := h.opts.Store.Query(r.Context(), q)
	if err != nil {
		writeAPIError(w, http.StatusUnprocessableEntity, "query_failed", err.Error())
		return http.StatusUnprocessableEntity
	}
	writeSecureJSON(w, http.StatusOK, result)
	return http.StatusOK
}

func (h *SecureAuditHandler) handleStats(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if !p.can("audit:read") {
		writeAPIError(w, 403, "forbidden", "audit:read permission required")
		return 403
	}
	writeSecureJSON(w, 200, h.opts.Store.Stats())
	return 200
}

type exportRequest struct {
	RecordIDs []string `json:"record_ids"`
	CaseID    string   `json:"case_id"`
	Reason    string   `json:"reason"`
}

func (h *SecureAuditHandler) handleExport(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if !p.can("audit:export") {
		writeAPIError(w, 403, "forbidden", "audit:export permission required")
		return 403
	}
	if h.opts.ForensicSigner == nil {
		writeAPIError(w, 503, "export_unavailable", "forensic signer not configured")
		return 503
	}
	var req exportRequest
	if err := decodeBoundedJSON(w, r, &req, h.opts.MaxBodyBytes); err != nil {
		writeAPIError(w, 400, "invalid_request", err.Error())
		return 400
	}
	tmp, err := os.CreateTemp("", "zlog-forensic-*.tar.gz")
	if err != nil {
		writeAPIError(w, 500, "export_failed", err.Error())
		return 500
	}
	name := tmp.Name()
	defer os.Remove(name)
	_, err = ExportForensicBundle(r.Context(), h.opts.Store, tmp, ForensicExportOptions{RecordIDs: req.RecordIDs, CaseID: req.CaseID, Reason: req.Reason, ExporterID: p.id, Signer: h.opts.ForensicSigner})
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		writeAPIError(w, 422, "export_failed", err.Error())
		return 422
	}
	f, err := os.Open(name)
	if err != nil {
		writeAPIError(w, 500, "export_failed", err.Error())
		return 500
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="zlog-forensic.tar.gz"`)
	if st != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	}
	w.WriteHeader(200)
	_, _ = io.Copy(w, f)
	return 200
}
func (h *SecureAuditHandler) handleHolds(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if h.opts.LegalHolds == nil {
		writeAPIError(w, 404, "not_found", "legal holds not configured")
		return 404
	}
	if !p.can("legal_hold:read") {
		writeAPIError(w, 403, "forbidden", "legal_hold:read permission required")
		return 403
	}
	writeSecureJSON(w, 200, h.opts.LegalHolds.Active())
	return 200
}
func (h *SecureAuditHandler) handlePlaceHold(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if h.opts.LegalHolds == nil {
		writeAPIError(w, 404, "not_found", "legal holds not configured")
		return 404
	}
	if !p.can("legal_hold:write") {
		writeAPIError(w, 403, "forbidden", "legal_hold:write permission required")
		return 403
	}
	var hold ActiveLegalHold
	if err := decodeBoundedJSON(w, r, &hold, h.opts.MaxBodyBytes); err != nil {
		writeAPIError(w, 400, "invalid_hold", err.Error())
		return 400
	}
	hold.ActorID = p.id
	e, err := h.opts.LegalHolds.Place(r.Context(), hold)
	if err != nil {
		writeAPIError(w, 422, "hold_failed", err.Error())
		return 422
	}
	writeSecureJSON(w, 201, e)
	return 201
}
func (h *SecureAuditHandler) handleReleaseHold(w http.ResponseWriter, r *http.Request, p securePrincipal) int {
	if h.opts.LegalHolds == nil {
		writeAPIError(w, 404, "not_found", "legal holds not configured")
		return 404
	}
	if !p.can("legal_hold:write") {
		writeAPIError(w, 403, "forbidden", "legal_hold:write permission required")
		return 403
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/legal-holds/"), "/release")
	var req struct {
		Reason string `json:"reason"`
	}
	if err := decodeBoundedJSON(w, r, &req, h.opts.MaxBodyBytes); err != nil {
		writeAPIError(w, 400, "invalid_release", err.Error())
		return 400
	}
	e, err := h.opts.LegalHolds.Release(r.Context(), id, p.id, req.Reason)
	if err != nil {
		writeAPIError(w, 422, "release_failed", err.Error())
		return 422
	}
	writeSecureJSON(w, 200, e)
	return 200
}

func (p securePrincipal) can(permission string) bool {
	_, all := p.permissions["*"]
	_, ok := p.permissions[permission]
	return all || ok
}
func (h *SecureAuditHandler) authenticate(r *http.Request) (securePrincipal, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return securePrincipal{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
	sum := sha256.Sum256([]byte(token))
	p, ok := h.credentials[hex.EncodeToString(sum[:])]
	return p, ok
}
func (h *SecureAuditHandler) allowedIP(ip netip.Addr) bool {
	if len(h.prefixes) == 0 {
		return true
	}
	for _, p := range h.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func (h *SecureAuditHandler) allowRate(key string) bool {
	now := time.Now()
	h.rateMu.Lock()
	defer h.rateMu.Unlock()
	rw := h.rates[key]
	if rw.start.IsZero() || now.Sub(rw.start) >= time.Minute {
		rw = rateWindow{start: now}
	}
	if rw.count >= h.opts.RequestsPerMinute {
		return false
	}
	rw.count++
	h.rates[key] = rw
	if len(h.rates) > 10000 {
		for k, v := range h.rates {
			if now.Sub(v.start) > 2*time.Minute {
				delete(h.rates, k)
			}
		}
	}
	return true
}
func remoteIP(addr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return ip, err == nil
}
func decodeBoundedJSON(w http.ResponseWriter, r *http.Request, out any, max int64) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		return errors.New("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return errors.New("request contains multiple JSON values")
	} else if err != io.EOF {
		return err
	}
	return nil
}
func setSecureHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
}
func writeAPIError(w http.ResponseWriter, status int, code, msg string) {
	writeSecureJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
func writeSecureJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
