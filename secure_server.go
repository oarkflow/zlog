package zlog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"time"
)

type SecureHTTPServerOptions struct {
	Addr           string
	Handler        http.Handler
	CertFile       string
	KeyFile        string
	ClientCAFile   string
	RequireMTLS    bool
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	IdleTimeout    time.Duration
	MaxHeaderBytes int
}

func NewSecureHTTPServer(opts SecureHTTPServerOptions) (*http.Server, error) {
	if opts.Handler == nil || opts.CertFile == "" || opts.KeyFile == "" {
		return nil, errors.New("zlog: secure HTTP handler, certificate and key are required")
	}
	if opts.Addr == "" {
		opts.Addr = ":8443"
	}
	if opts.ReadTimeout == 0 {
		opts.ReadTimeout = 15 * time.Second
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = 60 * time.Second
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = 60 * time.Second
	}
	if opts.MaxHeaderBytes == 0 {
		opts.MaxHeaderBytes = 1 << 20
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	if opts.RequireMTLS {
		if opts.ClientCAFile == "" {
			return nil, errors.New("zlog: client CA file is required for mTLS")
		}
		pemData, err := os.ReadFile(opts.ClientCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, errors.New("zlog: client CA file has no valid certificates")
		}
		tlsConfig.ClientCAs = pool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return &http.Server{Addr: opts.Addr, Handler: opts.Handler, TLSConfig: tlsConfig, ReadTimeout: opts.ReadTimeout, WriteTimeout: opts.WriteTimeout, IdleTimeout: opts.IdleTimeout, MaxHeaderBytes: opts.MaxHeaderBytes}, nil
}
func ListenAndServeSecureAudit(opts SecureHTTPServerOptions) error {
	srv, err := NewSecureHTTPServer(opts)
	if err != nil {
		return err
	}
	return srv.ListenAndServeTLS(opts.CertFile, opts.KeyFile)
}
func ShutdownSecureAuditServer(ctx context.Context, srv *http.Server) error {
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}
