package zlog

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"time"
)

type TCPWriter struct {
	Addr    string
	TLS     *tls.Config
	Timeout time.Duration
}

func (w TCPWriter) Write(p []byte) (int, error) {
	timeout := w.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	var c net.Conn
	var err error
	if w.TLS != nil {
		c, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", w.Addr, w.TLS)
	} else {
		c, err = net.DialTimeout("tcp", w.Addr, timeout)
	}
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	return c.Write(p)
}

type UDPWriter struct {
	Addr    string
	Timeout time.Duration
}

func (w UDPWriter) Write(p []byte) (int, error) {
	timeout := w.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	c, err := net.DialTimeout("udp", w.Addr, timeout)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	return c.Write(p)
}

type HTTPWriter struct {
	URL    string
	Client *http.Client
	Header http.Header
}

func (w HTTPWriter) Write(p []byte) (int, error) {
	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(p))
	if err != nil {
		return 0, err
	}
	for k, vs := range w.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-ndjson")
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return 0, &HTTPStatusError{Code: resp.StatusCode}
	}
	return len(p), nil
}

type HTTPStatusError struct{ Code int }

func (e *HTTPStatusError) Error() string { return "zlog http writer status " + strconv.Itoa(e.Code) }
