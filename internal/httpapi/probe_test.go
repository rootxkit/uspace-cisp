package httpapi

import (
	"bytes"
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbe(t *testing.T) {
	srv := httptest.NewServer(mustRouter(t, &Server{}, Options{RouteMiddleware: openRoutes()}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	if c := Probe(context.Background(), addr, "/healthz", &bytes.Buffer{}); c != 0 {
		t.Errorf("/healthz probe = %d, want 0", c)
	}
	var stderr bytes.Buffer
	if c := Probe(context.Background(), addr, "/readyz", &stderr); c != 1 || !strings.Contains(stderr.String(), "503") {
		t.Errorf("/readyz probe = %d %q, want 1 with 503", c, stderr.String())
	}
	if c := Probe(context.Background(), "no-port", "/healthz", &bytes.Buffer{}); c != 1 {
		t.Errorf("bad address probe = %d", c)
	}
	if c := Probe(context.Background(), addr, "\x7f", &bytes.Buffer{}); c != 1 {
		t.Errorf("bad path probe = %d", c)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	if c := Probe(context.Background(), closed, "/healthz", &bytes.Buffer{}); c != 1 {
		t.Errorf("closed port probe = %d", c)
	}
}
