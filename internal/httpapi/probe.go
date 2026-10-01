package httpapi

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Probe is the container health check of a distroless image (no shell,
// no curl): it GETs path on the local listener of addr and returns 0 on
// 200 and 1 otherwise, naming the failure on stderr.
func Probe(ctx context.Context, addr, path string, stderr io.Writer) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "probe:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+port+path, http.NoBody)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "probe:", err)
		return 1
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "probe:", err)
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintln(stderr, "probe:", path, resp.Status)
		return 1
	}
	return 0
}
