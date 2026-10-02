package httpapi

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// bodyServer is the middleware chain on a real server, with a handler
// deadline of 40 ms and a body route that answers with the length read.
func bodyServer(t *testing.T, minRate int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /body", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		if r.Context().Err() != nil {
			return // the handler deadline had already passed
		}
		w.Header().Set("X-Length", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(Wrap(mux, Options{
		HandlerTimeout: 40 * time.Millisecond, MaxBodyBytes: 1 << 20, BodyReadMinBytesPerS: minRate,
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A slow upload that takes longer than the handler deadline but stays
// within its own read deadline is served: the handler deadline starts
// after the body has arrived.
func TestSlowBodyIsNotCutByTheHandlerDeadline(t *testing.T) {
	srv := bodyServer(t, 1024) // 1 MiB at 1 KiB/s: a 1024 s read deadline
	pr, pw := io.Pipe()
	go func() {
		for range 3 {
			_, _ = pw.Write([]byte(strings.Repeat("a", 100)))
			time.Sleep(25 * time.Millisecond) // 75 ms in all, past the 40 ms handler deadline
		}
		_ = pw.Close()
	}()
	resp, err := http.Post(srv.URL+"/body", "application/octet-stream", pr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get("X-Length") != "300" {
		t.Fatalf("slow upload = %d, length %q", resp.StatusCode, resp.Header.Get("X-Length"))
	}
}

// A stalled upload is cut by its read deadline with 408 body_timeout
// (E-01 twin of the above): 1 MiB at 1 GiB/s is 1 ms, so the floor, the
// 40 ms handler timeout, applies.
func TestStalledBodyIsCutByItsReadDeadline(t *testing.T) {
	srv := bodyServer(t, 1<<30)
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("POST /body HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\nContent-Length: 100\r\n\r\n0123456789"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusRequestTimeout || !strings.Contains(string(body), SlugBodyTimeout) || !strings.Contains(string(body), "10 bytes arrived") {
		t.Fatalf("stalled upload = %d %s", resp.StatusCode, body)
	}
}

// The read deadline is the route's cap at the minimum rate, never less
// than the floor.
func TestBodyReadFor(t *testing.T) {
	p := bodyReadPolicy{defaultCap: 64 << 10, caps: map[string]int64{PublicationRoute: 32 << 20}, minBytesPerS: 64 << 10, floor: 10 * time.Second}
	if got := p.readFor(PublicationRoute); got != 512*time.Second {
		t.Errorf("32 MiB at 64 KiB/s = %s", got)
	}
	if got := p.readFor("GET /v1/status"); got != 10*time.Second {
		t.Errorf("64 KiB at 64 KiB/s = %s, want the 10 s floor", got)
	}
}

// A body that cannot be read is a 400 problem.
func TestUnreadableBodyIs400(t *testing.T) {
	h := Wrap(http.NewServeMux(), Options{})
	req := httptest.NewRequest(http.MethodPost, "/x", errReader{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if p := decodeProblem(t, rec); rec.Code != http.StatusBadRequest || !hasProblem(p, "body", "could not be read") {
		t.Errorf("= %d %s", rec.Code, rec.Body.String())
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
