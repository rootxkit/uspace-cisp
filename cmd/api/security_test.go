package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

const (
	testIssuer = "https://authority.example.test/"
	testHost   = "uspace-cisp.example.test"
)

// authRig is a token issuer with its JWKS served on loopback and a JWKS
// cache file of the test's own.
type authRig struct {
	iss   *coreauth.Issuer
	srv   *authtest.JWKSServer
	cache string
}

func newAuthRig(t *testing.T) authRig {
	t.Helper()
	iss, err := coreauth.NewIssuer(testIssuer, authtest.Key(t, "issuer", 2048), "tok-1")
	if err != nil {
		t.Fatal(err)
	}
	return authRig{iss: iss, srv: authtest.NewJWKSServer(t, iss.JWKS()), cache: filepath.Join(t.TempDir(), "local", "jwks-cache.json")}
}

func (a authRig) env(extra ...string) []string {
	return append([]string{
		"CISP_TOKEN_ISSUER=" + testIssuer,
		"CISP_TOKEN_JWKS_URL=" + a.srv.URL(),
		"CISP_AUDIENCES=" + testHost + ",cisp",
		"CISP_ANSP_MTLS_SUBJECT=CN=ansp-01",
		"CISP_JWKS_CACHE_FILE=" + a.cache,
	}, extra...)
}

func (a authRig) token(t *testing.T, scopes ...string) string {
	t.Helper()
	tok, err := a.iss.Issue("ussp-GEO1-01", testHost, scopes, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// baseEnv is extra plus a reachable token issuer: what every api run
// needs since WP-2 (the issuer, its JWKS, the audiences, the subject).
func baseEnv(t *testing.T, extra ...string) []string {
	t.Helper()
	return newAuthRig(t).env(extra...)
}

func getWith(t *testing.T, url, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// E-02, healthy: the issuer answers; the jwks component is not degraded,
// the copy is written, GET /v1/status takes a cis.read token and refuses
// none with a 401 problem.
func TestRunJWKSHealthy(t *testing.T) {
	a := newAuthRig(t)
	r := startRun(t, a.env("CISP_HTTP_ADDR=127.0.0.1:0"))
	status := waitForLine(t, r.logs, "status")
	jwks, _ := status["jwks"].(map[string]any)
	if jwks["degraded"] != nil || jwks["jwks_cache_written"] == nil {
		t.Errorf("jwks = %v", jwks)
	}
	for _, d := range status["degraded"].([]any) {
		if strings.HasPrefix(d.(string), "jwks") && d != "jwks_ansp" {
			t.Errorf("%s degraded with the issuer up", d)
		}
	}
	if _, err := os.Stat(a.cache); err != nil {
		t.Errorf("no copy written: %v", err)
	}
	code, body := getWith(t, r.base+"/v1/status", "")
	if code != 401 || !strings.Contains(body, `"type":"https://schemas.uspace.ge/problems/unauthenticated"`) || !strings.Contains(body, `"field":"authorization"`) {
		t.Errorf("no token: %d %s", code, body)
	}
	t.Logf("GET /v1/status without a token: %d %s", code, strings.TrimSpace(body))
	if code, body := getWith(t, r.base+"/v1/status", a.token(t, "cis.read")); code != 501 {
		t.Errorf("cis.read token: %d %s", code, body)
	}
	if code, body := getWith(t, r.base+"/v1/status", a.token(t)); code != 403 || !strings.Contains(body, `"field":"scope"`) {
		t.Errorf("no scope: %d %s", code, body)
	}
	if c := r.stop(t); c != 0 {
		t.Errorf("exit %d", c)
	}
}

// E-02, degraded: the issuer is down at start, the copy on disk serves,
// the status line is at error with "jwks: stale since T", and a token
// still verifies.
func TestRunJWKSDownWithCache(t *testing.T) {
	a := newAuthRig(t)
	first := startRun(t, a.env("CISP_HTTP_ADDR=127.0.0.1:0"))
	if c := first.stop(t); c != 0 {
		t.Fatalf("first run exit %d", c)
	}
	a.srv.Down()
	r := startRun(t, a.env("CISP_HTTP_ADDR=127.0.0.1:0"))
	status := waitForLine(t, r.logs, "status")
	jwks, _ := status["jwks"].(map[string]any)
	reason, _ := jwks["degraded"].(string)
	if status["level"] != "ERROR" || !strings.HasPrefix(reason, "stale since ") || !strings.Contains(reason, testIssuer) {
		t.Errorf("status = %v", status)
	}
	t.Logf("jwks: %s", reason)
	if code, body := getWith(t, r.base+"/v1/status", a.token(t, "cis.read")); code != 501 {
		t.Errorf("a token on the cached JWKS: %d %s", code, body)
	}
	if c := r.stop(t); c != 0 {
		t.Errorf("exit %d", c)
	}
}

// The issuer is down and there is no copy: the start fails with the
// reason (fatal, says so).
func TestRunJWKSDownNoCache(t *testing.T) {
	a := newAuthRig(t)
	a.srv.Down()
	logs := &syncBuffer{}
	if c := run(context.Background(), nil, a.env("CISP_HTTP_ADDR=127.0.0.1:0"), logs, io.Discard); c != 1 {
		t.Fatalf("exit %d, want 1: %s", c, logs.String())
	}
	line := waitForLine(t, logs, "authentication refused")
	if msg, _ := line["error"].(string); !strings.Contains(msg, "holds no copy") || !strings.Contains(msg, a.cache) {
		t.Errorf("reason = %v", line)
	}
	t.Logf("start refused: %v", line["error"])
}

// The signing key: served at /.well-known/jwks.json when configured; a
// key that does not load stops the start; none leaves the endpoint at 503
// and the signing component degraded. The ANSP's JWKS, when set, is
// fetched at start (its component healthy).
func TestRunSigningKeys(t *testing.T) {
	a := newAuthRig(t)
	dir := t.TempDir()
	pemBytes, err := jws.EncodePrivateKeyPEM(authtest.Key(t, "cisp", 3072))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "signing.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	ansp := authtest.NewJWKSServer(t, a.iss.JWKS())
	r := startRun(t, a.env("CISP_HTTP_ADDR=127.0.0.1:0", "CISP_SIGNING_KEY_FILE="+keyFile, "CISP_SIGNING_KID=cisp-1", "CISP_ANSP_JWKS_URL="+ansp.URL()))
	code, body := get(t, r.base+"/.well-known/jwks.json")
	if code != 200 || !strings.Contains(body, `"kid":"cisp-1"`) {
		t.Errorf("jwks = %d %s", code, body)
	}
	status := waitForLine(t, r.logs, "status")
	for _, c := range []string{"signing", "jwks_ansp", "jwks_authority"} {
		if comp, _ := status[c].(map[string]any); comp["degraded"] != nil {
			t.Errorf("%s degraded: %v", c, comp)
		}
	}
	r.stop(t)

	r = startRun(t, a.env("CISP_HTTP_ADDR=127.0.0.1:0"))
	if code, _ := get(t, r.base+"/.well-known/jwks.json"); code != 503 {
		t.Errorf("without a key: %d", code)
	}
	status = waitForLine(t, r.logs, "status")
	for _, c := range []string{"signing", "jwks_ansp"} {
		if comp, _ := status[c].(map[string]any); comp["degraded"] == nil {
			t.Errorf("%s not degraded without its configuration: %v", c, status)
		}
	}
	r.stop(t)

	short, err := jws.EncodePrivateKeyPEM(authtest.Key(t, "short", 2048))
	if err != nil {
		t.Fatal(err)
	}
	shortFile := filepath.Join(dir, "short.pem")
	if err := os.WriteFile(shortFile, short, 0o600); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	if c := run(context.Background(), nil, a.env("CISP_HTTP_ADDR=127.0.0.1:0", "CISP_SIGNING_KEY_FILE="+shortFile, "CISP_SIGNING_KID=cisp-1"), logs, io.Discard); c != 1 ||
		!strings.Contains(logs.String(), "shorter than 3072") {
		t.Errorf("a 2048-bit signing key: exit %d %s", c, logs.String())
	}
	ansp.Down()
	logs = &syncBuffer{}
	if c := run(context.Background(), nil, a.env("CISP_HTTP_ADDR=127.0.0.1:0", "CISP_ANSP_JWKS_URL="+ansp.URL(), "CISP_JWKS_CACHE_FILE="+filepath.Join(dir, "fresh.json")), logs, io.Discard); c != 1 ||
		!strings.Contains(logs.String(), "ansp signatures") {
		t.Errorf("the ANSP's JWKS down without a copy: exit %d %s", c, logs.String())
	}
	logs = &syncBuffer{}
	if c := run(context.Background(), nil, a.env("CISP_HTTP_ADDR=127.0.0.1:0", "CISP_JWKS_CACHE_FILE="+dir), logs, io.Discard); c != 1 {
		t.Errorf("a cache path that is a directory: exit %d %s", c, logs.String())
	}
}

// The retry loop: started on the copies of the issuer's and the
// authority's JWKS, one tick with the issuer still down changes nothing,
// one tick after it is back swaps the live verifiers in and clears both
// components.
func TestSecurityRetryLoop(t *testing.T) {
	a := newAuthRig(t)
	first := startRun(t, a.env("CISP_HTTP_ADDR=127.0.0.1:0"))
	first.stop(t)
	a.srv.Down()
	cfg, err := config.LoadAPI(a.env())
	if err != nil {
		t.Fatal(err)
	}
	st := obs.NewStatus(process, nil, time.Now())
	sec, err := startSecurity(context.Background(), cfg, st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if len(sec.machine.Stale()) != 1 || len(sec.publishers[auth.PublisherAuthority].Stale()) != 1 {
		t.Fatal("not started on the copies")
	}
	ctx, cancel := context.WithCancel(context.Background())
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() { sec.retry(ctx, tick); close(done) }()
	tick <- time.Now()
	tick <- time.Now() // the first tick has been handled once the second is taken
	if len(sec.machine.Stale()) != 1 {
		t.Error("recovered while the issuer is down")
	}
	a.srv.Up()
	tick <- time.Now()
	tick <- time.Now()
	if len(sec.machine.Stale()) != 0 || len(sec.publishers[auth.PublisherAuthority].Stale()) != 0 {
		t.Errorf("still stale after the issuer came back: %v", sec.machine.Stale())
	}
	for _, c := range []string{"jwks", "jwks_authority"} {
		if r := st.Component(c).DegradedReason(); r != "" {
			t.Errorf("%s still degraded: %s", c, r)
		}
	}
	cancel()
	<-done
}
