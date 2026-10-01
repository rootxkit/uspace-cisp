package auth_test

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

type jwksRig struct {
	iss   *coreauth.Issuer
	srv   *authtest.JWKSServer
	path  string
	st    *obs.Status
	comp  *obs.Component
	clock time.Time
}

func newRig(t *testing.T) *jwksRig {
	t.Helper()
	iss := newIssuer(t, issuer, "issuer", "tok-1")
	r := &jwksRig{iss: iss, srv: authtest.NewJWKSServer(t, iss.JWKS()), path: filepath.Join(t.TempDir(), "local", "jwks-cache.json"), clock: time.Now()}
	r.st = obs.NewStatus("api", nil, r.clock)
	r.comp = r.st.Component("jwks")
	return r
}

func (r *jwksRig) cache(t *testing.T) *auth.JWKSCache {
	t.Helper()
	c, err := auth.OpenJWKSCache(r.path, auth.JWKSCacheOptions{Component: r.comp, Now: func() time.Time { return r.clock }})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (r *jwksRig) start(t *testing.T, c *auth.JWKSCache) (*auth.MachineVerifier, error) {
	t.Helper()
	return auth.NewMachineVerifier(context.Background(), auth.MachineConfig{
		Issuers:   []auth.Source{{ID: issuer, JWKSURL: r.srv.URL()}},
		Audiences: []string{host},
		Cache:     c,
		Component: r.comp,
	})
}

func (r *jwksRig) statusLine(t *testing.T) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	r.st.Log(context.Background(), slog.New(slog.NewJSONHandler(&buf, nil)), r.clock)
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	t.Logf("status line: %s", strings.TrimSpace(buf.String()))
	return m
}

func (r *jwksRig) verifies(t *testing.T, mv *auth.MachineVerifier) {
	t.Helper()
	tok, err := r.iss.Issue("ussp-GEO1-01", host, []string{auth.ScopeRead}, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mv.Verify(context.Background(), tok); err != nil {
		t.Errorf("a valid token is refused: %v", err)
	}
}

// E-02, the healthy branch: the issuer answers, the token verifies, the
// copy is written, and the status line is at info with jwks healthy.
func TestMachineVerifierIssuerUp(t *testing.T) {
	r := newRig(t)
	mv, err := r.start(t, r.cache(t))
	if err != nil {
		t.Fatal(err)
	}
	r.verifies(t, mv)
	line := r.statusLine(t)
	jwks, _ := line["jwks"].(map[string]any)
	if line["level"] != "INFO" || jwks["degraded"] != nil || jwks[auth.CounterJWKSCacheWritten] == nil {
		t.Errorf("status line = %v", line)
	}
	raw, err := os.ReadFile(r.path)
	if err != nil || !strings.Contains(string(raw), r.srv.URL()) || !strings.Contains(string(raw), `"kid":"tok-1"`) {
		t.Errorf("cache file: %v %s", err, raw)
	}
	if len(mv.Stale()) != 0 || mv.Retry(context.Background()) != nil {
		t.Error("a healthy verifier reports stale sources")
	}
}

// E-02, the degraded branch: the issuer is down at start and a copy is on
// disk: the start succeeds on the copy, tokens verify, the status line is
// at error with "stale since T"; the issuer comes back, Retry swaps the
// live verifier in and the line is healthy again.
func TestMachineVerifierIssuerDownWithCache(t *testing.T) {
	r := newRig(t)
	if _, err := r.start(t, r.cache(t)); err != nil { // writes the copy
		t.Fatal(err)
	}
	fetchedAt := r.clock
	r.srv.Down()
	r.clock = r.clock.Add(time.Hour)
	mv, err := r.start(t, r.cache(t))
	if err != nil {
		t.Fatalf("start with a copy on disk: %v", err)
	}
	r.verifies(t, mv)
	line := r.statusLine(t)
	jwks, _ := line["jwks"].(map[string]any)
	want := "stale since " + fetchedAt.UTC().Format(time.RFC3339)
	if line["level"] != "ERROR" || !strings.HasPrefix(jwks["degraded"].(string), want) {
		t.Errorf("status line = %v, want jwks.degraded %q...", line, want)
	}
	if at, ok := mv.Stale()[issuer]; !ok || !at.Equal(fetchedAt.UTC().Truncate(0)) && at.Unix() != fetchedAt.Unix() {
		t.Errorf("Stale = %v", mv.Stale())
	}

	if err := mv.Retry(context.Background()); err == nil {
		t.Error("Retry with the issuer still down reports success")
	}
	if len(mv.Stale()) != 1 {
		t.Error("still down, but no longer stale")
	}
	r.srv.Up()
	if err := mv.Retry(context.Background()); err != nil {
		t.Fatalf("Retry with the issuer back: %v", err)
	}
	if len(mv.Stale()) != 0 || r.comp.DegradedReason() != "" {
		t.Errorf("after recovery: stale %v, degraded %q", mv.Stale(), r.comp.DegradedReason())
	}
	r.verifies(t, mv)
	if r.statusLine(t)["level"] != "INFO" {
		t.Error("the status line is not healthy after recovery")
	}
}

// The issuer is down at start and there is no copy: the start fails and
// says why, naming the issuer and the cache file.
func TestMachineVerifierIssuerDownNoCache(t *testing.T) {
	r := newRig(t)
	r.srv.Down()
	_, err := r.start(t, r.cache(t))
	if err == nil || !strings.Contains(err.Error(), "holds no copy") || !strings.Contains(err.Error(), issuer) || !strings.Contains(err.Error(), r.path) {
		t.Fatalf("err = %v", err)
	}
	t.Logf("start refused: %v", err)
	// Without a cache configured at all, core's refusal stands.
	if _, err := r.start(t, nil); err == nil {
		t.Error("no cache, issuer down: started")
	}
	if _, err := auth.NewMachineVerifier(context.Background(), auth.MachineConfig{Issuers: []auth.Source{{ID: issuer, JWKSURL: r.srv.URL()}}}); err == nil {
		t.Error("no audience: started")
	}
}

// A copy on disk is not used while the issuer answers, even when the
// first build failed for a passing reason.
func TestReloadingRebuildsLiveWhenTheIssuerAnswers(t *testing.T) {
	r := newRig(t)
	c := r.cache(t)
	calls := 0
	rl, err := auth.StartReloading(context.Background(), auth.ReloadConfig[int]{
		Name: "test", Sources: []auth.Source{{ID: issuer, JWKSURL: r.srv.URL()}}, Cache: c, Component: r.comp,
		Build: func(_ context.Context, src map[string]coreauth.IssuerConfig) (*int, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("transient")
			}
			if src[issuer].JWKSURL == "" {
				t.Error("rebuilt on a copy although the issuer answered")
			}
			n := calls
			return &n, nil
		},
	})
	if err != nil || *rl.Current() != 2 || len(rl.Stale()) != 0 {
		t.Fatalf("%v %v", err, rl.Stale())
	}
	if _, err := auth.StartReloading(context.Background(), auth.ReloadConfig[int]{Name: "empty"}); err == nil {
		t.Error("no sources accepted")
	}
	// A static source never touches the network or the cache.
	static, err := auth.StartReloading(context.Background(), auth.ReloadConfig[int]{
		Name: "static", Sources: []auth.Source{{ID: "p", Keys: r.iss.JWKS()}},
		Build: func(_ context.Context, src map[string]coreauth.IssuerConfig) (*int, error) {
			if src["p"].Keys == nil {
				t.Error("the static set is lost")
			}
			n := 7
			return &n, nil
		},
	})
	if err != nil || *static.Current() != 7 {
		t.Fatal(err)
	}
	// A build that fails on the copy too stops the start.
	r.srv.Down()
	if _, err := auth.StartReloading(context.Background(), auth.ReloadConfig[int]{
		Name: "failing", Sources: []auth.Source{{ID: issuer, JWKSURL: r.srv.URL()}}, Cache: c,
		Build: func(context.Context, map[string]coreauth.IssuerConfig) (*int, error) { return nil, errors.New("no") },
	}); err == nil {
		t.Error("a build failing on the copy started")
	}
}

func TestJWKSCacheFileProblems(t *testing.T) {
	dir := t.TempDir()
	if _, err := auth.OpenJWKSCache("", auth.JWKSCacheOptions{}); err == nil {
		t.Error("no path accepted")
	}
	corrupt := filepath.Join(dir, "corrupt.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.OpenJWKSCache(corrupt, auth.JWKSCacheOptions{}); err == nil || !strings.Contains(err.Error(), corrupt) {
		t.Errorf("a corrupt file: %v", err)
	}
	huge := filepath.Join(dir, "huge.json")
	if err := os.WriteFile(huge, bytes.Repeat([]byte(" "), 8<<20+10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.OpenJWKSCache(huge, auth.JWKSCacheOptions{}); err == nil {
		t.Error("a file past the bound was read")
	}
	if _, err := auth.OpenJWKSCache(dir, auth.JWKSCacheOptions{}); err == nil {
		t.Error("a directory was read as the cache file")
	}
	c, err := auth.OpenJWKSCache(filepath.Join(dir, "absent.json"), auth.JWKSCacheOptions{})
	if err != nil {
		t.Fatalf("a missing file is an empty cache: %v", err)
	}
	if _, _, ok := c.Lookup("https://nowhere/jwks"); ok {
		t.Error("an empty cache found something")
	}
}

// A write that fails is counted and leaves the previous copy; the
// response still reaches the caller.
func TestJWKSCacheWriteFailureIsCounted(t *testing.T) {
	r := newRig(t)
	blocker := filepath.Join(t.TempDir(), "local")
	c, err := auth.OpenJWKSCache(filepath.Join(blocker, "jwks-cache.json"), auth.JWKSCacheOptions{Component: r.comp})
	if err != nil {
		t.Fatal(err)
	}
	// The cache's directory becomes a regular file after it was opened:
	// every write now fails, on any OS.
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Fetch(context.Background(), r.srv.URL()); err != nil {
		t.Fatalf("the fetch failed: %v", err)
	}
	c.Commit(r.srv.URL())
	if r.comp.Counter(auth.CounterJWKSCacheWriteFailed, "").Value() != 1 {
		t.Error("the failed write is not counted")
	}
}

// A fetch only stages: nothing reaches the disk until Commit, and a URL
// with nothing staged (an error status, a closed port) writes nothing.
func TestJWKSCacheFetchStagesCommitWrites(t *testing.T) {
	r := newRig(t)
	c := r.cache(t)
	if err := c.Fetch(context.Background(), r.srv.URL()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c.Lookup(r.srv.URL()); ok {
		t.Error("a fetched set is in the cache before Commit")
	}
	if _, err := os.Stat(r.path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a file before Commit: %v", err)
	}
	c.Commit(r.srv.URL())
	if set, _, ok := c.Lookup(r.srv.URL()); !ok || set.Len() != 1 {
		t.Error("the committed set is not in the cache")
	}
	if _, _, ok := r.cache(t).Lookup(r.srv.URL()); !ok {
		t.Error("the copy did not survive a reopen")
	}

	bodies := map[string]string{"/empty": `{"keys":[]}`, "/notjwks": `{"hello":"world"}`, "/oversize": `{"keys":[` + strings.Repeat(" ", 1<<20) + `]}`}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/status" {
			http.Error(w, "no", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, bodies[req.URL.Path])
	}))
	defer srv.Close()
	for _, p := range []string{"/status", "/empty", "/notjwks", "/oversize"} {
		if err := c.Fetch(context.Background(), srv.URL+p); err == nil {
			t.Errorf("%s: Fetch reported a usable JWKS", p)
		}
	}
	c.Commit(srv.URL+"/status", "http://127.0.0.1:1/jwks")
	for _, u := range []string{srv.URL + "/status", "http://127.0.0.1:1/jwks"} {
		if _, _, ok := c.Lookup(u); ok {
			t.Errorf("%s written with nothing staged", u)
		}
	}
	if err := c.Fetch(context.Background(), "http://[::1]:0/%zz"); err == nil {
		t.Error("an unparseable URL fetched")
	}
}

// Only a set core accepted is written: a JWKS core refuses (no keys)
// fails the start and leaves no file; once the issuer serves a good set
// the start succeeds and writes it.
func TestJWKSCacheWritesOnlyWhatCoreAccepted(t *testing.T) {
	r := newRig(t)
	r.srv.SetKeys(t, authtest.PublicSet(t, nil))
	if _, err := r.start(t, r.cache(t)); err == nil {
		t.Fatal("core accepted an empty JWKS")
	}
	if _, err := os.Stat(r.path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a set core refused reached the disk: %v", err)
	}
	r.srv.SetKeys(t, r.iss.JWKS())
	if _, err := r.start(t, r.cache(t)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := r.cache(t).Lookup(r.srv.URL()); !ok {
		t.Error("the accepted set was not written")
	}
}

// The copy is keyed by the configured URL, not the redirect hop that
// answered.
func TestJWKSCacheKeysByConfiguredURL(t *testing.T) {
	r := newRig(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, r.srv.URL(), http.StatusFound)
	}))
	defer redirect.Close()
	configured := redirect.URL + "/.well-known/jwks.json"
	c := r.cache(t)
	if err := c.Fetch(context.Background(), configured); err != nil {
		t.Fatal(err)
	}
	c.Commit(configured, r.srv.URL())
	if _, _, ok := c.Lookup(configured); !ok {
		t.Error("not keyed by the configured URL")
	}
	if _, _, ok := c.Lookup(r.srv.URL()); ok {
		t.Error("keyed by the redirect hop")
	}
}

// A background refresh core accepted reaches the disk at the next Sync,
// not before; a Sync with no new refresh writes nothing.
func TestMachineVerifierSyncWritesAcceptedRefresh(t *testing.T) {
	r := newRig(t)
	mv, err := auth.NewMachineVerifier(context.Background(), auth.MachineConfig{
		Issuers: []auth.Source{{ID: issuer, JWKSURL: r.srv.URL()}}, Audiences: []string{host},
		Cache: r.cache(t), Component: r.comp, MinRefreshInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	written := func() uint64 { return r.comp.Counter(auth.CounterJWKSCacheWritten, "").Value() }
	before := written()
	mv.Sync()
	if written() != before {
		t.Error("a Sync without a refresh wrote")
	}
	next := newIssuer(t, issuer, "issuer-next", "tok-2")
	both := authtest.PublicSet(t, map[string]*rsa.PrivateKey{"tok-1": authtest.Key(t, "issuer", 2048), "tok-2": authtest.Key(t, "issuer-next", 2048)})
	r.srv.SetKeys(t, both)
	time.Sleep(5 * time.Millisecond) // past the 1 ms rate limit
	tok, err := next.Issue("ussp-GEO1-01", host, nil, time.Minute, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mv.Verify(context.Background(), tok); err != nil {
		t.Fatalf("the rotated key: %v", err)
	}
	if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "tok-2") {
		t.Error("the refresh reached the disk before Sync")
	}
	mv.Sync()
	if raw, _ := os.ReadFile(r.path); !strings.Contains(string(raw), "tok-2") || written() != before+1 {
		t.Errorf("after Sync: written %d, file %s", written()-before, raw)
	}
}

// A cache file another user could have written is refused: the mode and
// owner rule everywhere, and the real file on systems that have modes.
func TestJWKSCacheFileOwnership(t *testing.T) {
	me := 1000
	for _, c := range []struct {
		name  string
		mode  fs.FileMode
		owner int
		ok    bool
	}{
		{"0600, mine", 0o600, me, true},
		{"0644, mine", 0o644, me, true},
		{"group-writable", 0o620, me, false},
		{"world-writable", 0o606, me, false},
		{"another user's", 0o600, 0, false},
		{"a directory", fs.ModeDir | 0o700, me, false},
	} {
		if err := auth.CacheFileProblem(c.mode, c.owner, me); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("the mode and owner of the real file are not checked on Windows (ACLs, no mode bits); the rule above is")
	}
	r := newRig(t)
	if _, err := r.start(t, r.cache(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(r.path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.OpenJWKSCache(r.path, auth.JWKSCacheOptions{}); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a world-writable cache: %v", err)
	}
	if err := os.Chmod(r.path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.OpenJWKSCache(r.path, auth.JWKSCacheOptions{}); err != nil {
		t.Errorf("the 0600 twin: %v", err)
	}
}

// The client given to core refuses a redirect to plain http on another
// host, beside one to https or to loopback http.
func TestJWKSCacheRefusesInsecureRedirect(t *testing.T) {
	r := newRig(t)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, req.URL.Query().Get("to"), http.StatusFound)
	}))
	defer redirect.Close()
	c := r.cache(t)
	if err := c.Fetch(context.Background(), redirect.URL+"/?to="+r.srv.URL()); err != nil {
		t.Errorf("a redirect to loopback http: %v", err)
	}
	err := c.Fetch(context.Background(), redirect.URL+"/?to=http://jwks.example.test/jwks")
	if err == nil || !strings.Contains(err.Error(), "https only") {
		t.Errorf("a redirect to plain http elsewhere: %v", err)
	}
	if err := c.Fetch(context.Background(), redirect.URL+"/?to=ftp://jwks.example.test/"); err == nil {
		t.Error("a redirect to ftp")
	}
	loop := httptest.NewServer(nil)
	loop.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, loop.URL+"/again", http.StatusFound)
	})
	defer loop.Close()
	if err := c.Fetch(context.Background(), loop.URL); err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("a redirect loop: %v", err)
	}
}
