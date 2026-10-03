//go:build e2e

// Package e2e drives the CISP end to end (docs/PLAN.md section 10.5,
// docs/WORKPACKAGES/WP-6.md): PostgreSQL + TimescaleDB, NATS and the
// reference subscriber in compose (compose.yml), and the api, deliver
// and cispctl built from this checkout and run as processes with their
// CISP_* environment. The authority-role client publishes with
// `cispctl sign`; the ANSP-role client signs with its own key; tokens
// come from an issuer whose JWKS the test serves on 127.0.0.1.
//
//	go test -tags e2e -count=1 -v ./test/e2e/
//
// Docker with compose is required; without it the run fails (a skipped
// e2e proves nothing, E-04).
package e2e

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
)

// syncBuffer is a process's output, read while it runs.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// proc is one CISP process.
type proc struct {
	name string
	cmd  *exec.Cmd
	logs *syncBuffer
	done chan error
}

type stack struct {
	dir                                    string
	envFile                                string
	apiPort, subPort                       int
	apiURL, subURL, publicBase             string
	iss                                    *coreauth.Issuer
	authorityKeyFile, anspKeyFile, cispctl string
	api, deliver                           *proc
	jwks                                   *httptest.Server
}

var (
	once    sync.Once
	theOne  *stack
	setupOK bool
)

func TestMain(m *testing.M) {
	code := m.Run()
	if theOne != nil {
		theOne.teardown()
	}
	os.Exit(code)
}

// env is the running stack, started by the first test that asks.
func env(t *testing.T) *stack {
	t.Helper()
	once.Do(func() {
		s := &stack{}
		theOne = s
		s.start(t)
		setupOK = !t.Failed()
	})
	if !setupOK {
		t.Fatal("the e2e stack did not start (see the first test's log)")
	}
	return theOne
}

func (s *stack) compose(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"compose", "-p", project, "-f", "compose.yml", "--env-file", s.envFile}, args...)
	cmd := exec.Command("docker", full...)
	cmd.Env = composeEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func (s *stack) start(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is not on PATH: the e2e stack needs docker compose")
	}
	dir, err := os.MkdirTemp("", "cisp-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	s.dir = dir
	pgPort, natsPort := freePort(t), freePort(t)
	s.apiPort, s.subPort = freePort(t), freePort(t)
	s.apiURL = fmt.Sprintf("http://127.0.0.1:%d", s.apiPort)
	s.subURL = fmt.Sprintf("http://127.0.0.1:%d", s.subPort)
	s.publicBase = fmt.Sprintf("http://host.docker.internal:%d", s.apiPort)

	// Keys: the token issuer, the authority's and the ANSP's publication
	// keys, and the CISP's signing key.
	tokKey := authtest.Key(t, "e2e-issuer", 2048)
	authKey := authtest.Key(t, "e2e-authority", 3072)
	anspKey := authtest.Key(t, "e2e-ansp", 3072)
	s.iss, err = coreauth.NewIssuer(tokenIssuer, tokKey, tokenKID)
	if err != nil {
		t.Fatal(err)
	}
	s.authorityKeyFile = filepath.Join(dir, "authority.pem")
	s.anspKeyFile = filepath.Join(dir, "ansp.pem")
	cispKeyFile := filepath.Join(dir, "cisp.pem")
	writePEM(t, s.authorityKeyFile, authKey)
	writePEM(t, s.anspKeyFile, anspKey)
	writePEM(t, cispKeyFile, authtest.Key(t, "e2e-cisp", 3072))
	authoritySet, _ := json.Marshal(authtest.PublicSet(t, map[string]*rsa.PrivateKey{tokenKID: tokKey, authorityKID: authKey}))
	anspSet, _ := json.Marshal(authtest.PublicSet(t, map[string]*rsa.PrivateKey{anspKID: anspKey}))
	s.jwks = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/ansp") {
			_, _ = w.Write(anspSet)
			return
		}
		_, _ = w.Write(authoritySet)
	}))

	pw := map[string]string{"POSTGRES_PASSWORD": secret(), "PG_CISP_API_PASSWORD": secret(), "PG_CISP_DELIVER_PASSWORD": secret()}
	subToken := s.token(t, labClient, "host.docker.internal", "cis.read")
	s.envFile = filepath.Join(dir, "e2e.env")
	envLines := []string{
		"POSTGRES_PASSWORD=" + pw["POSTGRES_PASSWORD"], "PG_CISP_API_PASSWORD=" + pw["PG_CISP_API_PASSWORD"],
		"PG_CISP_DELIVER_PASSWORD=" + pw["PG_CISP_DELIVER_PASSWORD"],
		fmt.Sprintf("E2E_PG_PORT=%d", pgPort), fmt.Sprintf("E2E_NATS_PORT=%d", natsPort), fmt.Sprintf("E2E_SUBSCRIBER_PORT=%d", s.subPort),
		"E2E_CISP_JWKS_URL=" + s.publicBase + "/.well-known/jwks.json", "E2E_CISP_ISSUER_URL=" + cispIssuer,
		"E2E_CISP_PUBLIC_BASE_URL=" + s.publicBase, "E2E_SUBSCRIBER_TOKEN=" + subToken,
	}
	if err := os.WriteFile(s.envFile, []byte(strings.Join(envLines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	s.compose(t, "up", "-d", "--build", "--wait", "postgres", "nats", "subscriber")
	t.Logf("compose up in %s", time.Since(start).Round(time.Second))

	// The processes, built from this checkout.
	for _, c := range []string{"api", "deliver", "cispctl"} {
		bin := filepath.Join(dir, c)
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		out, err := exec.Command("go", "build", "-o", bin, "../../cmd/"+c).CombinedOutput()
		if err != nil {
			t.Fatalf("go build %s: %v\n%s", c, err, out)
		}
		if c == "cispctl" {
			s.cispctl = bin
		}
	}
	db := func(role, pass, name string) string {
		return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%d/%s?sslmode=disable", role, pass, pgPort, name)
	}
	natsURL := fmt.Sprintf("nats://127.0.0.1:%d", natsPort)
	migrateEnv := []string{
		"CISP_DATABASE_URL=" + db("cisp_api", pw["PG_CISP_API_PASSWORD"], "cisp"),
		"CISP_TIMESERIES_URL=" + db("cisp_deliver", pw["PG_CISP_DELIVER_PASSWORD"], "cisp_ts"),
	}
	// The image's healthcheck can pass while its init scripts still run
	// (the roles do not exist yet): migrate until the roles answer.
	for _, tree := range []string{"relational", "timeseries"} {
		var out []byte
		var err error
		for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(time.Second) {
			cmd := exec.Command(s.cispctl, "migrate", tree)
			cmd.Env = cleanEnv(migrateEnv...)
			if out, err = cmd.CombinedOutput(); err == nil || time.Now().After(deadline) {
				break
			}
		}
		if err != nil {
			t.Fatalf("cispctl migrate %s: %v\n%s", tree, err, out)
		}
	}
	listen := "127.0.0.1"
	if runtime.GOOS == "linux" {
		listen = "0.0.0.0" // the subscriber reaches the host through the bridge
	}
	common := []string{
		"CISP_SIGNING_KEY_FILE=" + cispKeyFile, "CISP_SIGNING_KID=" + cispKID,
		"CISP_ISSUER_URL=" + cispIssuer, "CISP_PUBLIC_BASE_URL=" + s.publicBase,
		"CISP_NATS_URL=" + natsURL, "CISP_ALLOW_PRIVATE_CALLBACKS=true", "CISP_ALLOW_INSECURE_CALLBACKS=true",
		"CISP_STATUS_INTERVAL_S=1",
	}
	s.api = s.run(t, "api", append([]string{
		fmt.Sprintf("CISP_HTTP_ADDR=%s:%d", listen, s.apiPort),
		"CISP_DATABASE_URL=" + db("cisp_api", pw["PG_CISP_API_PASSWORD"], "cisp"),
		"CISP_TIMESERIES_URL=" + db("cisp_api", pw["PG_CISP_API_PASSWORD"], "cisp_ts"),
		"CISP_TOKEN_ISSUER=" + tokenIssuer, "CISP_TOKEN_JWKS_URL=" + s.jwks.URL + "/authority/jwks.json",
		"CISP_ANSP_JWKS_URL=" + s.jwks.URL + "/ansp/jwks.json",
		"CISP_AUDIENCES=localhost,127.0.0.1,host.docker.internal", "CISP_MTLS_MODE=off",
		"CISP_JWKS_CACHE_FILE=" + filepath.Join(dir, "jwks-cache.json"),
	}, common...), "listening")
	s.deliver = s.run(t, "deliver", append([]string{
		"CISP_DELIVER_HTTP_ADDR=127.0.0.1:0",
		"CISP_DATABASE_URL=" + db("cisp_deliver", pw["PG_CISP_DELIVER_PASSWORD"], "cisp"),
		"CISP_TIMESERIES_URL=" + db("cisp_deliver", pw["PG_CISP_DELIVER_PASSWORD"], "cisp_ts"),
	}, common...), "delivering")
	t.Logf("stack up in %s: api %s, subscriber %s", time.Since(start).Round(time.Second), s.apiURL, s.subURL)
}

// cleanEnv is the test's environment without CISP_* plus extra.
func cleanEnv(extra ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CISP_") {
			out = append(out, kv)
		}
	}
	return append(out, extra...)
}

func (s *stack) run(t *testing.T, name string, environ []string, ready string) *proc {
	t.Helper()
	bin := filepath.Join(s.dir, name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	p := &proc{name: name, cmd: exec.Command(bin), logs: &syncBuffer{}, done: make(chan error, 1)}
	p.cmd.Env = cleanEnv(environ...)
	p.cmd.Stdout, p.cmd.Stderr = p.logs, p.logs
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	if _, err := p.waitLine(func(m doc) bool { return m["msg"] == ready }, 0, 30*time.Second); err != nil {
		t.Fatalf("%s: %v\n%s", name, err, p.logs.String())
	}
	return p
}

// lines are the process's JSON log lines from byte offset from.
func (p *proc) lines(from int) []doc {
	var out []doc
	all := p.logs.String()
	if from > len(all) {
		from = len(all)
	}
	for _, l := range strings.Split(all[from:], "\n") {
		var m doc
		if json.Unmarshal([]byte(l), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

// offset is where the process's output ends now.
func (p *proc) offset() int { return len(p.logs.String()) }

// waitLine waits for a line written after from that ok accepts.
func (p *proc) waitLine(ok func(doc) bool, from int, within time.Duration) (doc, error) {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, m := range p.lines(from) {
			if ok(m) {
				return m, nil
			}
		}
		select {
		case err := <-p.done:
			return nil, fmt.Errorf("%s exited: %w", p.name, err)
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("no such %s line within %s", p.name, within)
}

// stop sends SIGTERM (a kill on windows, which has none) and reports
// the exit.
func (p *proc) stop() string {
	if runtime.GOOS == "windows" {
		_ = p.cmd.Process.Kill()
	} else {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case err := <-p.done:
		if err != nil {
			return fmt.Sprintf("%s exited: %v", p.name, err)
		}
		return p.name + " exited 0"
	case <-time.After(15 * time.Second):
		_ = p.cmd.Process.Kill()
		return p.name + " did not stop within 15 s"
	}
}

func (s *stack) teardown() {
	for _, p := range []*proc{s.deliver, s.api} {
		if p != nil {
			fmt.Fprintln(os.Stderr, "e2e:", p.stop())
		}
	}
	if s.jwks != nil {
		s.jwks.Close()
	}
	if s.envFile != "" {
		cmd := exec.Command("docker", "compose", "-p", project, "-f", "compose.yml", "--env-file", s.envFile, "down", "-v", "--remove-orphans")
		cmd.Env = composeEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e: compose down: %v\n%s", err, out)
		}
	}
	_ = os.RemoveAll(s.dir)
}

func (s *stack) token(t *testing.T, sub, aud string, scopes ...string) string {
	t.Helper()
	tok, err := s.iss.Issue(sub, aud, scopes, 2*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// call is one request to the api as client (aud localhost).
func (s *stack) call(t *testing.T, method, path, token string, body []byte, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, s.apiURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// sign is the detached signature `cispctl sign` makes of body.
func (s *stack) sign(t *testing.T, keyFile, kid string, body []byte) string {
	t.Helper()
	cmd := exec.Command(s.cispctl, "sign", "--key", keyFile, "--kid", kid)
	cmd.Stdin = bytes.NewReader(body)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("cispctl sign: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// publish PUTs a dataset as the authority and returns its version.
func (s *stack) publish(t *testing.T, ds string, body []byte) int64 {
	t.Helper()
	tok := s.token(t, authorityID, "localhost", "cis.publish:zones", "cis.publish:uspace", "cis.read")
	head, _ := s.call(t, http.MethodHead, "/v1/"+ds, tok, nil, nil)
	etag := head.Header.Get("ETag")
	if etag == "" {
		etag = `"` + ds + `:0"`
	}
	resp, raw := s.call(t, http.MethodPut, "/v1/publications/"+ds, tok, body, map[string]string{
		"If-Match": etag, "X-JWS-Signature": s.sign(t, s.authorityKeyFile, authorityKID, body), "Content-Type": "application/geo+json",
	})
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT %s = %d %s", ds, resp.StatusCode, raw)
	}
	var out struct {
		Version int64 `json:"version"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.Version
}

func (s *stack) changes(t *testing.T, since int64) ([]change, int64) {
	t.Helper()
	resp, raw := s.call(t, http.MethodGet, fmt.Sprintf("/v1/changes?since=%d&limit=500", since), s.token(t, labClient, "localhost", "cis.read"), nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("changes = %d %s", resp.StatusCode, raw)
	}
	var out struct {
		Changes []change `json:"changes"`
		Next    int64    `json:"next"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.Changes, out.Next
}

func (s *stack) received(t *testing.T) []received {
	t.Helper()
	resp, err := http.Get(s.subURL + "/received")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out []received
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

var subOnce sync.Once

// subscribe registers the subscriber (lab-01) for zones, U-space
// airspace and restrictions once, and waits for its ping to verify it.
func (s *stack) subscribe(t *testing.T) {
	t.Helper()
	subOnce.Do(func() {
		tok := s.token(t, labClient, "localhost", "cis.read")
		body, _ := json.Marshal(doc{
			"callback_url": fmt.Sprintf("http://localhost:%d/v1/cis/notifications", s.subPort),
			"datasets":     []string{"zones", "uspace_airspace", "restrictions"},
		})
		resp, raw := s.call(t, http.MethodPost, "/v1/subscriptions", tok, body, nil)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("subscribe = %d %s", resp.StatusCode, raw)
		}
		var sub struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &sub)
		eventually(t, 15*time.Second, "the subscription verified", func() bool {
			_, raw := s.call(t, http.MethodGet, "/v1/subscriptions/"+sub.ID, tok, nil, nil)
			var got struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(raw, &got)
			return got.Status == "active"
		})
		t.Logf("subscription %s active", sub.ID)
	})
}
