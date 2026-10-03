//go:build chaos

// The chaos suite (WP-13, docs/PLAN.md section 10.5): the built image in
// compose (chaos.compose.yml), faults made for real (PostgreSQL and
// NATS stopped, api and deliver killed, a subscriber down for 30
// minutes), and each case asserting the degraded observation first and
// the recovery second, printing what it saw to the step summary.
//
//	go test -tags chaos -count=1 -v -timeout 60m ./test/e2e/
//
// CHAOS_IMAGE names an image already built (CI builds it once); unset,
// the test builds uspace-cisp:chaos-local from this checkout.
// CHAOS_SUBSCRIBER_DOWN shortens the subscriber outage for a local run
// (default 30m; the value used is printed). Docker with compose is
// required; without it the run fails (a skipped suite proves nothing).
package e2e

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
)

const (
	chaosProject = "uspace-cisp-chaos"
	chaosCompose = "chaos.compose.yml"
	// The CISP's issuer as subscribers verify it.
	chaosIssuer = "https://uspace-cisp.chaos.test"
	// The compose network and the edge's fixed address in it, the one
	// proxy api-edge believes (CISP_TRUSTED_PROXY_CIDR).
	chaosSubnet  = "10.213.7.0/24"
	chaosIPRange = "10.213.7.0/25"
	chaosEdgeIP  = "10.213.7.200"
)

type chaosStack struct {
	dir, envFile, image  string
	apiURL, apiEdgeURL   string
	edgeURL, edgeEchoURL string
	subURL               map[string]string
	iss                  *coreauth.Issuer
	authKey, anspKey     *rsa.PrivateKey
	caPEM                []byte
	roots                *x509.CertPool
	client               *http.Client
	anspCert, impostor   tls.Certificate
	anspSubject          string
	imageID, composeHash string
	edgeOnce             sync.Once
	edgeOK               bool
	edgeRoots            *x509.CertPool
	subscriptions        map[string]string
	subscriptionsMu      sync.Mutex
}

var (
	chaosOnce  sync.Once
	chaosOne   *chaosStack
	chaosSetUp bool
)

func TestMain(m *testing.M) {
	code := m.Run()
	if chaosOne != nil {
		chaosOne.teardown()
	}
	os.Exit(code)
}

// chaosEnv is the running stack, started by the first test that asks.
func chaosEnv(t *testing.T) *chaosStack {
	t.Helper()
	chaosOnce.Do(func() {
		s := &chaosStack{subURL: map[string]string{}, subscriptions: map[string]string{}}
		chaosOne = s
		s.start(t)
		chaosSetUp = !t.Failed()
	})
	if !chaosSetUp {
		t.Fatal("the chaos stack did not start (see the first test's log)")
	}
	return chaosOne
}

func (s *chaosStack) compose(t *testing.T, args ...string) string {
	t.Helper()
	out, err := s.composeErr(args...)
	if err != nil {
		t.Fatalf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (s *chaosStack) composeErr(args ...string) (string, error) {
	full := append([]string{"compose", "-p", chaosProject, "-f", chaosCompose, "--env-file", s.envFile, "--profile", "caddy"}, args...)
	cmd := exec.Command("docker", full...)
	cmd.Env = composeEnv()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	// 0644: the containers run as other users than the test (distroless
	// nonroot, caddy); these are throwaway test keys in a scratch dir.
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // test keys read by containers
		t.Fatal(err)
	}
}

func (s *chaosStack) start(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("docker is not on PATH: the chaos stack needs docker compose")
	}
	dir, err := os.MkdirTemp("", "cisp-chaos-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // read by the containers
		t.Fatal(err)
	}
	s.dir = dir
	start := time.Now()

	s.image = os.Getenv("CHAOS_IMAGE")
	if s.image == "" {
		s.image = "uspace-cisp:chaos-local"
		out, err := exec.Command("docker", "build", "--build-arg", "VERSION=chaos-local", "-t", s.image, "../..").CombinedOutput()
		if err != nil {
			t.Fatalf("docker build: %v\n%s", err, tail(string(out), 40))
		}
		t.Logf("built %s in %s", s.image, time.Since(start).Round(time.Second))
	}
	id, err := exec.Command("docker", "image", "inspect", "--format", "{{.Id}}", s.image).Output()
	if err != nil {
		t.Fatalf("docker image inspect %s: %v", s.image, err)
	}
	s.imageID = strings.TrimSpace(string(id))
	h := sha256.New()
	for _, f := range []string{chaosCompose, "../../deploy/caddy/Caddyfile.snippet"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		h.Write(raw)
	}
	s.composeHash = hex.EncodeToString(h.Sum(nil))[:16]

	s.keys(t)
	s.certs(t)
	pw := map[string]string{"POSTGRES_PASSWORD": secret(), "PG_CISP_API_PASSWORD": secret(), "PG_CISP_DELIVER_PASSWORD": secret()}
	ports := map[string]int{}
	for _, p := range []string{"CHAOS_API_PORT", "CHAOS_API_EDGE_PORT", "CHAOS_EDGE_PORT", "CHAOS_EDGE_ECHO_PORT", "CHAOS_SUB_A_PORT", "CHAOS_SUB_B_PORT", "CHAOS_SUB_SLOW_PORT"} {
		ports[p] = freePort(t)
	}
	s.apiURL = fmt.Sprintf("http://127.0.0.1:%d", ports["CHAOS_API_PORT"])
	s.apiEdgeURL = fmt.Sprintf("http://127.0.0.1:%d", ports["CHAOS_API_EDGE_PORT"])
	s.edgeURL = fmt.Sprintf("https://localhost:%d", ports["CHAOS_EDGE_PORT"])
	s.edgeEchoURL = fmt.Sprintf("https://localhost:%d", ports["CHAOS_EDGE_ECHO_PORT"])
	s.subURL["subscriber-a"] = fmt.Sprintf("https://127.0.0.1:%d", ports["CHAOS_SUB_A_PORT"])
	s.subURL["subscriber-b"] = fmt.Sprintf("https://127.0.0.1:%d", ports["CHAOS_SUB_B_PORT"])
	s.subURL["subscriber-slow"] = fmt.Sprintf("https://127.0.0.1:%d", ports["CHAOS_SUB_SLOW_PORT"])

	envLines := []string{
		"CHAOS_IMAGE=" + s.image, "CHAOS_DIR=" + filepath.ToSlash(dir), "CHAOS_SUBNET=" + chaosSubnet, "CHAOS_IP_RANGE=" + chaosIPRange, "CHAOS_EDGE_IP=" + chaosEdgeIP,
		"CHAOS_CISP_ISSUER_URL=" + chaosIssuer, "CHAOS_SUBSCRIBER_TOKEN=" + s.token(t, labClient, "api", "cis.read"),
	}
	for k, v := range pw {
		envLines = append(envLines, k+"="+v)
	}
	for k, v := range ports {
		envLines = append(envLines, fmt.Sprintf("%s=%d", k, v))
	}
	s.envFile = filepath.Join(dir, "chaos.env")
	writeFile(t, s.envFile, []byte(strings.Join(envLines, "\n")+"\n"))

	rel := "postgres://cisp_api:" + pw["PG_CISP_API_PASSWORD"] + "@postgres:5432/cisp?sslmode=disable"
	tsAPI := "postgres://cisp_api:" + pw["PG_CISP_API_PASSWORD"] + "@postgres:5432/cisp_ts?sslmode=disable"
	relDeliver := "postgres://cisp_deliver:" + pw["PG_CISP_DELIVER_PASSWORD"] + "@postgres:5432/cisp?sslmode=disable"
	tsDeliver := "postgres://cisp_deliver:" + pw["PG_CISP_DELIVER_PASSWORD"] + "@postgres:5432/cisp_ts?sslmode=disable"
	signing := []string{
		"CISP_SIGNING_KEY_FILE=/run/chaos/cisp.pem", "CISP_SIGNING_KID=" + cispKID,
		"CISP_ISSUER_URL=" + chaosIssuer, "CISP_PUBLIC_BASE_URL=http://api:8080",
		"CISP_NATS_URL=nats://nats:4222", "CISP_STATUS_INTERVAL_S=1", "CISP_LOG_LEVEL=info",
	}
	apiCommon := append([]string{
		"CISP_HTTP_ADDR=:8080", "CISP_DATABASE_URL=" + rel, "CISP_TIMESERIES_URL=" + tsAPI,
		"CISP_TOKEN_ISSUER=" + tokenIssuer, "CISP_TOKEN_JWKS_URL=https://jwks:8443/authority.json",
		"CISP_ANSP_JWKS_URL=https://jwks:8443/ansp.json", "CISP_AUDIENCES=localhost,127.0.0.1,api,api-edge",
		"CISP_JWKS_CACHE_FILE=/tmp/jwks-cache.json", "CISP_ALLOW_PRIVATE_CALLBACKS=true",
	}, signing...)
	writeEnv := func(name string, lines ...string) {
		writeFile(t, filepath.Join(dir, name), []byte(strings.Join(lines, "\n")+"\n"))
	}
	writeEnv("migrate.env", "CISP_DATABASE_URL="+rel, "CISP_TIMESERIES_URL="+tsDeliver)
	// The readers' api: the per-IP limit out of the way (every request of
	// the test comes from one address); CISP_MAX_PUBLICATION_BYTES is the
	// default on purpose.
	writeEnv("api.env", append([]string{"CISP_MTLS_MODE=off", "CISP_PUBLIC_RPM=1000000"}, apiCommon...)...)
	// The edge's api: production's mTLS mode and per-IP limit, believing
	// X-Forwarded-For from the edge only.
	writeEnv("api-edge.env", append([]string{
		"CISP_MTLS_MODE=required", "CISP_ANSP_MTLS_SUBJECT=" + s.anspSubject,
		"CISP_PUBLIC_RPM=60", "CISP_TRUSTED_PROXY_CIDR=" + chaosEdgeIP + "/32",
	}, apiCommon...)...)
	writeEnv("deliver.env", append([]string{
		"CISP_DELIVER_HTTP_ADDR=:8081", "CISP_DATABASE_URL=" + relDeliver, "CISP_TIMESERIES_URL=" + tsDeliver,
		"CISP_ALLOW_PRIVATE_CALLBACKS=true",
	}, signing...)...)

	s.compose(t, "up", "-d", "--wait", "postgres", "nats", "jwks")
	// The image's healthcheck can pass while its init scripts still run
	// (the roles do not exist yet): migrate until the roles answer.
	var out string
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(time.Second) {
		if out, err = s.composeErr("run", "--rm", "--no-deps", "migrate"); err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		t.Fatalf("cispctl migrate: %v\n%s", err, out)
	}
	s.compose(t, "up", "-d", "--wait", "--build", "api", "deliver", "subscriber-a", "subscriber-b", "subscriber-slow")
	t.Logf("chaos stack up in %s: image %s (%s), compose+snippet sha256 %s", time.Since(start).Round(time.Second),
		s.image, s.imageID, s.composeHash)
	summary(t, fmt.Sprintf("### Chaos run\n\nimage `%s` id `%s`; chaos.compose.yml + Caddyfile.snippet sha256 `%s`; %s; %s\n",
		s.image, s.imageID, s.composeHash, toolVersion("docker", "version", "--format", "docker {{.Server.Version}}"),
		toolVersion("docker", "compose", "version", "--short")))
}

func toolVersion(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return name + ": " + err.Error()
	}
	return strings.TrimSpace(string(out))
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// keys: the token issuer, the authority's and the ANSP's publication
// keys, the CISP's signing key, and the JWKS files the jwks service
// serves.
func (s *chaosStack) keys(t *testing.T) {
	t.Helper()
	tokKey := authtest.Key(t, "chaos-issuer", 2048)
	s.authKey = authtest.Key(t, "chaos-authority", 3072)
	s.anspKey = authtest.Key(t, "chaos-ansp", 3072)
	var err error
	if s.iss, err = coreauth.NewIssuer(tokenIssuer, tokKey, tokenKID); err != nil {
		t.Fatal(err)
	}
	cispPEM := mustPEM(t, authtest.Key(t, "chaos-cisp", 3072))
	writeFile(t, filepath.Join(s.dir, "cisp.pem"), cispPEM)
	if err := os.MkdirAll(filepath.Join(s.dir, "jwks"), 0o755); err != nil { //nolint:gosec // read by the jwks container
		t.Fatal(err)
	}
	authoritySet, _ := json.Marshal(authtest.PublicSet(t, map[string]*rsa.PrivateKey{tokenKID: tokKey, authorityKID: s.authKey}))
	anspSet, _ := json.Marshal(authtest.PublicSet(t, map[string]*rsa.PrivateKey{anspKID: s.anspKey}))
	writeFile(t, filepath.Join(s.dir, "jwks", "authority.json"), authoritySet)
	writeFile(t, filepath.Join(s.dir, "jwks", "ansp.json"), anspSet)
}

func mustPEM(t *testing.T, k *rsa.PrivateKey) []byte {
	t.Helper()
	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "k.pem"), k)
	raw, err := os.ReadFile(filepath.Join(dir, "k.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type issued struct {
	cert    *x509.Certificate
	certPEM []byte
	keyPEM  []byte
	key     *ecdsa.PrivateKey
}

func issue(t *testing.T, subject pkix.Name, parent *issued, isCA bool, dns []string, client bool) *issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true, IsCA: isCA,
	}
	if isCA {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	} else if client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		for _, d := range dns {
			if ip := net.ParseIP(d); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, d)
			}
		}
	}
	parentCert, parentKey := tmpl, key
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	kder, _ := x509.MarshalECPrivateKey(key)
	return &issued{
		cert: cert, key: key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}),
	}
}

// certs: a test CA for the jwks service and the subscribers (trusted by
// api and deliver through SSL_CERT_FILE), and an mTLS CA for the ANSP's
// client certificate and an impostor's.
func (s *chaosStack) certs(t *testing.T) {
	t.Helper()
	ca := issue(t, pkix.Name{CommonName: "uspace-cisp chaos test CA"}, nil, true, nil, false)
	s.caPEM = ca.certPEM
	writeFile(t, filepath.Join(s.dir, "ca.pem"), ca.certPEM)
	jwksCert := issue(t, pkix.Name{CommonName: "jwks"}, ca, false, []string{"jwks"}, false)
	writeFile(t, filepath.Join(s.dir, "jwks.pem"), jwksCert.certPEM)
	writeFile(t, filepath.Join(s.dir, "jwks-key.pem"), jwksCert.keyPEM)
	sub := issue(t, pkix.Name{CommonName: "subscriber"}, ca, false,
		[]string{"subscriber-a", "subscriber-b", "subscriber-slow", "localhost", "127.0.0.1"}, false)
	writeFile(t, filepath.Join(s.dir, "subscriber.pem"), sub.certPEM)
	writeFile(t, filepath.Join(s.dir, "subscriber-key.pem"), sub.keyPEM)
	writeFile(t, filepath.Join(s.dir, "jwks.Caddyfile"), []byte(`{
	admin off
}
https://jwks:8443 {
	tls /run/chaos/jwks.pem /run/chaos/jwks-key.pem
	root * /run/chaos/jwks
	file_server
}
`))
	writeFile(t, filepath.Join(s.dir, "echo.Caddyfile"), []byte(`{
	admin off
	auto_https off
}
:8080 {
	header Content-Type text/plain
	respond "subject=[{http.request.header.X-Client-Cert-Subject}] path={http.request.uri.path}" 200
}
`))
	s.roots = x509.NewCertPool()
	s.roots.AddCert(ca.cert)
	s.client = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.roots, MinVersion: tls.VersionTLS12}}}

	mca := issue(t, pkix.Name{CommonName: "uspace-cisp chaos mTLS CA"}, nil, true, nil, false)
	writeFile(t, filepath.Join(s.dir, "mtls-ca.pem"), mca.certPEM)
	ansp := issue(t, pkix.Name{CommonName: "ansp-01", Organization: []string{"Chaos ANSP"}}, mca, false, nil, true)
	imp := issue(t, pkix.Name{CommonName: "impostor", Organization: []string{"Chaos ANSP"}}, mca, false, nil, true)
	var err error
	if s.anspCert, err = tls.X509KeyPair(ansp.certPEM, ansp.keyPEM); err != nil {
		t.Fatal(err)
	}
	if s.impostor, err = tls.X509KeyPair(imp.certPEM, imp.keyPEM); err != nil {
		t.Fatal(err)
	}
	// The subject as Go writes it; the Caddy test checks it is what the
	// edge forwards (the placeholder http.request.tls.client.subject).
	s.anspSubject = ansp.cert.Subject.String()
	if err := os.MkdirAll(filepath.Join(s.dir, "basemap"), 0o755); err != nil { //nolint:gosec // read by caddy
		t.Fatal(err)
	}
}

func (s *chaosStack) teardown() {
	if s.envFile != "" {
		if os.Getenv("CHAOS_KEEP_LOGS") != "" {
			out, _ := s.composeErr("logs", "--no-color", "--tail", "200")
			fmt.Fprintln(os.Stderr, out)
		}
		out, err := s.composeErr("down", "-v", "--remove-orphans")
		if err != nil {
			fmt.Fprintf(os.Stderr, "chaos: compose down: %v\n%s", err, out)
		} else {
			fmt.Fprintln(os.Stderr, "chaos: compose down: stack removed")
		}
	}
	_ = os.RemoveAll(s.dir)
}

func (s *chaosStack) token(t *testing.T, sub, aud string, scopes ...string) string {
	t.Helper()
	tok, err := s.iss.Issue(sub, aud, scopes, 3*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// do is one request; the body is read whole.
func (s *chaosStack) do(t *testing.T, client *http.Client, method, url, token string, body []byte, headers map[string]string) (*http.Response, []byte, error) {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
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
	if client == nil {
		client = s.client
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return resp, raw, err
}

// call is a request to the readers' api that must get an answer.
func (s *chaosStack) call(t *testing.T, method, path, token string, body []byte, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	resp, raw, err := s.do(t, nil, method, s.apiURL+path, token, body, headers)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp, raw
}

func (s *chaosStack) signAs(t *testing.T, key *rsa.PrivateKey, kid string, body []byte) string {
	t.Helper()
	sig, err := coreauth.SignDetached(coreauth.SigningKey{KID: kid, Key: key}, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func (s *chaosStack) authorityToken(t *testing.T) string {
	return s.token(t, authorityID, "localhost", "cis.publish:zones", "cis.publish:uspace", "cis.read")
}

// etag is the current ETag of ds.
func (s *chaosStack) etag(t *testing.T, ds string) string {
	t.Helper()
	resp, _ := s.call(t, http.MethodHead, "/public/v1/"+ds, "", nil, nil)
	if e := resp.Header.Get("ETag"); e != "" {
		return e
	}
	return `"` + ds + `:0"`
}

// putAs PUTs a dataset with If-Match ifMatch and returns the response.
func (s *chaosStack) putAs(t *testing.T, ds, ifMatch string, body []byte) (*http.Response, []byte, error) {
	t.Helper()
	return s.do(t, nil, http.MethodPut, s.apiURL+"/v1/publications/"+ds, s.authorityToken(t), body, map[string]string{
		"If-Match": ifMatch, "X-JWS-Signature": s.signAs(t, s.authKey, authorityKID, body), "Content-Type": "application/geo+json",
	})
}

// publish PUTs a dataset on its current ETag and returns its version.
func (s *chaosStack) publish(t *testing.T, ds string, body []byte) int64 {
	t.Helper()
	resp, raw, err := s.putAs(t, ds, s.etag(t, ds), body)
	if err != nil {
		t.Fatalf("PUT %s: %v", ds, err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT %s = %d %s", ds, resp.StatusCode, tail(string(raw), 5))
	}
	var out struct {
		Version int64 `json:"version"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.Version
}

func (s *chaosStack) changes(t *testing.T, since int64) ([]change, int64) {
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

// received are the notifications sub recorded, read from its stdout
// (one JSON line each) rather than its published port: the log outlives
// a restart, and a port picked free at the start may be taken by
// another process while the subscriber is stopped.
func (s *chaosStack) received(t *testing.T, sub string) []received {
	t.Helper()
	out, err := s.composeErr("logs", "--no-color", "--no-log-prefix", sub)
	if err != nil {
		t.Logf("logs %s: %v", sub, err)
		return nil
	}
	var recs []received
	for _, l := range strings.Split(out, "\n") {
		if !strings.Contains(l, `"received_at"`) {
			continue
		}
		var r received
		if json.Unmarshal([]byte(l), &r) == nil {
			recs = append(recs, r)
		}
	}
	return recs
}

// subscribe registers sub (its callback on the compose network) for
// datasets once, and waits for its ping to verify it.
func (s *chaosStack) subscribe(t *testing.T, sub string, datasets ...string) string {
	t.Helper()
	s.subscriptionsMu.Lock()
	defer s.subscriptionsMu.Unlock()
	if id, ok := s.subscriptions[sub]; ok {
		return id
	}
	tok := s.token(t, labClient, "localhost", "cis.read")
	body, _ := json.Marshal(doc{"callback_url": "https://" + sub + ":8080/v1/cis/notifications", "datasets": datasets})
	resp, raw := s.call(t, http.MethodPost, "/v1/subscriptions", tok, body, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("subscribe %s = %d %s", sub, resp.StatusCode, raw)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(raw, &created)
	eventually(t, 30*time.Second, sub+" verified", func() bool {
		_, raw := s.call(t, http.MethodGet, "/v1/subscriptions/"+created.ID, tok, nil, nil)
		var got struct {
			Status string `json:"status"`
		}
		_ = json.Unmarshal(raw, &got)
		return got.Status == "active"
	})
	t.Logf("%s subscribed to %v: subscription %s active", sub, datasets, created.ID)
	s.subscriptions[sub] = created.ID
	return created.ID
}

// logs are a service's JSON log lines (other lines, such as the GC
// trace, are in raw).
func (s *chaosStack) logs(t *testing.T, service string) (lines []doc, raw []string) {
	t.Helper()
	out, err := s.composeErr("logs", "--no-color", "--no-log-prefix", service)
	if err != nil {
		t.Logf("logs %s: %v", service, err)
	}
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		raw = append(raw, l)
		var m doc
		if json.Unmarshal([]byte(l), &m) == nil {
			lines = append(lines, m)
		}
	}
	return lines, raw
}

// waitLog waits for a log line of service, after the first skip JSON
// lines, that ok accepts.
func (s *chaosStack) waitLog(t *testing.T, service string, skip int, within time.Duration, what string, ok func(doc) bool) doc {
	t.Helper()
	var found doc
	eventually(t, within, service+": "+what, func() bool {
		lines, _ := s.logs(t, service)
		for _, m := range lines[min(skip, len(lines)):] {
			if ok(m) {
				found = m
				return true
			}
		}
		return false
	})
	return found
}

func (s *chaosStack) logCount(t *testing.T, service string) int {
	lines, _ := s.logs(t, service)
	return len(lines)
}

// state is a container's state as docker reports it: running, exited
// with its code, OOM-killed, its restart count.
func (s *chaosStack) state(t *testing.T, service string) string {
	t.Helper()
	id := strings.TrimSpace(s.compose(t, "ps", "-a", "-q", service))
	if id == "" {
		return "no container"
	}
	out, err := exec.Command("docker", "inspect", "--format",
		"{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} restarts={{.RestartCount}}", id).Output()
	if err != nil {
		return "inspect: " + err.Error()
	}
	return strings.TrimSpace(string(out))
}

// ready waits until url answers 200.
func (s *chaosStack) ready(t *testing.T, url string, within time.Duration) {
	t.Helper()
	eventually(t, within, url+" ready", func() bool {
		resp, err := s.client.Get(url)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

// table renders rows as a markdown table.
func table(head []string, rows [][]string) string {
	var b strings.Builder
	b.WriteString("| " + strings.Join(head, " | ") + " |\n|")
	for range head {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, r := range rows {
		b.WriteString("| " + strings.Join(r, " | ") + " |\n")
	}
	return b.String()
}
