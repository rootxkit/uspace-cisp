package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/jws"
)

// sessionKeyFile writes a 3072-bit session key (generated at test time,
// never committed) and returns its path.
func sessionKeyFile(t *testing.T, bits int) string {
	t.Helper()
	pemBytes, err := jws.EncodePrivateKeyPEM(authtest.Key(t, "api-session", bits))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "session.pem")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func do(t *testing.T, method, url, token string, body any) (int, string) {
	t.Helper()
	var rdr io.Reader = http.NoBody
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Without the console variables the api starts, every console route
// answers 503 console_unavailable, and the status line warns (E-02:
// the branch that says the console is off is run and read).
func TestRunConsoleNotConfigured(t *testing.T) {
	r := startRun(t, baseEnv(t, "CISP_HTTP_ADDR=127.0.0.1:0"))
	status := waitForLine(t, r.logs, "status")
	comp, _ := status["console"].(map[string]any)
	if w, _ := comp["warning"].(string); !strings.Contains(w, "not configured") {
		t.Errorf("console component %v", comp)
	}
	code, body := do(t, http.MethodPost, r.base+"/v1/console/session", "", map[string]any{"username": "a", "password": "b"})
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "console_unavailable") || !strings.Contains(body, `"errors":[]`) {
		t.Errorf("login = %d %s", code, body)
	}
	if c := r.stop(t); c != 0 {
		t.Errorf("exit %d", c)
	}
}

// A console with a session key but no CISP_SECRETS_KEY_FILE refuses to start
// and names the variable; a short session key refuses to start too.
func TestRunConsoleRefusals(t *testing.T) {
	logs := &syncBuffer{}
	env := baseEnv(t, "CISP_HTTP_ADDR=127.0.0.1:0", "CISP_DATABASE_URL=postgres://cisp_api:x@"+closedPort(t)+"/cisp",
		"CISP_SESSION_KEY_FILE="+sessionKeyFile(t, 3072), "CISP_CONSOLE_ISSUER=https://cisp.example.test/console")
	if c := run(context.Background(), nil, env, logs, io.Discard); c != 2 || !strings.Contains(logs.String(), "CISP_SECRETS_KEY_FILE") {
		t.Errorf("no secrets key: exit %d %s", c, logs.String())
	}
	t.Logf("refused: %s", lastLine(logs.String()))
	logs = &syncBuffer{}
	env = baseEnv(t, "CISP_HTTP_ADDR=127.0.0.1:0", "CISP_DATABASE_URL=postgres://cisp_api:x@"+closedPort(t)+"/cisp",
		"CISP_SESSION_KEY_FILE="+sessionKeyFile(t, 2048), "CISP_CONSOLE_ISSUER=https://cisp.example.test/console", "CISP_SECRETS_KEY_FILE="+secretsKeyFile(t))
	if c := run(context.Background(), nil, env, logs, io.Discard); c != 1 || !strings.Contains(logs.String(), "shorter than 3072") {
		t.Errorf("short key: exit %d %s", c, logs.String())
	}
	logs = &syncBuffer{}
	env = baseEnv(t, "CISP_HTTP_ADDR=127.0.0.1:0", "CISP_DATABASE_URL=postgres://cisp_api:x@"+closedPort(t)+"/cisp",
		"CISP_SESSION_KEY_FILE="+filepath.Join(t.TempDir(), "missing.pem"), "CISP_CONSOLE_ISSUER=https://cisp.example.test/console", "CISP_SECRETS_KEY_FILE="+secretsKeyFile(t))
	if c := run(context.Background(), nil, env, logs, io.Discard); c != 1 || !strings.Contains(logs.String(), "CISP_SESSION_KEY_FILE") {
		t.Errorf("missing key: exit %d %s", c, logs.String())
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// k32 is a secrets key for tests: 32 bytes built at run time so no
// key-shaped literal sits in the repository.
func k32() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

// secretsKeyFile writes k32 as a CISP_SECRETS_KEY_FILE (one key, standard
// base64) and returns its path.
func secretsKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(k32())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
