package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/jws"
)

// The start's refusals and degraded starts, without a database: each a
// distinct exit and log line, beside the start that differs in one
// thing (E-01, E-02). No address below is reachable (port 1), and a
// pool does not connect at start, so nothing here needs PostgreSQL or
// NATS.

const (
	// unreachable parses and is never answered.
	unreachable = "postgres://cisp_deliver:s3cret-in-url@127.0.0.1:1/cisp?sslmode=disable"
	// unparsable passes the configuration's URL check (a postgres URL)
	// and is refused by the pool: sslmode has no such value.
	unparsable = "postgres://cisp_deliver:s3cret-in-url@127.0.0.1:1/cisp?sslmode=sometimes"
)

func keyFile(t *testing.T) string {
	t.Helper()
	pemBytes, err := jws.EncodePrivateKeyPEM(authtest.Key(t, "deliver-start", 3072))
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "cisp.pem")
	if err := os.WriteFile(f, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// sendingEnv is a deliver that would send: a database, a signing key,
// the issuer and the public base URL.
func sendingEnv(dbURL, key string, extra ...string) []string {
	return append([]string{
		"CISP_DELIVER_HTTP_ADDR=127.0.0.1:0",
		"CISP_DATABASE_URL=" + dbURL,
		"CISP_SIGNING_KEY_FILE=" + key, "CISP_SIGNING_KID=cisp-start",
		"CISP_ISSUER_URL=https://uspace-cisp.example.test", "CISP_PUBLIC_BASE_URL=https://uspace-cisp.example.test",
		"CISP_STATUS_INTERVAL_S=1",
	}, extra...)
}

// refused runs deliver to its exit and checks the code and the line.
func refused(t *testing.T, env []string, wantCode int, want ...string) string {
	t.Helper()
	logs := &syncBuffer{}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if c := run(ctx, nil, env, logs, io.Discard); c != wantCode {
		t.Errorf("exit %d, want %d: %s", c, wantCode, logs.String())
	}
	for _, w := range want {
		if !strings.Contains(logs.String(), w) {
			t.Errorf("no %q in: %s", w, logs.String())
		}
	}
	if strings.Contains(logs.String(), "s3cret-in-url") {
		t.Errorf("a database password reached the log: %s", logs.String())
	}
	if strings.Contains(logs.String(), `"msg":"listening"`) {
		t.Errorf("a refused start listened: %s", logs.String())
	}
	return logs.String()
}

func TestStartRefusals(t *testing.T) {
	key := keyFile(t)
	t.Run("a timeseries URL the pool refuses", func(t *testing.T) {
		refused(t, []string{"CISP_DELIVER_HTTP_ADDR=127.0.0.1:0", "CISP_TIMESERIES_URL=" + unparsable}, 1, "timeseries pool refused")
	})
	t.Run("a database URL the pool refuses", func(t *testing.T) {
		refused(t, sendingEnv(unparsable, key), 1, "deliver refused", `"error":"database pool: `)
	})
	t.Run("a signing key that is not there", func(t *testing.T) {
		refused(t, sendingEnv(unreachable, filepath.Join(t.TempDir(), "missing.pem")), 1, "deliver refused", `"error":"signing key: `)
	})
	t.Run("NATS credentials that are not there", func(t *testing.T) {
		refused(t, sendingEnv(unreachable, key, "CISP_NATS_URL=nats://127.0.0.1:1", "CISP_NATS_CREDS_FILE="+filepath.Join(t.TempDir(), "missing.creds")),
			1, "deliver refused", `"error":"nats: `)
	})
}

// The starts that go on degraded, each said: a timeseries database that
// cannot be asked about its migrations is a warning, not a refusal; no
// delivery log and no broker configured are in the status line. The
// same key and URLs as the refusals above, so it is the one thing that
// differs that refuses there.
func TestStartDegraded(t *testing.T) {
	key := keyFile(t)
	t.Run("the timeseries database unreachable at start", func(t *testing.T) {
		logs, cancel, code, _ := startRun(t, []string{"CISP_DELIVER_HTTP_ADDR=127.0.0.1:0", "CISP_TIMESERIES_URL=" + unreachable})
		if w := waitForLine(t, logs, "migrations not checked at start"); w["level"] != "WARN" || w["tree"] != "timeseries" {
			t.Errorf("warning %v", w)
		}
		cancel()
		if c := <-code; c != 0 {
			t.Errorf("exit %d", c)
		}
		if strings.Contains(logs.String(), "s3cret-in-url") {
			t.Errorf("a database password reached the log: %s", logs.String())
		}
	})
	t.Run("no delivery log and no broker", func(t *testing.T) {
		logs, cancel, code, _ := startRun(t, sendingEnv(unreachable, key))
		waitForLine(t, logs, "delivering")
		status := waitForLine(t, logs, "status")
		dl, _ := status["delivery_log"].(map[string]any)
		nats, _ := status["nats"].(map[string]any)
		if d, _ := dl["degraded"].(string); !strings.Contains(d, "not configured") {
			t.Errorf("delivery_log in the status line: %v", status)
		}
		if d, _ := nats["degraded"].(string); !strings.Contains(d, "the scan alone") {
			t.Errorf("nats in the status line: %v", status)
		}
		cancel()
		select {
		case c := <-code:
			if c != 0 {
				t.Errorf("exit %d: %s", c, logs.String())
			}
		case <-time.After(15 * time.Second):
			t.Fatal("deliver did not stop")
		}
	})
}
