//go:build integration

package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

func dbPool(t *testing.T) *store.Store {
	t.Helper()
	p, err := store.OpenPool(context.Background(), store.PoolConfig{URL: os.Getenv("CISP_TEST_DATABASE_URL"), ApplicationName: "uspace-cisp-test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	db := store.OpenSQL(p)
	defer func() { _ = db.Close() }()
	if _, err := store.Up(context.Background(), db, store.TreeRelational); err != nil {
		t.Fatal(err)
	}
	return store.New(p, store.Options{})
}

// tamper sets entity_id of events row id, as the owner would have to:
// UPDATE is granted for one transaction and revoked before it commits
// (the application role holds INSERT and SELECT only, 06 T7).
func tamper(t *testing.T, s *store.Store, id int64, entity string) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, q := range []string{"GRANT UPDATE ON events TO CURRENT_USER", "UPDATE events SET entity_id = $1 WHERE id = $2", "REVOKE UPDATE ON events FROM CURRENT_USER"} {
		var args []any
		if strings.HasPrefix(q, "UPDATE") {
			args = []any{entity, id}
		}
		if _, err := tx.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// create-account prints the one-time password and, for an admin, the
// otpauth URL; verify-audit over the rows it wrote prints the count and
// exits 0; with one row tampered it names that row and exits 1; with
// the row restored it is clean again (E-02: both printed).
func TestCreateAccountAndVerifyAudit(t *testing.T) {
	env := append(testEnv(t), "CISP_SECRETS_KEY="+k32())
	s := dbPool(t)
	ctx := context.Background()
	start, err := s.DatabaseNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	from := start.Add(-time.Second).Format(time.RFC3339)
	name := "first-admin-" + strings.ToLower(store.NewID(time.Now())[20:])
	code, out, errOut := runCtl([]string{"create-account", "--username", name, "--role", "admin"}, env)
	if code != exitOK || !strings.Contains(out, "one-time password (shown once): ") || !strings.Contains(out, "otpauth://totp/uspace-cisp:"+name) {
		t.Fatalf("create-account = %d %q %q", code, out, errOut)
	}
	var shown []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if p, _, ok := strings.Cut(l, ": "); ok && (strings.HasPrefix(l, "one-time password") || strings.HasPrefix(l, "TOTP")) {
			l = p + ": <shown once; not logged>"
		}
		shown = append(shown, l)
	}
	t.Logf("create-account:\n%s", strings.Join(shown, "\n"))
	if code, _, errOut := runCtl([]string{"create-account", "--username", name, "--role", "viewer"}, env); code != exitFailed || !strings.Contains(errOut, "another account has this username") {
		t.Errorf("duplicate = %d %q", code, errOut)
	}
	if code, _, _ := runCtl([]string{"create-account", "--username", name + "x", "--role", "owner"}, env); code != exitFailed {
		t.Errorf("bad role = %d", code)
	}
	if code, _, errOut := runCtl([]string{"create-account", "--username", name + "y", "--role", "viewer"}, testEnv(t)); code != exitConfig || !strings.Contains(errOut, "CISP_SECRETS_KEY is not set") {
		t.Errorf("no secrets key = %d %q", code, errOut)
	}
	code, out, errOut = runCtl([]string{"verify-audit", "--from", from}, env)
	if code != exitOK || !strings.Contains(out, "rows verified") || !strings.Contains(out, "intact") {
		t.Fatalf("verify-audit clean = %d %q %q", code, out, errOut)
	}
	t.Logf("verify-audit (clean): %s", strings.TrimSpace(out))

	rows, err := s.AuditEvents(ctx, store.AuditFilter{Since: start.Add(-time.Second), Limit: 10})
	if err != nil || len(rows) == 0 {
		t.Fatalf("rows %v %v", rows, err)
	}
	victim := rows[len(rows)-1] // the oldest of this test's rows
	tamper(t, s, victim.ID, "forged")
	code, out, _ = runCtl([]string{"verify-audit", "--from", from}, env)
	if code != exitFailed || !strings.Contains(out, "BROKEN") || !strings.Contains(out, "events row "+strconv.FormatInt(victim.ID, 10)) {
		t.Errorf("verify-audit tampered = %d %q", code, out)
	}
	t.Logf("verify-audit (row %d tampered): %s", victim.ID, strings.TrimSpace(out))
	tamper(t, s, victim.ID, victim.EntityID)
	if code, out, _ := runCtl([]string{"verify-audit", "--from", from}, env); code != exitOK {
		t.Errorf("restored = %d %q", code, out)
	}
	if code, out, _ := runCtl([]string{"verify-audit", "--from", "2001-01-01T00:00:00Z", "--to", "2001-01-02T00:00:00Z"}, env); code != exitOK || !strings.Contains(out, "0 rows") {
		t.Errorf("empty range = %d %q", code, out)
	}
	for _, bad := range [][]string{{"--from", "yesterday"}, {"--from", "2001-01-02T00:00:00Z", "--to", "2001-01-01T00:00:00Z"}, {"extra"}} {
		if code, _, _ := runCtl(append([]string{"verify-audit"}, bad...), env); code != exitUsage {
			t.Errorf("verify-audit %v = %d", bad, code)
		}
	}
}

// export-audit writes the rows as JSON lines with their chain hashes and
// a detached JWS of the file by the CISP's key, which verifies against
// the key's public half; the file is never overwritten.
func TestExportAudit(t *testing.T) {
	key := authtest.Key(t, "cisp-export", 3072)
	pemBytes, err := jws.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "signing.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	env := append(testEnv(t), "CISP_SECRETS_KEY="+k32(), "CISP_SIGNING_KEY_FILE="+keyFile, "CISP_SIGNING_KID=cisp-export-1")
	s := dbPool(t)
	start, _ := s.DatabaseNow(context.Background())
	if code, _, errOut := runCtl([]string{"create-account", "--username", "exp-" + strings.ToLower(store.NewID(time.Now())[20:]), "--role", "viewer"}, env); code != exitOK {
		t.Fatal(errOut)
	}
	out := filepath.Join(dir, "audit.jsonl")
	from := start.Add(-time.Second).Format(time.RFC3339)
	code, stdout, errOut := runCtl([]string{"export-audit", "--out", out, "--from", from}, env)
	if code != exitOK || !strings.Contains(stdout, "kid cisp-export-1") {
		t.Fatalf("export-audit = %d %q %q", code, stdout, errOut)
	}
	t.Log(strings.TrimSpace(stdout))
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	lines := 0
	for sc.Scan() {
		var r console.ExportRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil || r.Hash == "" {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		lines++
	}
	if lines == 0 {
		t.Fatal("no rows exported")
	}
	sig, err := os.ReadFile(out + ".jws")
	if err != nil {
		t.Fatal(err)
	}
	v, err := jws.NewDetachedVerifier(context.Background(), jws.KeySource{Publisher: "cisp", Keys: coreauth.IssuerConfig{Keys: authtest.PublicSet(t, map[string]*rsa.PrivateKey{"cisp-export-1": key})}},
		time.Hour, jws.Options{MaxPayloadBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), strings.TrimSpace(string(sig)), body); err != nil {
		t.Errorf("the export's signature does not verify: %v", err)
	}
	if _, err := v.Verify(context.Background(), strings.TrimSpace(string(sig)), append(body, '\n')); err == nil {
		t.Error("an altered export verified")
	}
	if code, _, _ := runCtl([]string{"export-audit", "--out", out, "--from", from}, env); code != exitFailed {
		t.Errorf("overwrite = %d", code)
	}
	if code, _, _ := runCtl([]string{"export-audit", "--from", from}, env); code != exitUsage {
		t.Errorf("no --out = %d", code)
	}
	if code, _, _ := runCtl([]string{"export-audit", "--out", filepath.Join(dir, "x.jsonl")}, testEnv(t)); code != exitConfig {
		t.Errorf("no signing key = %d", code)
	}
}

func TestPartitions(t *testing.T) {
	env := testEnv(t)
	code, out, errOut := runCtl([]string{"partitions", "--ensure-months", "4"}, env)
	if code != exitOK {
		t.Fatalf("partitions = %d %q %q", code, out, errOut)
	}
	t.Log(strings.TrimSpace(out))
	code, out, _ = runCtl([]string{"partitions", "--ensure-months", "4"}, env)
	if code != exitOK || !strings.Contains(out, "every partition through 4 months ahead exists") {
		t.Errorf("second run = %d %q", code, out)
	}
	if code, _, _ := runCtl([]string{"partitions", "--ensure-months", "-1"}, env); code != exitUsage {
		t.Errorf("negative = %d", code)
	}
}
