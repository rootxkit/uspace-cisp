package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/jws"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func runIn(t *testing.T, dir string, args, env []string, stdin string, now time.Time) (int, string, string) {
	t.Helper()
	t.Chdir(dir)
	var stdout, stderr bytes.Buffer
	code := runIO(context.Background(), args, env, strings.NewReader(stdin), &stdout, &stderr, now)
	return code, stdout.String(), stderr.String()
}

func envLines(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok && !strings.HasPrefix(l, "#") {
			m[k] = v
		}
	}
	return m
}

// rotate-key writes an RSA-3072 key the api's ring loads, prints the env
// lines (with the current key as the previous one), and never overwrites.
func TestRotateKey(t *testing.T) {
	dir := t.TempDir()
	code, out, errOut := runIn(t, dir, []string{"rotate-key"}, []string{"CISP_SIGNING_KEY_FILE=local/signing-old.pem", "CISP_SIGNING_KID=old"}, "", t0)
	if code != exitOK {
		t.Fatalf("rotate-key = %d %s", code, errOut)
	}
	t.Logf("rotate-key printed:\n%s", out)
	env := envLines(out)
	kid := "cisp-20261002T120000Z"
	path := filepath.Join("local", "signing-"+kid+".pem")
	if env["CISP_SIGNING_KID"] != kid || env["CISP_SIGNING_KEY_FILE"] != path ||
		env["CISP_SIGNING_KEY_PREV_FILE"] != "local/signing-old.pem" || env["CISP_SIGNING_KID_PREV"] != "old" {
		t.Errorf("env lines = %v", env)
	}
	info, err := os.Stat(filepath.Join(dir, path))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	r, err := jws.ReadKeyRing(filepath.Join(dir, path), kid, "", "")
	if err != nil || r.ActiveKID() != kid {
		t.Fatalf("the written key does not load: %v", err)
	}
	if code, _, errOut := runIn(t, dir, []string{"rotate-key"}, nil, "", t0); code != exitFailed || !strings.Contains(errOut, "never overwritten") {
		t.Errorf("second rotate-key with the same kid: %d %s", code, errOut)
	}
	// Without a current key there is no previous line.
	code, out, _ = runIn(t, dir, []string{"rotate-key", "--kid", "k-2", "--out", "local/keys"}, nil, "", t0)
	if code != exitOK || strings.Contains(out, "PREV") {
		t.Errorf("rotate-key --kid: %d %s", code, out)
	}
}

func TestRotateKeyRefusals(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "keys")
	if code, _, errOut := runIn(t, dir, []string{"rotate-key", "--out", outside}, nil, "", t0); code != exitUsage || !strings.Contains(errOut, "--force") {
		t.Errorf("outside local/: %d %s", code, errOut)
	}
	if code, _, errOut := runIn(t, dir, []string{"rotate-key", "--out", "local/../elsewhere"}, nil, "", t0); code != exitUsage {
		t.Errorf("escaping local/: %d %s", code, errOut)
	}
	if code, out, errOut := runIn(t, dir, []string{"rotate-key", "--out", outside, "--force"}, nil, "", t0); code != exitOK || !strings.Contains(out, outside) {
		t.Errorf("--force: %d %s", code, errOut)
	}
	for _, args := range [][]string{{"rotate-key", "--kid", "a/b"}, {"rotate-key", "extra"}, {"rotate-key", "--nope"}} {
		if code, _, _ := runIn(t, dir, args, nil, "", t0); code != exitUsage {
			t.Errorf("%v: %d", args, code)
		}
	}
	blocker := filepath.Join(dir, "local", "file")
	if err := os.MkdirAll(filepath.Dir(blocker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runIn(t, dir, []string{"rotate-key", "--out", "local/file/sub"}, nil, "", t0); code != exitFailed {
		t.Errorf("an unwritable directory: %d", code)
	}
}

// sign then verify-signature: the end-to-end pair of rotate-key's key,
// beside an altered body, another kid and a stale signature refused.
func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	if code, _, errOut := runIn(t, dir, []string{"rotate-key", "--kid", "k1"}, nil, "", t0); code != exitOK {
		t.Fatal(errOut)
	}
	key := filepath.Join("local", "signing-k1.pem")
	body := `{"type":"FeatureCollection","features":[]}`
	code, sig, errOut := runIn(t, dir, []string{"sign", "--key", key, "--kid", "k1"}, nil, body, t0)
	if code != exitOK || strings.Count(sig, ".") != 2 {
		t.Fatalf("sign = %d %q %s", code, sig, errOut)
	}
	sig = strings.TrimSpace(sig)
	verify := func(b, kid string, at time.Time) (int, string) {
		code, out, errOut := runIn(t, dir, []string{"verify-signature", "--key", key, "--kid", kid, "--sig", sig}, nil, b, at)
		return code, out + errOut
	}
	if code, out := verify(body, "k1", t0); code != exitOK || !strings.Contains(out, "signature ok: kid k1") {
		t.Errorf("verify = %d %s", code, out)
	}
	for name, c := range map[string]struct {
		body, kid string
		at        time.Time
	}{
		"altered body": {body + " ", "k1", t0},
		"other kid":    {body, "k2", t0},
		"6 min later":  {body, "k1", t0.Add(6 * time.Minute)},
		"empty body":   {"", "k1", t0},
	} {
		if code, out := verify(c.body, c.kid, c.at); code != exitFailed || !strings.Contains(out, "signature refused") {
			t.Errorf("%s: %d %s", name, code, out)
		}
	}
}

func TestSignAndVerifyUsage(t *testing.T) {
	dir := t.TempDir()
	if code, _, _ := runIn(t, dir, []string{"rotate-key", "--kid", "k1"}, nil, "", t0); code != exitOK {
		t.Fatal("rotate-key")
	}
	key := filepath.Join("local", "signing-k1.pem")
	notKey := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notKey, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args  []string
		stdin string
		code  int
	}{
		{[]string{"sign"}, "x", exitUsage},
		{[]string{"sign", "--key", key}, "x", exitUsage},
		{[]string{"sign", "--key", "missing.pem", "--kid", "k1"}, "x", exitFailed},
		{[]string{"sign", "--key", notKey, "--kid", "k1"}, "x", exitFailed},
		{[]string{"sign", "--key", key, "--kid", "k1", "--max-bytes", "2"}, "xyz", exitFailed},
		{[]string{"sign", "--key", key, "--kid", "k1", "--max-bytes", "3"}, "xyz", exitOK},
		{[]string{"verify-signature", "--key", key}, "x", exitUsage},
		{[]string{"verify-signature", "--key", "missing.pem", "--kid", "k1"}, "x", exitFailed},
		{[]string{"verify-signature", "--key", key, "--kid", "k1", "--max-bytes", "2", "--sig", "a..b"}, "xyz", exitFailed},
		{[]string{"verify-signature", "--key", key, "--kid", "k1", "--max-skew", "0s", "--sig", "a..b"}, "xyz", exitFailed},
	}
	for _, c := range cases {
		if code, _, errOut := runIn(t, dir, c.args, nil, c.stdin, t0); code != c.code {
			t.Errorf("%v: %d, want %d (%s)", c.args, code, c.code, errOut)
		}
	}
	// run() (no stdin) still dispatches.
	if code := run(context.Background(), []string{"sign"}, nil, &bytes.Buffer{}, &bytes.Buffer{}); code != exitUsage {
		t.Errorf("run sign = %d", code)
	}
}
