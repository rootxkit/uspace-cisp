package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runCtl(args, env []string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, env, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestVersion(t *testing.T) {
	code, out, _ := runCtl([]string{"version"}, nil)
	if code != exitOK || strings.TrimSpace(out) != version {
		t.Errorf("version = %d %q", code, out)
	}
}

func TestConfigCheckOK(t *testing.T) {
	code, out, errOut := runCtl([]string{"config", "check"}, []string{
		"CISP_DATABASE_URL=postgres://cisp_api:hunter2-pw@db/cisp",
		"CISP_SECRETS_KEY=very-secret-key-material",
	})
	if code != exitOK || !strings.Contains(out, "config check: ok") {
		t.Fatalf("config check = %d %q %q", code, out, errOut)
	}
	for _, want := range []string{"CISP_HTTP_ADDR=:8080", "CISP_DELIVER_HTTP_ADDR=:8081", "CISP_DATABASE_URL=postgres://cisp_api:***@db/cisp", "CISP_SECRETS_KEY=***"} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "hunter2-pw") || strings.Contains(out, "very-secret-key-material") {
		t.Error("config check printed a secret")
	}
}

// Every process's problems are printed, each naming its variable.
func TestConfigCheckRefuses(t *testing.T) {
	code, out, errOut := runCtl([]string{"config", "check"}, []string{
		"CISP_MTLS_MODE=sometimes",
		"CISP_DELIVERY_LOG_RETENTION_DAYS=0",
		"CISP_LOG_LEVEL=loud",
	})
	if code != exitConfig || out != "" {
		t.Fatalf("config check = %d %q", code, out)
	}
	for _, want := range []string{
		"api: CISP_MTLS_MODE:",
		"deliver: CISP_DELIVERY_LOG_RETENTION_DAYS:",
		"api: CISP_LOG_LEVEL:", "deliver: CISP_LOG_LEVEL:", "cispctl: CISP_LOG_LEVEL:",
	} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
}

func TestMigrateIsNotImplementedYet(t *testing.T) {
	code, _, errOut := runCtl([]string{"migrate", "relational"}, nil)
	if code != exitNotImplemented || !strings.Contains(errOut, "WP-1") || !strings.Contains(errOut, "nothing was applied") {
		t.Errorf("migrate = %d %q", code, errOut)
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"config"}, {"frobnicate"}, {"version", "extra"}} {
		code, _, errOut := runCtl(args, nil)
		if code != exitUsage || !strings.Contains(errOut, "usage: cispctl") {
			t.Errorf("%q = %d %q", args, code, errOut)
		}
	}
}

func TestPrintProblemsOtherError(t *testing.T) {
	var stderr bytes.Buffer
	if !printProblems(&stderr, "api", errors.New("plain")) || !strings.Contains(stderr.String(), "api: plain") {
		t.Errorf("plain error = %q", stderr.String())
	}
	if printProblems(&stderr, "api", nil) {
		t.Error("nil error reported as a failure")
	}
}

// The binary: exit codes as documented, from a clean environment.
func TestBinary(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH; the in-process tests cover run()")
	}
	bin := filepath.Join(t.TempDir(), "cispctl")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command(goTool, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "CISP_") {
			env = append(env, kv)
		}
	}
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"version"}, exitOK},
		{[]string{"config", "check"}, exitOK},
		{[]string{"migrate"}, exitNotImplemented},
		{nil, exitUsage},
	} {
		cmd := exec.Command(bin, c.args...)
		cmd.Env = env
		err := cmd.Run()
		got := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			got = exitErr.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("cispctl %q exit %d, want %d", c.args, got, c.want)
		}
	}
}
