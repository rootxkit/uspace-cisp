package main

import (
	"bytes"
	"context"
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
	code := run(context.Background(), args, env, &stdout, &stderr)
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
		"CISP_TOKEN_ISSUER=https://authority.example.test/",
		"CISP_TOKEN_JWKS_URL=https://authority.example.test/.well-known/jwks.json",
		"CISP_AUDIENCES=uspace-cisp.example.test",
		"CISP_ANSP_MTLS_SUBJECT=CN=ansp-01",
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

// Without a database: every refusal names what is wrong and exits with
// its code, before anything connects.
func TestDatabaseCommandsRefuseWithoutADatabase(t *testing.T) {
	unreachable := []string{"CISP_DATABASE_URL=postgres://u:p@127.0.0.1:1/cisp?connect_timeout=1", "CISP_TIMESERIES_URL=postgres://u:p@127.0.0.1:1/cisp_ts?connect_timeout=1"}
	cases := []struct {
		args []string
		env  []string
		code int
		want string
	}{
		{[]string{"migrate", "both"}, nil, exitUsage, "unknown migration tree"},
		{[]string{"migrate", "relational", "--down-to"}, nil, exitUsage, "usage"},
		{[]string{"migrate", "relational", "extra"}, nil, exitUsage, "usage"},
		{[]string{"migrate", "status", "both"}, nil, exitUsage, "unknown migration tree"},
		{[]string{"migrate", "relational"}, nil, exitConfig, "CISP_DATABASE_URL is not set"},
		{[]string{"migrate", "timeseries"}, nil, exitConfig, "CISP_TIMESERIES_URL is not set"},
		{[]string{"migrate", "status", "relational"}, nil, exitConfig, "CISP_DATABASE_URL is not set"},
		{[]string{"migrate", "relational"}, []string{"CISP_DATABASE_URL=postgres://db/cisp?pool_max_conns=many"}, exitConfig, "does not parse"},
		{[]string{"migrate", "relational"}, []string{"CISP_LOG_LEVEL=loud"}, exitConfig, "CISP_LOG_LEVEL"},
		{[]string{"migrate", "relational"}, unreachable, exitFailed, "migrate relational"},
		{[]string{"migrate", "status", "timeseries"}, unreachable, exitFailed, "migrate timeseries"},
		{[]string{"rebuild-current"}, nil, exitUsage, "usage"},
		{[]string{"rebuild-current", "--dataset", "geo_zones"}, nil, exitUsage, "not a dataset"},
		{[]string{"rebuild-current", "--dataset", "zones"}, nil, exitConfig, "CISP_DATABASE_URL is not set"},
		{[]string{"rebuild-current", "--dataset", "zones"}, unreachable, exitFailed, "nothing was changed"},
		{[]string{"set-retention", "--days", "0"}, nil, exitUsage, "outside 1..3650"},
		{[]string{"set-retention", "--days", "x"}, nil, exitUsage, "usage"},
		{[]string{"set-retention"}, nil, exitConfig, "CISP_TIMESERIES_URL is not set"},
		{[]string{"set-retention", "--days", "30"}, unreachable, exitFailed, "set retention"},
	}
	for _, c := range cases {
		code, out, errOut := runCtl(c.args, c.env)
		if code != c.code || !strings.Contains(errOut, c.want) {
			t.Errorf("%q = %d, want %d with %q; stdout %q stderr %q", c.args, code, c.code, c.want, out, errOut)
		}
		if strings.Contains(errOut, ":p@") {
			t.Errorf("%q printed a database password: %s", c.args, errOut)
		}
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
	// The variables of the api that have no default (config check
	// validates every process).
	env = append(env, "CISP_TOKEN_ISSUER=https://authority.example.test/",
		"CISP_TOKEN_JWKS_URL=https://authority.example.test/.well-known/jwks.json",
		"CISP_AUDIENCES=uspace-cisp.example.test", "CISP_ANSP_MTLS_SUBJECT=CN=ansp-01")
	for _, c := range []struct {
		args []string
		want int
	}{
		{[]string{"version"}, exitOK},
		{[]string{"config", "check"}, exitOK},
		{[]string{"migrate"}, exitUsage},
		{[]string{"migrate", "relational"}, exitConfig},
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
