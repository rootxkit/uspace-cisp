// Command cispctl is the CISP's operations tool. WP-0 ships `version`
// and `config check`; `migrate` answers that it arrives with WP-1. It is
// never long-running and never on the request path.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/rootxkit/uspace-cisp/internal/config"
)

// version is set at build time: -ldflags "-X main.version=<tag or sha>".
var version = "dev"

// Exit codes.
const (
	exitOK             = 0
	exitUsage          = 2
	exitConfig         = 3
	exitNotImplemented = 4
)

const usage = `usage: cispctl <command>

commands:
  version         print the version
  config check    load and validate the api, deliver and cispctl
                  configuration from the CISP_* environment; print every
                  problem, or the redacted effective values
  migrate         apply the migrations (not implemented until WP-1)
`

func main() {
	os.Exit(run(os.Args[1:], os.Environ(), os.Stdout, os.Stderr))
}

func run(args, environ []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 1 && args[0] == "version":
		_, _ = fmt.Fprintln(stdout, version)
		return exitOK
	case len(args) == 2 && args[0] == "config" && args[1] == "check":
		return configCheck(environ, stdout, stderr)
	case len(args) >= 1 && args[0] == "migrate":
		_, _ = fmt.Fprintln(stderr, "cispctl migrate: not implemented until WP-1; nothing was applied")
		return exitNotImplemented
	default:
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
}

type redactor interface {
	Redacted() map[string]string
}

func configCheck(environ []string, stdout, stderr io.Writer) int {
	api, errAPI := config.LoadAPI(environ)
	deliver, errDeliver := config.LoadDeliver(environ)
	ctl, errCtl := config.LoadCtl(environ)

	failed := printProblems(stderr, "api", errAPI)
	failed = printProblems(stderr, "deliver", errDeliver) || failed
	failed = printProblems(stderr, "cispctl", errCtl) || failed
	if failed {
		return exitConfig
	}

	merged := map[string]string{}
	for _, r := range []redactor{api, deliver, ctl} {
		for k, v := range r.Redacted() {
			merged[k] = v
		}
	}
	names := make([]string, 0, len(merged))
	for k := range merged {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		_, _ = fmt.Fprintf(stdout, "%s=%s\n", k, merged[k])
	}
	_, _ = fmt.Fprintln(stdout, "config check: ok")
	return exitOK
}

// printProblems writes every problem of err, prefixed by the process,
// and reports whether there was any.
func printProblems(stderr io.Writer, process string, err error) bool {
	if err == nil {
		return false
	}
	var probs config.FieldErrors
	if errors.As(err, &probs) {
		for _, p := range probs {
			_, _ = fmt.Fprintf(stderr, "%s: %s: %s\n", process, p.Field, p.Reason)
		}
		return true
	}
	_, _ = fmt.Fprintf(stderr, "%s: %v\n", process, err)
	return true
}
