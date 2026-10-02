package config

import (
	"strings"
	"testing"
)

// consoleEnv is a configured console with a database.
func consoleEnv(extra ...string) []string {
	return withBase(append([]string{
		"CISP_DATABASE_URL=postgres://db/cisp",
		"CISP_SESSION_KEY_FILE=/run/secrets/session.pem",
		"CISP_CONSOLE_ISSUER=https://cisp.example.test/console",
		"CISP_SECRETS_KEY_FILE=/run/secrets/secrets.key",
	}, extra...)...)
}

// The console is configured by any of its three variables; then all
// three and the database are required, each refusal naming its variable
// (E-01: the configured console beside each one taken away).
func TestConsoleVariables(t *testing.T) {
	api, err := LoadAPI(consoleEnv())
	if err != nil {
		t.Fatalf("a configured console was refused: %v", err)
	}
	if !api.ConsoleConfigured() || api.ConsoleIssuer != "https://cisp.example.test/console" {
		t.Errorf("console = %v %q", api.ConsoleConfigured(), api.ConsoleIssuer)
	}
	none, err := LoadAPI(withBase("CISP_DATABASE_URL=postgres://db/cisp"))
	if err != nil || none.ConsoleConfigured() {
		t.Fatalf("no console variable: %v, configured %v", err, none != nil && none.ConsoleConfigured())
	}
	for _, missing := range []string{EnvSessionKeyFile, EnvConsoleIssuer, EnvSecretsKeyFile, EnvDatabaseURL} {
		env := []string{}
		for _, kv := range consoleEnv() {
			if !strings.HasPrefix(kv, missing+"=") {
				env = append(env, kv)
			}
		}
		_, err := LoadAPI(env)
		probs := problemsOf(t, err)
		if len(probs) != 1 || !strings.Contains(probs[missing], "not set") {
			t.Errorf("without %s: %v", missing, probs)
		}
	}
}

func TestConsoleVariablesRefused(t *testing.T) {
	for name, c := range map[string]struct {
		env   []string
		field string
	}{
		"issuer not a URL": {[]string{"CISP_CONSOLE_ISSUER=console"}, EnvConsoleIssuer},
		"issuer is the token issuer": {
			[]string{"CISP_CONSOLE_ISSUER=" + strings.TrimPrefix(apiBaseValue(EnvTokenIssuer), EnvTokenIssuer+"=")}, EnvConsoleIssuer,
		},
	} {
		_, err := LoadAPI(consoleEnv(c.env...))
		probs := problemsOf(t, err)
		if _, ok := probs[c.field]; !ok || len(probs) != 1 {
			t.Errorf("%s: %v", name, probs)
		}
	}
}

func apiBaseValue(name string) string {
	for _, kv := range apiBase {
		if strings.HasPrefix(kv, name+"=") {
			return kv
		}
	}
	return name + "="
}
