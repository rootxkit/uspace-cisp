//go:build integration

package main

import (
	"os"
	"strings"
	"testing"
)

func testEnv(t *testing.T) []string {
	t.Helper()
	db, ts := os.Getenv("CISP_TEST_DATABASE_URL"), os.Getenv("CISP_TEST_TIMESERIES_URL")
	if db == "" || ts == "" {
		t.Fatal("CISP_TEST_DATABASE_URL and CISP_TEST_TIMESERIES_URL must be set; run make dev-deps")
	}
	return []string{"CISP_DATABASE_URL=" + db, "CISP_TIMESERIES_URL=" + ts}
}

// migrate prints what it applied and the applied versions; --down-to
// prints what it rolled back and what is pending; status lists both.
func TestMigrateBothTrees(t *testing.T) {
	env := testEnv(t)
	for _, c := range []struct {
		tree, last, versions string
		down                 string
	}{
		{"relational", "0007_publisher_heartbeat.sql", "1, 2, 3, 4, 5, 6, 7", "6"},
		{"timeseries", "0002_delivery_attempts.sql", "1, 2", "1"},
	} {
		t.Run(c.tree, func(t *testing.T) {
			code, out, errOut := runCtl([]string{"migrate", c.tree}, env)
			if code != exitOK || !strings.Contains(out, c.tree+": applied versions "+c.versions+"; nothing pending") {
				t.Fatalf("migrate = %d %q %q", code, out, errOut)
			}
			code, out, _ = runCtl([]string{"migrate", c.tree, "--down-to", c.down}, env)
			if code != exitOK || !strings.Contains(out, "rolled back "+c.last) || !strings.Contains(out, "pending "+c.last) {
				t.Fatalf("down = %d %q", code, out)
			}
			code, out, _ = runCtl([]string{"migrate", "status", c.tree}, env)
			if code != exitOK || !strings.Contains(out, c.last+" pending") || !strings.Contains(out, "0001_init.sql applied") {
				t.Errorf("status = %d %q", code, out)
			}
			code, out, _ = runCtl([]string{"migrate", c.tree}, env)
			if code != exitOK || !strings.Contains(out, "applied "+c.last) || !strings.Contains(out, "nothing pending") {
				t.Fatalf("up again = %d %q", code, out)
			}
			t.Log(strings.TrimSpace(out))
		})
	}
}

// The relational tree against the timeseries database is refused.
func TestMigrateRefusesTheWrongDatabase(t *testing.T) {
	env := testEnv(t)
	wrong := []string{"CISP_DATABASE_URL=" + strings.TrimPrefix(env[1], "CISP_TIMESERIES_URL=")}
	code, _, errOut := runCtl([]string{"migrate", "relational"}, wrong)
	if code != exitFailed || !strings.Contains(errOut, "other migration tree") {
		t.Errorf("migrate = %d %q", code, errOut)
	}
}

func TestSetRetentionAndRebuildCurrent(t *testing.T) {
	env := testEnv(t)
	code, out, errOut := runCtl([]string{"set-retention", "--days", "45"}, env)
	if code != exitOK || !strings.Contains(out, "policy_retention") || !strings.Contains(out, `"45 days"`) || !strings.Contains(out, "policy_compression") {
		t.Fatalf("set-retention = %d %q %q", code, out, errOut)
	}
	if code, _, _ := runCtl([]string{"set-retention"}, env); code != exitOK {
		t.Errorf("set-retention back to 90 = %d", code)
	}
	code, out, errOut = runCtl([]string{"rebuild-current", "--dataset", "zones"}, env)
	if code != exitOK || !strings.Contains(out, "zones version ") || !strings.Contains(out, "rows before") {
		t.Errorf("rebuild-current = %d %q %q", code, out, errOut)
	}
	t.Log(strings.TrimSpace(out))
	code, _, errOut = runCtl([]string{"rebuild-current", "--dataset", "restrictions"}, env)
	if code != exitFailed || !strings.Contains(errOut, "nothing was changed") {
		t.Errorf("rebuild-current restrictions = %d %q", code, errOut)
	}
}
