// Package caddy_test keeps what the reference Caddy snippet says about
// itself true (docs/PLAN.md section 15 Q48).
package caddy_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A comment may say the public surface is cached only when the snippet
// carries a cache directive: stock Caddy has no HTTP cache, and a
// promise of one makes a reader believe the public map is cache-fronted
// (S2). The threat model counts no Caddy cache as a control in place
// either, while the snippet has none.
func TestSnippetPromisesNoCacheItLacks(t *testing.T) {
	raw, err := os.ReadFile("Caddyfile.snippet")
	if err != nil {
		t.Fatal(err)
	}
	var comments, directives []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			comments = append(comments, strings.ToLower(line))
		} else if line != "" {
			directives = append(directives, line)
		}
	}
	hasCache := false
	for _, d := range directives {
		if regexp.MustCompile(`^(cache|souin|cache_handler)\b`).MatchString(d) {
			hasCache = true
		}
	}
	promise := regexp.MustCompile(`\bcached by caddy\b|\bcaddy caches\b`)
	for _, c := range comments {
		if promise.MatchString(c) && !hasCache {
			t.Errorf("the snippet promises a Caddy cache it does not configure: %q", c)
		}
	}
	plan, err := os.ReadFile("../../docs/PLAN.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(plan), "\n") {
		if strings.HasPrefix(line, "| T8 ") && strings.Contains(line, "Caddy cache on the public surface,") && !hasCache {
			t.Errorf("the T8 row counts a Caddy cache the snippet does not configure as a control in place")
		}
	}
}
