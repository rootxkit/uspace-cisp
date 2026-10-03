//go:build chaos

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLabConformance runs uspace-lab's conformance/cisp/run against the
// chaos stack (tools/conformance.sh starts it when the suite exists;
// docs/PLAN.md sections 10.6, 15 Q47). CONFORMANCE_ENV hands the suite
// the stack's identities: tokens for the authority, the ANSP and a
// reader, and the authority's and the ANSP's publication keys.
func TestLabConformance(t *testing.T) {
	suite := os.Getenv("LAB_CONFORMANCE_SUITE")
	if suite == "" {
		t.Fatal("LAB_CONFORMANCE_SUITE is unset: run this through make conformance, which sets it when the suite exists")
	}
	s := chaosEnv(t)
	authorityPEM := filepath.Join(s.dir, "authority-signing.pem")
	anspPEM := filepath.Join(s.dir, "ansp-signing.pem")
	writePEM(t, authorityPEM, s.authKey)
	writePEM(t, anspPEM, s.anspKey)
	envFile := filepath.Join(s.dir, "conformance.env")
	writeFile(t, envFile, []byte(strings.Join([]string{
		"CISP_AUTHORITY_TOKEN=" + s.authorityToken(t),
		"CISP_ANSP_TOKEN=" + s.token(t, anspID, "localhost", "cis.publish:restrictions", "cis.read"),
		"CISP_READER_TOKEN=" + s.token(t, labClient, "localhost", "cis.read"),
		"CISP_AUTHORITY_SIGNING_KEY_FILE=" + authorityPEM, "CISP_AUTHORITY_SIGNING_KID=" + authorityKID,
		"CISP_ANSP_SIGNING_KEY_FILE=" + anspPEM, "CISP_ANSP_SIGNING_KID=" + anspKID,
		"CISP_JWKS_URL=" + s.apiURL + "/.well-known/jwks.json", "CISP_ISSUER_URL=" + chaosIssuer,
	}, "\n")+"\n"))
	report := os.Getenv("CONFORMANCE_REPORT")
	if report == "" {
		report = t.TempDir()
	}
	cmd := exec.Command(filepath.Join(suite, "run"))
	cmd.Env = append(os.Environ(), "CISP_BASE_URL="+s.apiURL, "CONFORMANCE_ENV="+envFile, "CONFORMANCE_REPORT="+report)
	out, err := cmd.CombinedOutput()
	t.Logf("lab conformance suite %s against %s:\n%s", suite, s.apiURL, tail(string(out), 60))
	if err != nil {
		t.Fatalf("the suite failed: %v (report in %s)", err, report)
	}
}
