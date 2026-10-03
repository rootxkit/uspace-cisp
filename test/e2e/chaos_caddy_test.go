//go:build chaos

package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
)

// basemapBytes is the size of the test tile on the basemap volume.
const basemapBytes = 256 << 10

// startEdge brings up the caddy profile: api-edge, echo and the two
// edges running deploy/caddy/Caddyfile.snippet, and trusts each edge's
// internal CA.
func (s *chaosStack) startEdge(t *testing.T) {
	t.Helper()
	s.edgeOnce.Do(func() {
		tile := make([]byte, basemapBytes)
		_, _ = rand.Read(tile)
		writeFile(t, filepath.Join(s.dir, "basemap", "tile.bin"), tile)
		s.compose(t, "up", "-d", "--wait", "api-edge", "echo", "edge", "edge-echo")
		s.edgeRoots = x509.NewCertPool()
		for _, svc := range []string{"edge", "edge-echo"} {
			var root string
			eventually(t, 30*time.Second, svc+"'s internal CA root", func() bool {
				out, err := s.composeErr("exec", "-T", svc, "cat", "/data/caddy/pki/authorities/local/root.crt")
				root = out
				return err == nil && strings.Contains(out, "BEGIN CERTIFICATE")
			})
			if !s.edgeRoots.AppendCertsFromPEM([]byte(root)) {
				t.Fatalf("%s: root not PEM", svc)
			}
		}
		s.edgeOK = true
	})
	if !s.edgeOK {
		t.Fatal("the caddy profile did not start")
	}
}

// edgeClient is a client of the edges, presenting cert when not nil.
func (s *chaosStack) edgeClient(cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{RootCAs: s.edgeRoots, MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// restrictionBody is an active restriction in TSU001, signed by the ANSP.
func (s *chaosStack) restrictionBody(t *testing.T, n int) ([]byte, map[string]string) {
	t.Helper()
	starts := time.Now().UTC().Truncate(time.Second)
	ends := starts.Add(time.Hour)
	id := fmt.Sprintf("DAR%04d", (time.Now().UnixMilli()+int64(n))%10000)
	body, _ := json.Marshal(doc{
		"ansp_ref": fmt.Sprintf("chaos-%s-%d", id, n), "ansp_version": 1, "uspace_airspace_id": "TSU001", "state": "active",
		"starts_at": starts.Format(time.RFC3339), "ends_at": ends.Format(time.RFC3339),
		"feature": doc{
			"type": "Feature",
			"geometry": doc{
				"type":        "Polygon",
				"coordinates": []any{[]any{[]any{44.80, 41.70}, []any{44.82, 41.70}, []any{44.82, 41.72}, []any{44.80, 41.72}, []any{44.80, 41.70}}},
				"layer":       doc{"lower": 0, "lowerReference": "AGL", "upper": 120, "upperReference": "AGL", "uom": "m"},
			},
			"properties": doc{
				"identifier": id, "country": "GEO", "type": "PROHIBITED", "variant": "COMMON", "reason": []any{"DAR"},
				"name":                 []any{doc{"lang": "en-GB", "text": "chaos dynamic restriction"}},
				"limitedApplicability": []any{doc{"startDateTime": starts.Format(time.RFC3339), "endDateTime": ends.Format(time.RFC3339)}},
				"zoneAuthority":        []any{doc{"name": []any{doc{"lang": "en-GB", "text": "chaos ANSP"}}, "purpose": "NOTIFICATION"}},
			},
		},
	})
	return body, map[string]string{"X-JWS-Signature": s.signAs(t, s.anspKey, anspKID, body)}
}

func problemType(raw []byte) string {
	var p gen.Problem
	_ = json.Unmarshal(raw, &p)
	return p.Type
}

// TestCaddyProfile runs deploy/caddy/Caddyfile.snippet, the reference
// copy uspace-deploy composes (D1), in front of an api in production's
// mTLS mode, and checks each promise the snippet makes (docs/PLAN.md
// sections 8.3, 11). A difference from the deployment repository's real
// Caddyfile is a finding for the owner, not something fixed here.
func TestCaddyProfile(t *testing.T) {
	s := chaosEnv(t)
	s.startEdge(t)
	if s.etag(t, "uspace_airspace") == `"uspace_airspace:0"` {
		s.publish(t, "uspace_airspace", uspaceBodyN(t, 0))
	}
	if s.etag(t, "zones") == `"zones:0"` {
		s.publish(t, "zones", zonesBody(t, 0))
	}
	plain := s.edgeClient(nil)
	var findings []string

	t.Run("metrics not routed", func(t *testing.T) {
		resp, raw, err := s.do(t, plain, http.MethodGet, s.edgeURL+"/metrics", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		direct, _, err := s.do(t, nil, http.MethodGet, s.apiEdgeURL+"/metrics", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		line := fmt.Sprintf("GET %s/metrics -> %d %q (Server %q); the same path on api-edge directly -> %d",
			s.edgeURL, resp.StatusCode, string(raw), resp.Header.Get("Server"), direct.StatusCode)
		t.Log(line)
		summary(t, "### Caddy: /metrics\n\n```\n"+line+"\n```\n")
		if resp.StatusCode != http.StatusNotFound || len(raw) != 0 || resp.Header.Get("Server") != "Caddy" {
			t.Errorf("edge /metrics = %d %q from %q, want Caddy's empty 404", resp.StatusCode, raw, resp.Header.Get("Server"))
		}
		if direct.StatusCode != http.StatusOK {
			t.Errorf("api-edge /metrics = %d: the 404 above proves nothing unless the api serves it", direct.StatusCode)
		}
	})

	t.Run("public GET and the cache", func(t *testing.T) {
		// api-edge learns of the version by its own refresh; HEAD has its
		// own bucket, so waiting costs the GET bucket nothing.
		eventually(t, 30*time.Second, "api-edge serves zones", func() bool {
			resp, _, err := s.do(t, plain, http.MethodHead, s.edgeURL+"/public/v1/zones", "", nil, nil)
			return err == nil && resp.StatusCode == http.StatusOK
		})
		var rows [][]string
		var second *http.Response
		for i := range 2 {
			resp, raw, err := s.do(t, plain, http.MethodGet, s.edgeURL+"/public/v1/zones", "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK || len(raw) == 0 {
				t.Fatalf("GET %d = %d", i+1, resp.StatusCode)
			}
			rows = append(rows, []string{strconv.Itoa(i + 1), strconv.Itoa(resp.StatusCode), resp.Header.Get("Cache-Control"),
				resp.Header.Get("ETag"), resp.Header.Get("Age"), resp.Header.Get("Cache-Status")})
			second = resp
		}
		tab := table([]string{"request", "status", "Cache-Control", "ETag", "Age", "Cache-Status"}, rows)
		t.Logf("\n%s", tab)
		if !strings.HasPrefix(second.Header.Get("Cache-Control"), "public, max-age=") {
			t.Errorf("Cache-Control through the edge = %q, want the api's public max-age", second.Header.Get("Cache-Control"))
		}
		cached := second.Header.Get("Age") != "" || strings.Contains(strings.ToLower(second.Header.Get("Cache-Status")), "hit")
		note := "the second GET was served from Caddy's cache."
		if !cached {
			note = "FINDING: the second GET was not served from a Caddy cache (no Age, no Cache-Status hit): the snippet has no cache directive and stock Caddy has no HTTP cache, so the public surface is cached only by clients honouring the api's Cache-Control (docs/PLAN.md section 15 Q48)."
			findings = append(findings, note)
		}
		t.Log(note)
		summary(t, "### Caddy: public GET twice\n\n"+tab+"\n"+note+"\n")
	})

	t.Run("basemap with ranges and a long cache", func(t *testing.T) {
		want, err := os.ReadFile(filepath.Join(s.dir, "basemap", "tile.bin"))
		if err != nil {
			t.Fatal(err)
		}
		resp, raw, err := s.do(t, plain, http.MethodGet, s.edgeURL+"/basemap/tile.bin", "", nil, map[string]string{"Range": "bytes=100-199"})
		if err != nil {
			t.Fatal(err)
		}
		full, fullRaw, err := s.do(t, plain, http.MethodGet, s.edgeURL+"/basemap/tile.bin", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		line := fmt.Sprintf("Range bytes=100-199 -> %d, Content-Range %q, %d bytes, Cache-Control %q; no Range -> %d, %d bytes, Accept-Ranges %q",
			resp.StatusCode, resp.Header.Get("Content-Range"), len(raw), resp.Header.Get("Cache-Control"), full.StatusCode, len(fullRaw), full.Header.Get("Accept-Ranges"))
		t.Log(line)
		summary(t, "### Caddy: /basemap/\n\n```\n"+line+"\n```\n")
		if resp.StatusCode != http.StatusPartialContent || resp.Header.Get("Content-Range") != fmt.Sprintf("bytes 100-199/%d", basemapBytes) || !bytes.Equal(raw, want[100:200]) {
			t.Errorf("range: %s", line)
		}
		if full.StatusCode != http.StatusOK || !bytes.Equal(fullRaw, want) || full.Header.Get("Accept-Ranges") != "bytes" {
			t.Errorf("full: %s", line)
		}
		if cc := full.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=86400") {
			t.Errorf("Cache-Control = %q, want a day", cc)
		}
	})

	t.Run("the ANSP route without a certificate is refused by api", func(t *testing.T) {
		tok := s.token(t, anspID, "localhost", "cis.publish:restrictions", "cis.read")
		body, h := s.restrictionBody(t, 1)
		resp, raw, err := s.do(t, plain, http.MethodPost, s.edgeURL+"/v1/restrictions", tok, body, h)
		if err != nil {
			t.Fatal(err)
		}
		withCert, rawCert, err := s.do(t, s.edgeClient(&s.anspCert), http.MethodPost, s.edgeURL+"/v1/restrictions", tok, body, h)
		if err != nil {
			t.Fatal(err)
		}
		line := fmt.Sprintf("POST /v1/restrictions without a client certificate -> %d %s; with the ANSP's -> %d", resp.StatusCode, problemType(raw), withCert.StatusCode)
		t.Log(line)
		summary(t, "### Caddy: the ANSP route\n\n```\n"+line+"\n```\n")
		if resp.StatusCode != http.StatusForbidden || !strings.HasSuffix(problemType(raw), "/mtls_required") {
			t.Errorf("without a certificate: %d %s", resp.StatusCode, raw)
		}
		if withCert.StatusCode != http.StatusCreated {
			t.Errorf("with the ANSP's certificate: %d %s", withCert.StatusCode, rawCert)
		}
	})

	t.Run("a forged subject header never reaches the upstream", func(t *testing.T) {
		tok := s.token(t, anspID, "localhost", "cis.publish:restrictions", "cis.read")
		forged := map[string]string{"X-Client-Cert-Subject": s.anspSubject}
		var rows [][]string
		// api-edge: the forged subject is the configured one, so it would
		// pass the binding if it arrived.
		for _, c := range []struct {
			name string
			cert *tls.Certificate
		}{{"no certificate", nil}, {"the impostor's certificate", &s.impostor}} {
			body, h := s.restrictionBody(t, 2+len(rows))
			h["X-Client-Cert-Subject"] = s.anspSubject
			resp, raw, err := s.do(t, s.edgeClient(c.cert), http.MethodPost, s.edgeURL+"/v1/restrictions", tok, body, h)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, []string{"api-edge", "POST /v1/restrictions", c.name, strconv.Itoa(resp.StatusCode) + " " + problemType(raw)})
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s with a forged subject: %d %s", c.name, resp.StatusCode, raw)
			}
		}
		// echo: what reaches the upstream, on every route class.
		paths := []string{"/v1/restrictions", "/v1/restrictions/DAR0001", "/v1/publishers/heartbeat", "/v1/zones",
			"/v1/stream", "/public/v1/zones", "/.well-known/jwks.json", "/healthz", "/_bff/api/v1/console/me", "/"}
		mtls := map[string]bool{"/v1/restrictions": true, "/v1/restrictions/DAR0001": true, "/v1/publishers/heartbeat": true}
		for _, path := range paths {
			for _, c := range []struct {
				name string
				cert *tls.Certificate
				want string
			}{{"no certificate", nil, ""}, {"the impostor's certificate", &s.impostor, s.impostor.Leaf.Subject.String()},
				{"the ANSP's certificate", &s.anspCert, s.anspSubject}} {
				resp, raw, err := s.do(t, s.edgeClient(c.cert), http.MethodGet, s.edgeEchoURL+path, "", nil, forged)
				if err != nil {
					t.Fatal(err)
				}
				got := strings.TrimSuffix(strings.TrimPrefix(strings.SplitN(string(raw), "] ", 2)[0], "subject=["), "]")
				want := ""
				if mtls[path] {
					want = c.want
				}
				rows = append(rows, []string{"echo", "GET " + path, c.name, fmt.Sprintf("%d, subject %q", resp.StatusCode, got)})
				if resp.StatusCode != http.StatusOK || got != want {
					t.Errorf("echo %s with %s and a forged header: %d %q, want subject %q", path, c.name, resp.StatusCode, raw, want)
				}
			}
		}
		tab := table([]string{"upstream", "request (X-Client-Cert-Subject forged)", "client", "reached"}, rows)
		t.Logf("\n%s", tab)
		summary(t, "### Caddy: forged X-Client-Cert-Subject\n\n"+tab)
	})

	t.Run("the public rate limit holds behind the edge", func(t *testing.T) {
		var codes []string
		first429 := 0
		var retry string
		for i := 1; i <= 40 && first429 == 0; i++ {
			// A different forged X-Forwarded-For each time: the edge
			// replaces it, so the client stays one bucket.
			resp, _, err := s.do(t, plain, http.MethodGet, s.edgeURL+"/public/v1/zones", "", nil,
				map[string]string{"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i)})
			if err != nil {
				t.Fatal(err)
			}
			codes = append(codes, strconv.Itoa(resp.StatusCode))
			if resp.StatusCode == http.StatusTooManyRequests {
				first429, retry = i, resp.Header.Get("Retry-After")
			}
		}
		line := fmt.Sprintf("GET /public/v1/zones with a new forged X-Forwarded-For each time: %s (first 429 at request %d, Retry-After %q; CISP_PUBLIC_RPM=60, burst 10)",
			strings.Join(codes, " "), first429, retry)
		t.Log(line)
		summary(t, "### Caddy: rate limit\n\n```\n"+line+"\n```\n")
		if codes[0] != "200" || first429 == 0 || retry == "" {
			t.Errorf("%s", line)
		}
	})

	if len(findings) > 0 {
		summary(t, "### Caddy findings for the owner\n\n- "+strings.Join(findings, "\n- ")+"\n")
	}
}
