//go:build e2e || chaos

package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-cisp/internal/jws"
)

// The helpers both suites use: the e2e suite (processes built from the
// checkout) and the chaos suite (the built images, chaos_*_test.go).

// The identities of the e2e stack.
const (
	tokenIssuer  = "https://authority.e2e.test/"
	cispIssuer   = "https://uspace-cisp.e2e.test"
	authorityID  = "authority-01"
	anspID       = "ansp-01"
	labClient    = "lab-01"
	tokenKID     = "tok-1"
	authorityKID = "authority-sig-1"
	anspKID      = "ansp-sig-1"
	cispKID      = "cisp-e2e-1"
	project      = "uspace-cisp-e2e"
)

type doc = map[string]any

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func secret() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writePEM(t *testing.T, path string, k *rsa.PrivateKey) {
	t.Helper()
	pemBytes, err := jws.EncodePrivateKeyPEM(k)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

// change is one record of GET /v1/changes.
type change struct {
	MsgID   string    `json:"msg_id"`
	Dataset string    `json:"dataset"`
	Version int64     `json:"version"`
	Reason  string    `json:"reason"`
	At      time.Time `json:"at"`
}

// received is one record of the subscriber's GET /received.
type received struct {
	ReceivedAt time.Time `json:"received_at"`
	DeliveryID string    `json:"delivery_id"`
	ChangeID   string    `json:"change_id"`
	Reason     string    `json:"reason"`
	Verified   bool      `json:"verified"`
	Pulled     bool      `json:"pulled"`
	Note       string    `json:"note"`
}

func eventually(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("not within %s: %s", within, what)
}

// zonesBody is the vector's authority collection without its U-space
// airspace, its first zone named n (a new version each time).
func zonesBody(t *testing.T, n int) []byte {
	t.Helper()
	d := vectorDoc(t)
	feats := d["features"].([]any)
	d["features"] = feats[1:]
	p := feats[1].(doc)["properties"].(doc)
	p["reason"] = []any{"EMERGENCY"}
	p["name"] = []any{doc{"lang": "en-GB", "text": fmt.Sprintf("e2e zone, publication %d", n)}}
	raw, _ := json.Marshal(d)
	return raw
}

// uspaceBody is the vector's U-space airspace TSU001 with its
// requirements block.
func uspaceBody(t *testing.T) []byte {
	t.Helper()
	d := vectorDoc(t)
	d["features"] = d["features"].([]any)[:1]
	p := d["features"].([]any)[0].(doc)["properties"].(doc)
	ext, _ := p["extendedProperties"].(doc)
	if ext == nil {
		ext = doc{}
		p["extendedProperties"] = ext
	}
	ext["uspace_requirements"] = doc{
		"uas_requirements": doc{}, "operational_conditions": doc{}, "airspace_constraints": doc{},
		"service_performance": doc{"nid_update_hz": 1, "ti_update_hz": 1, "cis_latency_s": 5},
		"services_required":   []any{"NID", "GEO", "FA", "TI"}, "adjacent": []any{},
	}
	raw, _ := json.Marshal(d)
	return raw
}

func vectorDoc(t *testing.T) doc {
	t.Helper()
	f := vectors.Load(t, "ed318_roundtrip.json")
	for _, c := range f.Cases {
		if c.Name != "accept-authority-collection" {
			continue
		}
		var in struct {
			Document doc `json:"document"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatal(err)
		}
		return in.Document
	}
	t.Fatal("no accept-authority-collection case")
	return nil
}

// percentile is the p-th percentile (nearest rank) of ds.
func percentile(ds []time.Duration, p float64) time.Duration {
	s := append([]time.Duration{}, ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(p*float64(len(s))+0.999999) - 1
	return s[max(0, min(idx, len(s)-1))]
}

// summary appends markdown to the CI step summary when there is one.
func summary(t *testing.T, md string) {
	t.Helper()
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Logf("step summary: %v", err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(md + "\n")
}

// composeEnv is the test's environment without the variables the env
// file sets: compose prefers the shell's value of a variable to the env
// file's, so a developer's exported dev passwords would win over the
// ones the test generated.
func composeEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "E2E_") || strings.HasPrefix(name, "CHAOS_") || strings.HasPrefix(name, "PG_CISP_") || name == "POSTGRES_PASSWORD" {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// bigZones is a zone set of polygons with vertices vertices each, as
// many as fit under maxBytes (the shape that costs the api the most
// memory per byte: BenchmarkPutPublicationPeakHeap "vertices"), its
// first zone named n so each call is a new version. Identifiers are
// "B" and five base-36 digits.
func bigZones(t *testing.T, n, vertices, maxBytes int) []byte {
	t.Helper()
	const latDeg, lonDeg, stepDeg, radiusDeg = 41.60, 44.65, 0.004, 0.0015
	feature := func(i int) doc {
		cols := 200
		cLat, cLon := latDeg+float64(i/cols)*stepDeg, lonDeg+float64(i%cols)*stepDeg
		ring := make([]any, 0, vertices+1)
		for k := range vertices {
			a := 2 * math.Pi * float64(k) / float64(vertices)
			ring = append(ring, []any{math.Round((cLon+radiusDeg*math.Cos(a))*1e7) / 1e7, math.Round((cLat+radiusDeg*math.Sin(a))*1e7) / 1e7})
		}
		ring = append(ring, ring[0])
		b36 := strings.ToUpper(strconvBase36(i))
		id := "B" + strings.Repeat("0", max(0, 5-len(b36))) + b36
		return doc{
			"type": "Feature",
			"geometry": doc{
				"type": "Polygon", "coordinates": []any{ring},
				"layer": doc{"lower": 0, "lowerReference": "AGL", "upper": 120, "upperReference": "AGL", "uom": "m"},
			},
			"properties": doc{
				"identifier": id, "country": "GEO", "type": "PROHIBITED", "variant": "COMMON", "reason": []any{"SENSITIVE"},
				"name":          []any{doc{"lang": "en-GB", "text": fmt.Sprintf("Chaos zone %s, publication %d", id, n)}},
				"zoneAuthority": []any{doc{"name": []any{doc{"lang": "en-GB", "text": "Test authority"}}, "purpose": "AUTHORIZATION"}},
			},
		}
	}
	one, _ := json.Marshal(feature(0))
	count := max(1, maxBytes/(len(one)+1)-1)
	for {
		fs := make([]any, count)
		for i := range fs {
			fs[i] = feature(i)
		}
		body, err := json.Marshal(doc{"type": "FeatureCollection", "features": fs})
		if err != nil {
			t.Fatal(err)
		}
		if len(body) <= maxBytes {
			return body
		}
		count -= max(1, (len(body)-maxBytes)/len(one)+1)
	}
}

func strconvBase36(i int) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if i == 0 {
		return "0"
	}
	var out []byte
	for ; i > 0; i /= 36 {
		out = append([]byte{digits[i%36]}, out...)
	}
	return string(out)
}

// uspaceBodyN is uspaceBody with its name naming n (a new version).
func uspaceBodyN(t *testing.T, n int) []byte {
	t.Helper()
	var d doc
	if err := json.Unmarshal(uspaceBody(t), &d); err != nil {
		t.Fatal(err)
	}
	p := d["features"].([]any)[0].(doc)["properties"].(doc)
	p["name"] = []any{doc{"lang": "en-GB", "text": fmt.Sprintf("U-space airspace, publication %d", n)}}
	raw, _ := json.Marshal(d)
	return raw
}
