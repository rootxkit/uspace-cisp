package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/jws"
)

const issuer = "https://uspace-cisp.example.test"

type cisp struct {
	srv   *httptest.Server
	ring  *jws.KeyRing
	pulls atomic.Int64
}

// newCISP serves the ring's JWKS and the dataset reads the receiver pulls.
func newCISP(t *testing.T) *cisp {
	t.Helper()
	pemBytes, err := jws.EncodePrivateKeyPEM(authtest.Key(t, "cisp", 3072))
	if err != nil {
		t.Fatal(err)
	}
	ring, err := jws.LoadKeyRing(pemBytes, "cisp-1", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	c := &cisp{ring: ring}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			_, _ = w.Write(ring.JWKS())
			return
		}
		if r.Header.Get("Authorization") == "Bearer tok" {
			c.pulls.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *cisp) receiver(t *testing.T, failFirst int) (*receiver, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	return newReceiver(config{
		jwksURL: c.srv.URL + "/.well-known/jwks.json", issuer: issuer, publicBase: c.srv.URL, audience: "subscriber.example.test",
		token: "tok", failFirst: failFirst,
	}, out), out
}

func signWith(t *testing.T, ring *jws.KeyRing, aud, reason, pullURL string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"schema": "cis/change/v1", "msg_id": "12", "producer": "cisp/deliver-test", "dataset": "zones", "version": 3,
		"etag": `"zones:3"`, "feature_ids": []string{}, "removed_ids": []string{}, "reason": reason,
		"at": time.Now().UTC(), "pull_url": pullURL,
	})
	tok, err := ring.SignCompact(coreauth.CompactClaims{Issuer: issuer, Audience: aud, Subject: "S1", JTI: "D1"}, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func post(r *receiver, token string) int {
	req := httptest.NewRequest(http.MethodPost, "/v1/cis/notifications", strings.NewReader(token))
	req.Header.Set("X-CIS-Delivery-Id", "D1")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

// A notification signed by the CISP for this host is verified and
// answered 204; one signed by another key, or for another host, is
// refused (T4 pair).
func TestVerifies(t *testing.T) {
	c := newCISP(t)
	r, out := c.receiver(t, 0)
	pull := c.srv.URL + "/v1/zones?since_version=2"
	if code := post(r, signWith(t, c.ring, "subscriber.example.test", "subscription_test", pull)); code != http.StatusNoContent {
		t.Fatalf("signed by the CISP = %d %s", code, out)
	}
	pemBytes, _ := jws.EncodePrivateKeyPEM(authtest.Key(t, "impostor", 3072))
	impostor, err := jws.LoadKeyRing(pemBytes, "cisp-1", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if code := post(r, signWith(t, impostor, "subscriber.example.test", "publication", pull)); code != http.StatusUnauthorized {
		t.Errorf("signed by another key = %d", code)
	}
	if code := post(r, signWith(t, c.ring, "other.example.test", "publication", pull)); code != http.StatusUnauthorized {
		t.Errorf("for another host = %d", code)
	}
	recs := r.received()
	if len(recs) != 3 || !recs[0].Verified || recs[1].Verified || !strings.Contains(recs[1].Note, "signature") || recs[2].Verified {
		t.Errorf("records %+v", recs)
	}
	if !strings.Contains(out.String(), `"verified":true`) {
		t.Errorf("stdout %s", out)
	}
}

// subscription_test, republished and an unknown reason are acknowledged
// without a pull; publication and a restriction reason pull; a pull_url
// on another host is refused (E-01 pairs).
func TestPullsOnlyWhatChangesContent(t *testing.T) {
	c := newCISP(t)
	r, _ := c.receiver(t, 0)
	pull := c.srv.URL + "/v1/zones?since_version=2"
	for _, reason := range []string{"subscription_test", "republished", "something_new"} {
		if code := post(r, signWith(t, c.ring, "subscriber.example.test", reason, pull)); code != http.StatusNoContent {
			t.Errorf("%s = %d", reason, code)
		}
	}
	if code := post(r, signWith(t, c.ring, "subscriber.example.test", "publication", "https://elsewhere.example.test/v1/zones")); code != http.StatusNoContent {
		t.Errorf("other host = %d", code)
	}
	if c.pulls.Load() != 0 {
		t.Fatalf("pulled %d times", c.pulls.Load())
	}
	for _, reason := range []string{"publication", "restriction_activated"} {
		post(r, signWith(t, c.ring, "subscriber.example.test", reason, pull))
	}
	r.pulls.Wait()
	if c.pulls.Load() != 2 {
		t.Errorf("pulled %d times, want 2", c.pulls.Load())
	}
	recs := r.received()
	if len(recs) != 6 || recs[3].Note != "pull_url refused: not the CISP's host" || !recs[4].Pulled || !recs[5].Pulled {
		t.Errorf("records %+v", recs)
	}
}

// FAIL_FIRST answers the first n with 500, then verifies as usual.
func TestFailFirst(t *testing.T) {
	c := newCISP(t)
	r, _ := c.receiver(t, 2)
	tok := signWith(t, c.ring, "subscriber.example.test", "subscription_test", c.srv.URL)
	codes := []int{post(r, tok), post(r, tok), post(r, tok)}
	if codes[0] != 500 || codes[1] != 500 || codes[2] != 204 {
		t.Errorf("codes %v", codes)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/received", http.NoBody))
	var recs []record
	if err := json.Unmarshal(rec.Body.Bytes(), &recs); err != nil || len(recs) != 3 {
		t.Errorf("GET /received %s %v", rec.Body.String(), err)
	}
	nf := httptest.NewRecorder()
	r.ServeHTTP(nf, httptest.NewRequest(http.MethodGet, "/other", http.NoBody))
	if nf.Code != http.StatusNotFound {
		t.Errorf("other path = %d", nf.Code)
	}
}
