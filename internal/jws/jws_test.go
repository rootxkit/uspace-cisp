package jws_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func pemOf(t testing.TB, k *rsa.PrivateKey) []byte {
	t.Helper()
	b, err := jws.EncodePrivateKeyPEM(k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ring(t testing.TB, cur string, prev string) *jws.KeyRing {
	t.Helper()
	var prevPEM []byte
	if prev != "" {
		prevPEM = pemOf(t, authtest.Key(t, prev, 3072))
	}
	r, err := jws.LoadKeyRing(pemOf(t, authtest.Key(t, cur, 3072)), cur, prevPEM, prev)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func setOf(t testing.TB, raw []byte) jwk.Set {
	t.Helper()
	s, err := jwk.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func verifier(t testing.TB, publisher string, set jwk.Set, maxSkew time.Duration, now time.Time) *jws.DetachedVerifier {
	t.Helper()
	v, err := jws.NewDetachedVerifier(context.Background(), jws.KeySource{Publisher: publisher, Keys: coreauth.IssuerConfig{Keys: set}},
		maxSkew, jws.Options{MaxPayloadBytes: 32 << 20, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func refusal(t *testing.T, err error) *coreauth.TokenError {
	t.Helper()
	var te *coreauth.TokenError
	if !errors.As(err, &te) {
		t.Fatalf("error %v (%T) is not a *TokenError", err, err)
	}
	return te
}

// Key ring: the 3072-bit floor, a missing kid and a duplicate kid are
// refused beside the ring that loads.
func TestLoadKeyRingRefusals(t *testing.T) {
	good := pemOf(t, authtest.Key(t, "a", 3072))
	short := pemOf(t, authtest.Key(t, "short", 2048))
	if _, err := jws.LoadKeyRing(good, "k1", nil, ""); err != nil {
		t.Fatalf("a 3072-bit key was refused: %v", err)
	}
	cases := map[string]struct {
		cur, prev       []byte
		curKID, prevKID string
		field           string
	}{
		"current shorter than 3072":  {short, nil, "k1", "", "current.key"},
		"previous shorter than 3072": {good, short, "k1", "k0", "previous.key"},
		"current kid missing":        {good, nil, "", "", "current.kid"},
		"previous kid missing":       {good, good, "k1", "", "previous.kid"},
		"previous key missing":       {good, nil, "k1", "k0", "previous.key"},
		"duplicate kid":              {good, pemOf(t, authtest.Key(t, "b", 3072)), "k1", "k1", "previous.kid"},
		"not PEM":                    {[]byte("no key here"), nil, "k1", "", "current.key"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := jws.LoadKeyRing(c.cur, c.curKID, c.prev, c.prevKID)
			var fe *core.FieldError
			if !errors.As(err, &fe) || fe.Field != c.field {
				t.Fatalf("err = %v, want a refusal on %s", err, c.field)
			}
		})
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	k := authtest.Key(t, "a", 3072)
	pkcs1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if got, err := jws.ParsePrivateKeyPEM(pkcs1); err != nil || got.N.Cmp(k.N) != 0 {
		t.Errorf("PKCS#1: %v", err)
	}
	if got, err := jws.ParsePrivateKeyPEM(pemOf(t, k)); err != nil || got.N.Cmp(k.N) != 0 {
		t.Errorf("PKCS#8: %v", err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string][]byte{
		"EC key":         pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		"public key":     pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}),
		"broken PKCS#8":  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2}}),
		"broken PKCS#1":  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2}}),
		"no PEM at all":  []byte("x"),
		"empty":          nil,
		"truncated PEM":  pemOf(t, k)[:40],
		"another header": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
	}
	for name, raw := range refused {
		if _, err := jws.ParsePrivateKeyPEM(raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestReadKeyRing(t *testing.T) {
	dir := t.TempDir()
	cur, prev := filepath.Join(dir, "cur.pem"), filepath.Join(dir, "prev.pem")
	if err := os.WriteFile(cur, pemOf(t, authtest.Key(t, "a", 3072)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(prev, pemOf(t, authtest.Key(t, "b", 3072)), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := jws.ReadKeyRing(cur, "k2", prev, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.KIDs(), ","); got != "k2,k1" || r.ActiveKID() != "k2" {
		t.Errorf("kids = %s, active %s", got, r.ActiveKID())
	}
	if r, err := jws.ReadKeyRing(cur, "k2", "", ""); err != nil || len(r.KIDs()) != 1 {
		t.Errorf("without a previous key: %v", err)
	}
	big := filepath.Join(dir, "big.pem")
	if err := os.WriteFile(big, bytes.Repeat([]byte("A"), 70<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][4]string{
		"missing current":  {filepath.Join(dir, "none.pem"), "k2", "", ""},
		"missing previous": {cur, "k2", filepath.Join(dir, "none.pem"), "k1"},
		"oversized file":   {big, "k2", "", ""},
	} {
		if _, err := jws.ReadKeyRing(args[0], args[1], args[2], args[3]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The JWKS carries both kids during a rotation, with alg RS256 and use
// sig, and no private member; the ETag is strong and changes with it.
func TestJWKSCarriesBothKIDs(t *testing.T) {
	r := ring(t, "k2", "k1")
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(r.JWKS(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Keys) != 2 || doc.Keys[0]["kid"] != "k2" || doc.Keys[1]["kid"] != "k1" {
		t.Fatalf("keys = %v", doc.Keys)
	}
	for _, k := range doc.Keys {
		if k["alg"] != "RS256" || k["use"] != "sig" || k["kty"] != "RSA" {
			t.Errorf("key %v", k)
		}
		for _, private := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if _, ok := k[private]; ok {
				t.Errorf("the JWKS publishes the private member %s", private)
			}
		}
	}
	if e := r.ETag(); !strings.HasPrefix(e, `"`) || !strings.HasSuffix(e, `"`) || strings.HasPrefix(e, "W/") {
		t.Errorf("ETag %s is not a strong entity tag", e)
	}
	if ring(t, "k2", "").ETag() == r.ETag() {
		t.Error("a different key set has the same ETag")
	}
	if ring(t, "k2", "k1").ETag() != r.ETag() {
		t.Error("the same key set has another ETag")
	}
}

// Rotation: a body signed by the previous key still verifies against the
// rotated ring's JWKS; once that key leaves the ring it is refused.
func TestRotationOverlap(t *testing.T) {
	body := []byte(`{"type":"FeatureCollection","features":[]}`)
	old := ring(t, "k1", "")
	sig, err := old.SignDetached(body, t0)
	if err != nil {
		t.Fatal(err)
	}
	rotated := ring(t, "k2", "k1")
	if _, err := verifier(t, "authority-01", setOf(t, rotated.JWKS()), 5*time.Minute, t0).Verify(context.Background(), sig, body); err != nil {
		t.Errorf("the previous key no longer verifies during the overlap: %v", err)
	}
	newSig, err := rotated.SignDetached(body, t0)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := coreauth.ParseDetachedHeader(newSig); err != nil || h.KID != "k2" {
		t.Errorf("the rotated ring signs with %q, want k2 (%v)", h.KID, err)
	}
	retired := ring(t, "k2", "")
	_, err = verifier(t, "authority-01", setOf(t, retired.JWKS()), 5*time.Minute, t0).Verify(context.Background(), sig, body)
	if te := refusal(t, err); te.Counter != coreauth.CounterRejectedKID {
		t.Errorf("a key no longer in the ring: %s, want rejected_kid", te.Counter)
	}
}

func TestSignCompact(t *testing.T) {
	r := ring(t, "k1", "")
	tok, err := r.SignCompact(coreauth.CompactClaims{Issuer: "https://cisp.example.test/", Audience: "ussp.example.test", Subject: "sub-1", JTI: "d-1"},
		json.RawMessage(`{"schema":"cis/change/v1"}`), t0)
	if err != nil || strings.Count(tok, ".") != 2 {
		t.Fatalf("SignCompact = %q, %v", tok, err)
	}
	cv, err := coreauth.NewCompactVerifier(context.Background(), coreauth.CompactConfig{
		Issuers:   map[string]coreauth.IssuerConfig{"https://cisp.example.test/": {Keys: setOf(t, r.JWKS())}},
		Audiences: []string{"ussp.example.test"},
		Now:       func() time.Time { return t0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, body, err := cv.Verify(context.Background(), tok); err != nil || string(body) != `{"schema":"cis/change/v1"}` {
		t.Errorf("the compact JWS does not verify: %v %s", err, body)
	}
}

func signed(t testing.TB, key *rsa.PrivateKey, kid string, body []byte, at time.Time) string {
	t.Helper()
	s, err := coreauth.SignDetached(coreauth.SigningKey{KID: kid, Key: key}, body, at)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// E-01: the accepted signature beside each refusal, every one differing
// from it in one thing, and each counted under its reason.
func TestDetachedVerifierRefusals(t *testing.T) {
	key := authtest.Key(t, "authority", 2048)
	set := authtest.PublicSet(t, map[string]*rsa.PrivateKey{"auth-sig-1": key})
	v := verifier(t, "authority-01", set, 5*time.Minute, t0)
	body := []byte(`{"type":"FeatureCollection","features":[]}`)
	pem := pemOf(t, key)
	good := signed(t, key, "auth-sig-1", body, t0)
	if s, err := v.Verify(context.Background(), good, body); err != nil || s.KID != "auth-sig-1" || s.Publisher != "authority-01" || !s.IssuedAt.Equal(t0) {
		t.Fatalf("the good signature: %+v %v", s, err)
	}
	hdr := func(m map[string]any) map[string]any {
		base := map[string]any{"alg": "RS256", "kid": "auth-sig-1", "iat": t0.Unix(), "b64": false, "crit": []string{"b64"}}
		for k, val := range m {
			if val == nil {
				delete(base, k)
			} else {
				base[k] = val
			}
		}
		return base
	}
	other := authtest.Key(t, "other", 2048)
	cases := []struct {
		name, header string
		body         []byte
		counter      string
	}{
		{"no signature", "", body, coreauth.CounterRejectedMalformed},
		{"attached payload", strings.Replace(good, "..", ".e30.", 1), body, coreauth.CounterRejectedMalformed},
		{"altered body", good, append([]byte(nil), append(body[:len(body)-1], ' ', '}')...), coreauth.CounterRejectedSignature},
		{"empty body", good, nil, jws.CounterRejectedEmpty},
		{"b64 true", authtest.Detached(t, hdr(map[string]any{"b64": true}), body, key, nil), body, coreauth.CounterRejectedB64},
		{"b64 absent", authtest.Detached(t, hdr(map[string]any{"b64": nil, "crit": nil}), body, key, nil), body, coreauth.CounterRejectedB64},
		{"crit missing", authtest.Detached(t, hdr(map[string]any{"crit": nil}), body, key, nil), body, coreauth.CounterRejectedB64},
		{"crit names more", authtest.Detached(t, hdr(map[string]any{"crit": []string{"b64", "exp"}}), body, key, nil), body, coreauth.CounterRejectedCrit},
		{"alg none", authtest.Detached(t, hdr(map[string]any{"alg": "none"}), body, nil, nil), body, coreauth.CounterRejectedAlgorithm},
		{"HS256 with the public key as secret", authtest.Detached(t, hdr(map[string]any{"alg": "HS256"}), body, nil, pem), body, coreauth.CounterRejectedAlgorithm},
		{"unknown kid", signed(t, other, "someone-else", body, t0), body, coreauth.CounterRejectedKID},
		{"right kid, other key", signed(t, other, "auth-sig-1", body, t0), body, coreauth.CounterRejectedSignature},
		{"kid missing", authtest.Detached(t, hdr(map[string]any{"kid": nil}), body, key, nil), body, coreauth.CounterRejectedKID},
		{"iat missing", authtest.Detached(t, hdr(map[string]any{"iat": nil}), body, key, nil), body, coreauth.CounterRejectedIAT},
		{"iat 5 min + 1 s old", signed(t, key, "auth-sig-1", body, t0.Add(-5*time.Minute-time.Second)), body, coreauth.CounterRejectedIAT},
		{"iat 5 min + 1 s ahead", signed(t, key, "auth-sig-1", body, t0.Add(5*time.Minute+time.Second)), body, coreauth.CounterRejectedIAT},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := v.Counters().Get(c.counter)
			_, err := v.Verify(context.Background(), c.header, c.body)
			te := refusal(t, err)
			if te.Counter != c.counter {
				t.Errorf("refused as %s (%v), want %s", te.Counter, err, c.counter)
			}
			if v.Counters().Get(c.counter) != before+1 {
				t.Errorf("%s not counted", c.counter)
			}
		})
	}
	// The iat edges inside the window are accepted.
	for _, at := range []time.Time{t0.Add(-5*time.Minute + time.Second), t0.Add(5*time.Minute - time.Second)} {
		if _, err := v.Verify(context.Background(), signed(t, key, "auth-sig-1", body, at), body); err != nil {
			t.Errorf("iat %s inside 5 min refused: %v", at.Sub(t0), err)
		}
	}
}

// A body signed with the authority's key is refused by the ANSP's
// verifier and the other way round, beside each accepted by its own.
func TestPublishersDoNotCrossVerify(t *testing.T) {
	ak, nk := authtest.Key(t, "authority", 2048), authtest.Key(t, "ansp", 2048)
	authority := verifier(t, "authority-01", authtest.PublicSet(t, map[string]*rsa.PrivateKey{"auth-sig-1": ak}), 5*time.Minute, t0)
	ansp := verifier(t, "ansp-01", authtest.PublicSet(t, map[string]*rsa.PrivateKey{"ansp-sig-1": nk}), 5*time.Minute, t0)
	body := []byte(`{"ansp_ref":"R1","ansp_version":1}`)
	bySig := map[string]string{"authority": signed(t, ak, "auth-sig-1", body, t0), "ansp": signed(t, nk, "ansp-sig-1", body, t0)}
	if _, err := authority.Verify(context.Background(), bySig["authority"], body); err != nil {
		t.Errorf("authority body on the authority verifier: %v", err)
	}
	if _, err := ansp.Verify(context.Background(), bySig["ansp"], body); err != nil {
		t.Errorf("ANSP body on the ANSP verifier: %v", err)
	}
	if _, err := ansp.Verify(context.Background(), bySig["authority"], body); refusal(t, err).Counter != coreauth.CounterRejectedKID {
		t.Errorf("authority body on the ANSP verifier: %v", err)
	}
	if _, err := authority.Verify(context.Background(), bySig["ansp"], body); refusal(t, err).Counter != coreauth.CounterRejectedKID {
		t.Errorf("ANSP body on the authority verifier: %v", err)
	}
	// The same kid under both publishers does not help a forger.
	forged := signed(t, nk, "auth-sig-1", body, t0)
	if _, err := authority.Verify(context.Background(), forged, body); refusal(t, err).Counter != coreauth.CounterRejectedSignature {
		t.Errorf("the ANSP's key under the authority's kid: %v", err)
	}
	if ansp.Publisher() != "ansp-01" {
		t.Errorf("Publisher = %s", ansp.Publisher())
	}
}

func TestNewDetachedVerifierRefusals(t *testing.T) {
	set := authtest.PublicSet(t, map[string]*rsa.PrivateKey{"k": authtest.Key(t, "authority", 2048)})
	if _, err := jws.NewDetachedVerifier(context.Background(), jws.KeySource{Keys: coreauth.IssuerConfig{Keys: set}}, time.Minute, jws.Options{}); err == nil {
		t.Error("no publisher accepted")
	}
	if _, err := jws.NewDetachedVerifier(context.Background(), jws.KeySource{Publisher: "p", Keys: coreauth.IssuerConfig{Keys: set}}, 0, jws.Options{}); err == nil {
		t.Error("no skew accepted")
	}
	if _, err := jws.NewDetachedVerifier(context.Background(), jws.KeySource{Publisher: "p"}, time.Minute, jws.Options{}); err == nil {
		t.Error("no key source accepted")
	}
	if _, err := jws.NewDetachedVerifier(context.Background(), jws.KeySource{Publisher: "p", Keys: coreauth.IssuerConfig{Keys: set}}, time.Minute, jws.Options{}); err != nil {
		t.Errorf("a static set refused: %v", err)
	}
}

// The publisher's JWKS by URL: fetched at start, a rotated key picked up
// on an unknown kid.
func TestDetachedVerifierByURL(t *testing.T) {
	k1, k2 := authtest.Key(t, "authority", 2048), authtest.Key(t, "authority-next", 2048)
	srv := authtest.NewJWKSServer(t, authtest.PublicSet(t, map[string]*rsa.PrivateKey{"k1": k1}))
	v, err := jws.NewDetachedVerifier(context.Background(), jws.KeySource{Publisher: "authority-01", Keys: coreauth.IssuerConfig{JWKSURL: srv.URL()}},
		5*time.Minute, jws.Options{MinRefreshInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("x")
	if _, err := v.Verify(context.Background(), signed(t, k1, "k1", body, time.Now()), body); err != nil {
		t.Errorf("k1: %v", err)
	}
	srv.SetKeys(t, authtest.PublicSet(t, map[string]*rsa.PrivateKey{"k1": k1, "k2": k2}))
	time.Sleep(5 * time.Millisecond) // past the 1 ms rate limit
	if _, err := v.Verify(context.Background(), signed(t, k2, "k2", body, time.Now()), body); err != nil {
		t.Errorf("the rotated key k2 was not fetched: %v", err)
	}
}

// --- RequireSignature -------------------------------------------------

func writeProblem(w http.ResponseWriter, status int, slug, _, detail string, fields ...*core.FieldError) {
	w.Header().Set("X-Slug", slug)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	var parts []string
	for _, f := range fields {
		parts = append(parts, f.Field+"|"+f.Reason)
	}
	_, _ = io.WriteString(w, detail+"\n"+strings.Join(parts, "\n"))
}

func guardFor(v *jws.DetachedVerifier, comp *obs.Component) jws.SignatureGuard {
	return jws.SignatureGuard{Verifier: func() *jws.DetachedVerifier { return v }, Problems: writeProblem, MaxBodyBytes: 1 << 20, Component: comp}
}

func serve(t *testing.T, g jws.SignatureGuard, caller *auth.Caller, header string, body []byte, next http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/v1/publications/zones", bytes.NewReader(body))
	if header != "" {
		req.Header.Set(jws.HeaderSignature, header)
	}
	if caller != nil {
		req = req.WithContext(auth.WithCaller(req.Context(), caller))
	}
	rec := httptest.NewRecorder()
	g.RequireSignature()(next).ServeHTTP(rec, req)
	return rec
}

// The handler receives exactly the bytes that were verified, with the
// signature in the context; a refusal never reaches it.
func TestRequireSignatureAcceptsAndPassesTheBytes(t *testing.T) {
	key := authtest.Key(t, "authority", 2048)
	v := verifier(t, "authority-01", authtest.PublicSet(t, map[string]*rsa.PrivateKey{"k1": key}), 5*time.Minute, t0)
	comp := obs.NewStatus("test", nil, t0).Component("signatures")
	body := []byte(`{"type":"FeatureCollection","features":[]}`)
	var got []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		if s, ok := jws.SignatureFrom(r.Context()); !ok || s.KID != "k1" {
			t.Errorf("signature in context = %+v %v", s, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rec := serve(t, guardFor(v, comp), &auth.Caller{ClientID: "authority-01"}, signed(t, key, "k1", body, t0), body, next)
	if rec.Code != http.StatusNoContent || !bytes.Equal(got, body) {
		t.Fatalf("status %d, handler got %q", rec.Code, got)
	}
	if comp.Counter("signature_accepted", "").Value() != 1 {
		t.Error("the acceptance is not counted")
	}
	if _, ok := jws.SignatureFrom(context.Background()); ok {
		t.Error("a signature in an empty context")
	}
}

// Safety note of WP-2: a body that is both unsigned and invalid ED-318 is
// refused for the signature only; the parser never sees it. Its twin with
// a valid signature reaches the parser, which then names the content.
func TestSignatureIsCheckedBeforeTheBodyIsParsed(t *testing.T) {
	key := authtest.Key(t, "authority", 2048)
	v := verifier(t, "authority-01", authtest.PublicSet(t, map[string]*rsa.PrivateKey{"k1": key}), 5*time.Minute, t0)
	invalid := []byte(`{"type":"FeatureCollection","features":[{"type":"Feature"}],"oops":`)
	parsed := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parsed++
		b, _ := io.ReadAll(r.Body)
		if _, err := ed318.Parse(b, ed318.Limits{}); err != nil {
			writeProblem(w, http.StatusUnprocessableEntity, "invalid_ed318", "", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rec := serve(t, guardFor(v, nil), &auth.Caller{ClientID: "authority-01"}, "", invalid, next)
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-Slug") != jws.SlugSignature || parsed != 0 {
		t.Fatalf("unsigned invalid body: %d %s, parsed %d times", rec.Code, rec.Header().Get("X-Slug"), parsed)
	}
	if strings.Contains(strings.ToLower(rec.Body.String()), "feature") || !strings.Contains(rec.Body.String(), "header|") {
		t.Errorf("the problem names more than the signature: %s", rec.Body.String())
	}
	rec = serve(t, guardFor(v, nil), &auth.Caller{ClientID: "authority-01"}, signed(t, key, "k1", invalid, t0), invalid, next)
	if rec.Code != http.StatusUnprocessableEntity || parsed != 1 {
		t.Errorf("signed invalid body: %d, parsed %d times", rec.Code, parsed)
	}
}

func TestRequireSignatureRefusals(t *testing.T) {
	key := authtest.Key(t, "authority", 2048)
	v := verifier(t, "authority-01", authtest.PublicSet(t, map[string]*rsa.PrivateKey{"k1": key}), 5*time.Minute, t0)
	body := []byte(`{"a":1}`)
	sig := signed(t, key, "k1", body, t0)
	never := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("the handler ran") })
	cases := []struct {
		name   string
		g      jws.SignatureGuard
		caller *auth.Caller
		header string
		body   []byte
		status int
		slug   string
	}{
		{"no verifier configured", jws.SignatureGuard{Problems: writeProblem, MaxBodyBytes: 1 << 20}, &auth.Caller{ClientID: "authority-01"}, sig, body, 503, jws.SlugSignatureUnavailable},
		{"verifier func returns nil", jws.SignatureGuard{Verifier: func() *jws.DetachedVerifier { return nil }, Problems: writeProblem}, &auth.Caller{ClientID: "authority-01"}, sig, body, 503, jws.SlugSignatureUnavailable},
		{"no caller", guardFor(v, nil), nil, sig, body, 403, auth.SlugNotAPublisher},
		{"another client", guardFor(v, nil), &auth.Caller{ClientID: "ansp-01"}, sig, body, 403, auth.SlugNotAPublisher},
		{"body over the cap", jws.SignatureGuard{Verifier: func() *jws.DetachedVerifier { return v }, Problems: writeProblem, MaxBodyBytes: 4}, &auth.Caller{ClientID: "authority-01"}, sig, body, 413, jws.SlugBodyTooLarge},
		{"bad signature", guardFor(v, nil), &auth.Caller{ClientID: "authority-01"}, sig, []byte(`{"a":2}`), 403, jws.SlugSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := serve(t, c.g, c.caller, c.header, c.body, never)
			if rec.Code != c.status || rec.Header().Get("X-Slug") != c.slug {
				t.Errorf("%d %s, want %d %s: %s", rec.Code, rec.Header().Get("X-Slug"), c.status, c.slug, rec.Body.String())
			}
		})
	}
	// The cap exactly met is accepted (E-10: the bound and one past it).
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	g := jws.SignatureGuard{Verifier: func() *jws.DetachedVerifier { return v }, Problems: writeProblem, MaxBodyBytes: int64(len(body))}
	if rec := serve(t, g, &auth.Caller{ClientID: "authority-01"}, sig, body, ok); rec.Code != http.StatusNoContent {
		t.Errorf("a body exactly at the cap: %d", rec.Code)
	}
	// A body reader that fails is a 400 naming the body.
	req := httptest.NewRequest(http.MethodPut, "/", io.NopCloser(failingReader{}))
	req = req.WithContext(auth.WithCaller(req.Context(), &auth.Caller{ClientID: "authority-01"}))
	rec := httptest.NewRecorder()
	guardFor(v, nil).RequireSignature()(never).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "body|") {
		t.Errorf("failing body: %d %s", rec.Code, rec.Body.String())
	}
	// A MaxBytesReader set by the router's body cap is a 413.
	req = httptest.NewRequest(http.MethodPut, "/", bytes.NewReader(body))
	req = req.WithContext(auth.WithCaller(req.Context(), &auth.Caller{ClientID: "authority-01"}))
	rec = httptest.NewRecorder()
	req.Body = http.MaxBytesReader(rec, req.Body, 2)
	guardFor(v, nil).RequireSignature()(never).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("router cap exceeded: %d", rec.Code)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

// FuzzVerifyDetached: no header and body make the verifier panic, and
// nothing but the genuine pair is accepted.
func FuzzVerifyDetached(f *testing.F) {
	key := authtest.Key(f, "authority", 2048)
	v := verifier(f, "authority-01", authtest.PublicSet(f, map[string]*rsa.PrivateKey{"k1": key}), 5*time.Minute, t0)
	body := []byte(`{"type":"FeatureCollection","features":[]}`)
	good := signed(f, key, "k1", body, t0)
	f.Add(good, body)
	f.Add(good, []byte("x"))
	f.Add("", body)
	f.Add("..", []byte{})
	f.Add("eyJhbGciOiJub25lIn0..", body)
	f.Add(strings.Repeat("A", 9000)+"..x", body)
	f.Add("e30..e30", body)
	f.Fuzz(func(t *testing.T, header string, b []byte) {
		_, err := v.Verify(context.Background(), header, b)
		if err == nil && (header != good || !bytes.Equal(b, body)) {
			t.Errorf("accepted a pair that was not signed: %q", header)
		}
	})
}

// BenchmarkVerifyDetached20MB: one RSA verify and SHA-256 of 20 MB
// (budget 100 ms per operation).
func BenchmarkVerifyDetached20MB(b *testing.B) {
	key := authtest.Key(b, "authority", 2048)
	v := verifier(b, "authority-01", authtest.PublicSet(b, map[string]*rsa.PrivateKey{"k1": key}), 5*time.Minute, t0)
	body := bytes.Repeat([]byte(`{"type":"Feature"},`), (20<<20)/19)
	sig := signed(b, key, "k1", body, t0)
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := v.Verify(context.Background(), sig, body); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignCompact(b *testing.B) {
	r := ring(b, "k1", "")
	cl := coreauth.CompactClaims{Issuer: "https://cisp.example.test/", Audience: "ussp.example.test", Subject: "sub-1", JTI: "d-1"}
	body := json.RawMessage(`{"schema":"cis/change/v1","body":{"dataset":"zones","version":42}}`)
	for b.Loop() {
		if _, err := r.SignCompact(cl, body, t0); err != nil {
			b.Fatal(err)
		}
	}
}
