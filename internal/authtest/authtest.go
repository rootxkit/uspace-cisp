// Package authtest holds test helpers for the CISP's authentication:
// RSA keys generated at test time and never written anywhere (spec 06
// section 4), a JWKS server that can be taken down and brought back, and
// hand-built detached JWS headers for the refusals the helpers of
// uspace-core will not produce (b64 true, no crit, alg none, HS256). Only
// tests import it.
package authtest

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var (
	keysMu sync.Mutex
	keys   = map[string]*rsa.PrivateKey{}
)

// Key returns the RSA key of bits named name, generated once per test
// binary (key generation is slow; the name keeps keys apart).
func Key(t testing.TB, name string, bits int) *rsa.PrivateKey {
	t.Helper()
	keysMu.Lock()
	defer keysMu.Unlock()
	id := name + "/" + strconv.Itoa(bits)
	if k, ok := keys[id]; ok {
		return k
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	keys[id] = k
	return k
}

// PublicSet is the JWKS of the public halves of keys, by kid, each with
// alg RS256 and use sig.
func PublicSet(t testing.TB, keys map[string]*rsa.PrivateKey) jwk.Set {
	t.Helper()
	set := jwk.NewSet()
	for kid, k := range keys {
		pub, err := jwk.Import(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		for name, v := range map[string]any{jwk.KeyIDKey: kid, jwk.AlgorithmKey: jwa.RS256(), jwk.KeyUsageKey: "sig"} {
			if err := pub.Set(name, v); err != nil {
				t.Fatal(err)
			}
		}
		if err := set.AddKey(pub); err != nil {
			t.Fatal(err)
		}
	}
	return set
}

// JWKSServer serves a JWKS until Down, and again after Up.
type JWKSServer struct {
	*httptest.Server
	down  atomic.Bool
	body  atomic.Value // []byte
	Fetch atomic.Int64
}

// NewJWKSServer serves set on a loopback http URL (core allows plain
// http there), closed at the end of the test.
func NewJWKSServer(t testing.TB, set jwk.Set) *JWKSServer {
	t.Helper()
	s := &JWKSServer{}
	s.SetKeys(t, set)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.Fetch.Add(1)
		if s.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.body.Load().([]byte))
	}))
	t.Cleanup(s.Close)
	return s
}

// SetKeys replaces the served set.
func (s *JWKSServer) SetKeys(t testing.TB, set jwk.Set) {
	t.Helper()
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	s.body.Store(raw)
}

// URL is the JWKS URL.
func (s *JWKSServer) URL() string { return s.Server.URL + "/.well-known/jwks.json" }

// Down makes every fetch answer 503.
func (s *JWKSServer) Down() { s.down.Store(true) }

// Up serves the set again.
func (s *JWKSServer) Up() { s.down.Store(false) }

// Detached builds an X-JWS-Signature value by hand from a protected
// header and a payload: b64 false signs ASCII(BASE64URL(header)) || '.' ||
// payload, b64 true (or absent) the base64url payload. alg selects the
// signature: "RS256" with key, "HS256" with secret, "none" with nothing.
func Detached(t testing.TB, header map[string]any, payload []byte, key *rsa.PrivateKey, secret []byte) string {
	t.Helper()
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p64 := base64.RawURLEncoding.EncodeToString(raw)
	input := []byte(p64 + ".")
	if b64, ok := header["b64"].(bool); ok && !b64 {
		input = append(input, payload...)
	} else {
		input = append(input, base64.RawURLEncoding.EncodeToString(payload)...)
	}
	var sig []byte
	switch header["alg"] {
	case "RS256":
		sum := sha256.Sum256(input)
		sig, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
	case "HS256":
		m := hmac.New(sha256.New, secret)
		m.Write(input)
		sig = m.Sum(nil)
	}
	return p64 + ".." + base64.RawURLEncoding.EncodeToString(sig)
}
