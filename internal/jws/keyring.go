package jws

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// MinRSABits is the shortest key the CISP signs with (docs/PLAN.md
// section 8.4: RSA-3072). Core accepts 2048 for verification; the CISP's
// own keys are held to this.
const MinRSABits = 3072

// maxPEMBytes bounds a key file: an RSA-4096 PKCS#8 PEM is about 3.3 KiB.
const maxPEMBytes = 64 << 10

// KeyRing is the CISP's signing keys: the current key signs, the previous
// one (during a rotation) is only published. Its JWKS bytes and ETag are
// computed once. It is safe for concurrent use.
type KeyRing struct {
	ring *coreauth.KeyRing
	jwks []byte
	etag string
}

// LoadKeyRing builds the ring from PEM: the current key under currentKID
// and, when prevPEM is not empty, the previous key under prevKID. It
// refuses a key shorter than MinRSABits, a missing kid, and a kid used
// twice; every refusal is a *core.FieldError naming the key.
func LoadKeyRing(currentPEM []byte, currentKID string, prevPEM []byte, prevKID string) (*KeyRing, error) {
	cur, err := signingKey("current", currentPEM, currentKID)
	if err != nil {
		return nil, err
	}
	var retired []coreauth.SigningKey
	if len(prevPEM) > 0 || prevKID != "" {
		prev, err := signingKey("previous", prevPEM, prevKID)
		if err != nil {
			return nil, err
		}
		if prev.KID == cur.KID {
			return nil, core.Fieldf("previous.kid", "%q is also the current kid", prevKID)
		}
		retired = append(retired, prev)
	}
	ring, err := coreauth.NewKeyRing(cur, retired...)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(ring.JWKS())
	if err != nil {
		return nil, core.Fieldf("jwks", "%v", err)
	}
	sum := sha256.Sum256(raw)
	return &KeyRing{ring: ring, jwks: raw, etag: `"` + base64.RawURLEncoding.EncodeToString(sum[:16]) + `"`}, nil
}

// ReadKeyRing is LoadKeyRing from files (CISP_SIGNING_KEY_FILE and
// CISP_SIGNING_KEY_PREV_FILE); an empty prevFile means no previous key.
func ReadKeyRing(currentFile, currentKID, prevFile, prevKID string) (*KeyRing, error) {
	cur, err := readPEM("current", currentFile)
	if err != nil {
		return nil, err
	}
	var prev []byte
	if prevFile != "" {
		if prev, err = readPEM("previous", prevFile); err != nil {
			return nil, err
		}
	}
	return LoadKeyRing(cur, currentKID, prev, prevKID)
}

func readPEM(field, path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the operator's configuration
	if err != nil {
		return nil, core.Fieldf(field+".file", "%v", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxPEMBytes+1))
	if err != nil {
		return nil, core.Fieldf(field+".file", "%v", err)
	}
	if len(raw) > maxPEMBytes {
		return nil, core.Fieldf(field+".file", "larger than %d bytes: not a PEM key", maxPEMBytes)
	}
	return raw, nil
}

func signingKey(field string, pemBytes []byte, kid string) (coreauth.SigningKey, error) {
	if kid == "" {
		return coreauth.SigningKey{}, core.Fieldf(field+".kid", "missing")
	}
	key, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		return coreauth.SigningKey{}, core.Fieldf(field+".key", "%v", err)
	}
	if bits := key.N.BitLen(); bits < MinRSABits {
		return coreauth.SigningKey{}, core.Fieldf(field+".key", "%d bits, shorter than %d", bits, MinRSABits)
	}
	return coreauth.SigningKey{KID: kid, Key: key}, nil
}

// ParsePrivateKeyPEM reads one RSA private key, PKCS#8 ("PRIVATE KEY") or
// PKCS#1 ("RSA PRIVATE KEY").
func ParsePrivateKeyPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#8: %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is %T, not RSA", k)
		}
		return rk, nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS#1: %w", err)
		}
		return k, nil
	}
	return nil, fmt.Errorf("PEM block %q is not a private key", block.Type)
}

// EncodePrivateKeyPEM is key as a PKCS#8 PEM block (what cispctl
// rotate-key writes).
func EncodePrivateKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// JWKS is the public key set, every kid of the ring with alg RS256 and
// use sig, as the bytes GET /.well-known/jwks.json serves.
func (k *KeyRing) JWKS() []byte { return k.jwks }

// ETag is the strong entity tag of JWKS().
func (k *KeyRing) ETag() string { return k.etag }

// ActiveKID is the kid of the key that signs.
func (k *KeyRing) ActiveKID() string { return k.ring.ActiveKID() }

// KIDs is every kid of the ring, the signing one first.
func (k *KeyRing) KIDs() []string { return k.ring.KIDs() }

// SignDetached is the X-JWS-Signature value of body (core's
// KeyRing.SignDetached: RS256, b64 false, crit ["b64"], kid, iat).
func (k *KeyRing) SignDetached(body []byte, now time.Time) (string, error) {
	return k.ring.SignDetached(body, now)
}

// SignCompact signs a delivery as a compact JWS (core's
// KeyRing.SignCompact; WP-6 fills the claims).
func (k *KeyRing) SignCompact(cl coreauth.CompactClaims, body json.RawMessage, now time.Time) (string, error) {
	return k.ring.SignCompact(cl, body, now)
}
