package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the argon2id cost parameters of a password hash
// (spec 06 section 3). They travel in the PHC string, so a hash made
// with older parameters still verifies and is re-hashed on the next
// successful login (NeedsRehash).
type Argon2Params struct {
	// MemoryKiB is the memory cost in KiB.
	MemoryKiB uint32
	// Iterations is the time cost.
	Iterations uint32
	// Lanes is the parallelism.
	Lanes uint8
}

// DefaultArgon2 is the parameter set new hashes are made with: 64 MiB,
// 3 iterations, 4 lanes (docs/WORKPACKAGES/WP-8.md).
var DefaultArgon2 = Argon2Params{MemoryKiB: 64 << 10, Iterations: 3, Lanes: 4}

// Bounds of what a stored hash or a submitted password may ask of the
// process (E-10): a hash whose parameters exceed them is refused before
// any work, and so is a password longer than MaxPasswordBytes.
const (
	MaxPasswordBytes   = 1024
	maxArgon2MemoryKiB = 1 << 20 // 1 GiB
	maxArgon2Iter      = 64
	argon2SaltBytes    = 16
	argon2KeyBytes     = 32
	maxEncodedHash     = 512
)

// ErrPasswordTooLong is a submitted password over MaxPasswordBytes.
var ErrPasswordTooLong = errors.New("password longer than 1024 bytes")

// HashPassword hashes password with argon2id and the given parameters
// (DefaultArgon2 in production) and returns the PHC string
// $argon2id$v=19$m=<KiB>,t=<iterations>,p=<lanes>$<salt>$<hash>, salt
// and hash in unpadded standard base64.
func HashPassword(password string, p Argon2Params) (string, error) {
	if len(password) > MaxPasswordBytes {
		return "", ErrPasswordTooLong
	}
	if err := p.valid(); err != nil {
		return "", err
	}
	salt := make([]byte, argon2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.MemoryKiB, p.Lanes, argon2KeyBytes)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Iterations, p.Lanes, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func (p Argon2Params) valid() error {
	switch {
	case p.MemoryKiB < 8*uint32(p.Lanes) || p.MemoryKiB > maxArgon2MemoryKiB:
		return fmt.Errorf("argon2 memory %d KiB is outside %d..%d", p.MemoryKiB, 8*uint32(p.Lanes), maxArgon2MemoryKiB)
	case p.Iterations < 1 || p.Iterations > maxArgon2Iter:
		return fmt.Errorf("argon2 iterations %d is outside 1..%d", p.Iterations, maxArgon2Iter)
	case p.Lanes < 1:
		return errors.New("argon2 lanes must be at least 1")
	}
	return nil
}

// VerifyPassword reports whether password matches the PHC string
// encoded, comparing in constant time, and whether the hash was made
// with parameters other than want (the caller re-hashes then). A hash
// that does not parse, or whose parameters are out of bounds, is an
// error, never a panic.
func VerifyPassword(encoded, password string, want Argon2Params) (ok, needsRehash bool, err error) {
	if len(password) > MaxPasswordBytes {
		return false, false, ErrPasswordTooLong
	}
	p, salt, key, err := parsePHC(encoded)
	if err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.MemoryKiB, p.Lanes, uint32(len(key)))
	if subtle.ConstantTimeCompare(got, key) != 1 {
		return false, false, nil
	}
	return true, p != want || len(salt) != argon2SaltBytes || len(key) != argon2KeyBytes, nil
}

// parsePHC reads $argon2id$v=19$m=..,t=..,p=..$salt$hash.
func parsePHC(encoded string) (Argon2Params, []byte, []byte, error) {
	var p Argon2Params
	if len(encoded) > maxEncodedHash {
		return p, nil, nil, errors.New("password hash: too long")
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, errors.New("password hash: not an argon2id PHC string")
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return p, nil, nil, fmt.Errorf("password hash: version %q is not v=%d", parts[2], argon2.Version)
	}
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return p, nil, nil, fmt.Errorf("password hash: parameter %q", kv)
		}
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return p, nil, nil, fmt.Errorf("password hash: parameter %q", kv)
		}
		switch k {
		case "m":
			p.MemoryKiB = uint32(n)
		case "t":
			p.Iterations = uint32(n)
		case "p":
			if n > 255 {
				return p, nil, nil, fmt.Errorf("password hash: parameter %q", kv)
			}
			p.Lanes = uint8(n)
		default:
			return p, nil, nil, fmt.Errorf("password hash: parameter %q", kv)
		}
	}
	if err := p.valid(); err != nil {
		return p, nil, nil, fmt.Errorf("password hash: %w", err)
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return p, nil, nil, errors.New("password hash: salt")
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return p, nil, nil, errors.New("password hash: key")
	}
	return p, salt, key, nil
}
