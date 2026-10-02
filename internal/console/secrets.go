package console

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// SecretsKeyBytes is the length of each key in CISP_SECRETS_KEY_FILE
// once decoded: an AES-256 key.
const SecretsKeyBytes = 32

// MaxSecretsKeys bounds the keys the file may hold (the current one and
// the retired ones still opening old secrets).
const MaxSecretsKeys = 16

// maxSecretsKeyFileBytes bounds the key file read.
const maxSecretsKeyFileBytes = 16 << 10

// kidBytes is the length of a key id inside a sealed value.
const kidBytes = 8

const gcmNonceBytes = 12

// ErrSecretsKeyMissing is the start-up refusal when
// CISP_SECRETS_KEY_FILE is not set.
var ErrSecretsKeyMissing = errors.New("CISP_SECRETS_KEY_FILE is not set: console TOTP secrets are encrypted at rest under the keys in that file (one key per line, 32 random bytes in standard base64 or hex, e.g. `openssl rand -base64 32`; the first line seals)")

// ErrUnknownSecretsKey is a sealed value whose key id is none of the
// keys in CISP_SECRETS_KEY_FILE: its key was removed from the file.
var ErrUnknownSecretsKey = errors.New("the sealed secret names a key that is not in CISP_SECRETS_KEY_FILE")

// SecretsKeyID names a secrets key: the first 8 bytes of its SHA-256,
// in hex (the key id uspace-ansp uses), never the key.
func SecretsKeyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:kidBytes])
}

// Sealer encrypts the console's TOTP secrets at rest (docs/PLAN.md
// section 8.5) with AES-256-GCM under the keys of CISP_SECRETS_KEY_FILE.
// A sealed value is kid || nonce || ciphertext: the 8-byte id of the key
// that sealed it, a random 96-bit nonce, and the ciphertext with the kid
// and the account id as associated data, so a ciphertext copied onto
// another account's row, or relabelled with another kid, does not open.
//
// Rotation: the first key seals; every key in the file opens what it
// sealed. To rotate, put a new key on the first line and keep the old
// one below it until no secret is sealed under it any more (an MFA
// reset reseals under the current key).
type Sealer struct {
	current string
	aeads   map[string]cipher.AEAD
	order   []string
}

// LoadSealer reads CISP_SECRETS_KEY_FILE: one key per line, each 32
// bytes in standard base64 or hex; blank lines and lines starting with
// # are ignored; the first key seals. An empty path, an unreadable file
// or a malformed key is refused with a message that names the variable
// and the line, never the value.
func LoadSealer(path string) (*Sealer, error) {
	if path == "" {
		return nil, ErrSecretsKeyMissing
	}
	f, err := os.Open(path) //nolint:gosec // G304: the path is the operator's configuration
	if err != nil {
		return nil, fmt.Errorf("CISP_SECRETS_KEY_FILE: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxSecretsKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("CISP_SECRETS_KEY_FILE: %w", err)
	}
	if len(raw) > maxSecretsKeyFileBytes {
		return nil, fmt.Errorf("CISP_SECRETS_KEY_FILE: larger than %d bytes", maxSecretsKeyFileBytes)
	}
	keys, err := ParseSecretsKeys(raw)
	if err != nil {
		return nil, err
	}
	return NewSealer(keys...)
}

// ParseSecretsKeys reads the keys of a CISP_SECRETS_KEY_FILE body, the
// sealing key first.
func ParseSecretsKeys(raw []byte) ([][]byte, error) {
	var keys [][]byte
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, err := hex.DecodeString(line)
		if err != nil {
			key, err = base64.StdEncoding.DecodeString(line)
		}
		if err != nil || len(key) != SecretsKeyBytes {
			return nil, fmt.Errorf("CISP_SECRETS_KEY_FILE line %d: a key must be %d bytes in standard base64 or hex (e.g. `openssl rand -base64 32`)", n, SecretsKeyBytes)
		}
		keys = append(keys, key)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("CISP_SECRETS_KEY_FILE: %w", err)
	}
	if len(keys) == 0 {
		return nil, errors.New("CISP_SECRETS_KEY_FILE holds no key: put one per line, 32 random bytes in standard base64 or hex (e.g. `openssl rand -base64 32`)")
	}
	return keys, nil
}

// NewSealer seals under the first key and opens under any of them; at
// most MaxSecretsKeys keys, each SecretsKeyBytes long and listed once.
func NewSealer(keys ...[]byte) (*Sealer, error) {
	if len(keys) == 0 {
		return nil, ErrSecretsKeyMissing
	}
	if len(keys) > MaxSecretsKeys {
		return nil, fmt.Errorf("CISP_SECRETS_KEY_FILE holds %d keys, at most %d", len(keys), MaxSecretsKeys)
	}
	s := &Sealer{aeads: make(map[string]cipher.AEAD, len(keys))}
	for i, key := range keys {
		if len(key) != SecretsKeyBytes {
			return nil, fmt.Errorf("CISP_SECRETS_KEY_FILE key %d: must be %d bytes", i+1, SecretsKeyBytes)
		}
		kid := SecretsKeyID(key)
		if _, dup := s.aeads[kid]; dup {
			return nil, fmt.Errorf("CISP_SECRETS_KEY_FILE key %d: listed twice (kid %s)", i+1, kid)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("CISP_SECRETS_KEY_FILE: %w", err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("CISP_SECRETS_KEY_FILE: %w", err)
		}
		s.aeads[kid] = aead
		s.order = append(s.order, kid)
	}
	s.current = s.order[0]
	return s, nil
}

// KeyID is the id of the key that seals (the file's first key).
func (s *Sealer) KeyID() string { return s.current }

// KeyIDs are the ids of every key that opens, the sealing key first.
func (s *Sealer) KeyIDs() []string { return append([]string(nil), s.order...) }

// SealedKeyID is the id of the key a sealed value names, or "" when the
// value is too short to name one.
func SealedKeyID(sealed []byte) string {
	if len(sealed) < kidBytes {
		return ""
	}
	return hex.EncodeToString(sealed[:kidBytes])
}

// associated binds a sealed value to its key id and its account.
func associated(kid []byte, accountID string) []byte {
	return append(append(make([]byte, 0, len(kid)+len(accountID)), kid...), accountID...)
}

// Seal encrypts plaintext for the account id under the current key.
func (s *Sealer) Seal(accountID string, plaintext []byte) ([]byte, error) {
	kid, err := hex.DecodeString(s.current)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	aead := s.aeads[s.current]
	out := make([]byte, kidBytes+gcmNonceBytes, kidBytes+gcmNonceBytes+len(plaintext)+aead.Overhead())
	copy(out, kid)
	if _, err := rand.Read(out[kidBytes:]); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	nonce := out[kidBytes : kidBytes+gcmNonceBytes]
	return aead.Seal(out, nonce, plaintext, associated(kid, accountID)), nil
}

// Open decrypts what Seal wrote for the same account id, under whichever
// key of the file sealed it; a value naming a key that is not in the
// file is ErrUnknownSecretsKey, and a short, altered or misplaced one an
// error, never a panic.
func (s *Sealer) Open(accountID string, sealed []byte) ([]byte, error) {
	kid := SealedKeyID(sealed)
	if kid == "" {
		return nil, errors.New("open: the sealed secret is too short")
	}
	aead, ok := s.aeads[kid]
	if !ok {
		return nil, fmt.Errorf("open: kid %s: %w", kid, ErrUnknownSecretsKey)
	}
	if len(sealed) < kidBytes+gcmNonceBytes+aead.Overhead() {
		return nil, errors.New("open: the sealed secret is too short")
	}
	nonce := sealed[kidBytes : kidBytes+gcmNonceBytes]
	pt, err := aead.Open(nil, nonce, sealed[kidBytes+gcmNonceBytes:], associated(sealed[:kidBytes], accountID))
	if err != nil {
		return nil, fmt.Errorf("open: the sealed secret does not decrypt under key %s for this account", kid)
	}
	return pt, nil
}
