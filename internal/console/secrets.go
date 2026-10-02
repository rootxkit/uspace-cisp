package console

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// SecretsKeyBytes is the length of CISP_SECRETS_KEY once decoded: an
// AES-256 key.
const SecretsKeyBytes = 32

const gcmNonceBytes = 12

// ErrSecretsKeyMissing is the start-up refusal when CISP_SECRETS_KEY is
// not set.
var ErrSecretsKeyMissing = errors.New("CISP_SECRETS_KEY is not set: console TOTP secrets are encrypted at rest with it (32 random bytes, standard base64, e.g. `openssl rand -base64 32`)")

// Sealer encrypts the console's TOTP secrets at rest (docs/PLAN.md
// section 8.5) with AES-256-GCM under CISP_SECRETS_KEY: a random 96-bit
// nonce per row, stored as nonce || ciphertext, and the account id as
// associated data, so a ciphertext copied onto another account's row
// does not open.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer decodes CISP_SECRETS_KEY (standard base64 of 32 bytes) and
// returns the sealer; an empty or malformed key is refused with a
// message that names the variable and never repeats the value.
func NewSealer(keyB64 string) (*Sealer, error) {
	if keyB64 == "" {
		return nil, ErrSecretsKeyMissing
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != SecretsKeyBytes {
		return nil, fmt.Errorf("CISP_SECRETS_KEY must be %d bytes in standard base64 (e.g. `openssl rand -base64 32`)", SecretsKeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("CISP_SECRETS_KEY: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("CISP_SECRETS_KEY: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext for the account id.
func (s *Sealer) Seal(accountID string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, gcmNonceBytes, gcmNonceBytes+len(plaintext)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return s.aead.Seal(nonce, nonce, plaintext, []byte(accountID)), nil
}

// Open decrypts what Seal wrote for the same account id; a short,
// altered or misplaced ciphertext is an error, never a panic.
func (s *Sealer) Open(accountID string, sealed []byte) ([]byte, error) {
	if len(sealed) < gcmNonceBytes+s.aead.Overhead() {
		return nil, errors.New("open: the sealed secret is too short")
	}
	pt, err := s.aead.Open(nil, sealed[:gcmNonceBytes], sealed[gcmNonceBytes:], []byte(accountID))
	if err != nil {
		return nil, errors.New("open: the sealed secret does not decrypt under CISP_SECRETS_KEY for this account")
	}
	return pt, nil
}
