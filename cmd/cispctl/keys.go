package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/jws"
)

// keyDir is where rotate-key writes unless --force (git-ignored; spec 06
// section 4: keys are generated at run time, never committed).
const keyDir = "local"

// maxSignBytes is the default bound on a body sign and verify-signature
// read: the default publication cap (CISP_MAX_PUBLICATION_BYTES).
const maxSignBytes = 8 << 20

// rotateKey generates an RSA-3072 key, writes it as signing-<kid>.pem
// (0600) and prints the environment lines that make it the signing key,
// keeping the current one as the previous key for the rotation window.
func rotateKey(args, environ []string, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("rotate-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", keyDir, "directory to write the key into (under local/ unless --force)")
	kid := fs.String("kid", "", "key id (default cisp-<UTC time>)")
	force := fs.Bool("force", false, "allow a directory outside local/")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	if *kid == "" {
		*kid = "cisp-" + now.UTC().Format("20060102T150405Z")
	}
	if !kidPattern(*kid) {
		_, _ = fmt.Fprintf(stderr, "cispctl: --kid %q must be 1-64 of A-Z a-z 0-9 . _ -\n", *kid)
		return exitUsage
	}
	inside, err := within(*out, keyDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitUsage
	}
	if !inside && !*force {
		_, _ = fmt.Fprintf(stderr, "cispctl: %s is outside %s/ (git-ignored); refusing to write a private key there without --force\n", *out, keyDir)
		return exitUsage
	}
	key, err := rsa.GenerateKey(rand.Reader, jws.MinRSABits)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: generate: %v\n", err)
		return exitFailed
	}
	pemBytes, err := jws.EncodePrivateKeyPEM(key)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: encode: %v\n", err)
		return exitFailed
	}
	// The ring the api will build from these lines must accept them.
	prevFile, prevKID := envValue(environ, config.EnvSigningKeyFile), envValue(environ, config.EnvSigningKID)
	if _, err := jws.LoadKeyRing(pemBytes, *kid, nil, ""); err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: the new key does not load: %v\n", err)
		return exitFailed
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	path := filepath.Join(*out, "signing-"+*kid+".pem")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator's directory
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v (an existing key is never overwritten)\n", err)
		return exitFailed
	}
	if _, err := f.Write(pemBytes); err != nil {
		_ = f.Close()
		_, _ = fmt.Fprintf(stderr, "cispctl: write %s: %v\n", path, err)
		return exitFailed
	}
	if err := f.Close(); err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: write %s: %v\n", path, err)
		return exitFailed
	}
	_, _ = fmt.Fprintf(stdout, "# RSA-%d signing key written to %s (mode 0600)\n", jws.MinRSABits, path)
	_, _ = fmt.Fprintf(stdout, "%s=%s\n%s=%s\n", config.EnvSigningKeyFile, path, config.EnvSigningKID, *kid)
	if prevFile != "" && prevKID != "" {
		_, _ = fmt.Fprintln(stdout, "# keep the current key in the JWKS for the rotation window:")
		_, _ = fmt.Fprintf(stdout, "%s=%s\n%s=%s\n", config.EnvSigningKeyPrevFile, prevFile, config.EnvSigningKIDPrev, prevKID)
	}
	return exitOK
}

// within reports whether dir is base or inside it, both taken relative
// to the working directory.
func within(dir, base string) (bool, error) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}
	b, err := filepath.Abs(base)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(b, d)
	if err != nil {
		return false, nil //nolint:nilerr // another volume is outside, not an error
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

func kidPattern(kid string) bool {
	if kid == "" || len(kid) > 64 {
		return false
	}
	for _, r := range kid {
		ok := r == '.' || r == '_' || r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}

func envValue(environ []string, name string) string {
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// readBody reads stdin up to maxBytes; more is an error.
func readBody(stdin io.Reader, maxBytes int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(stdin, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("the body is longer than %d bytes", maxBytes)
	}
	return body, nil
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator's key file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := readBody(f, 64<<10)
	if err != nil {
		return nil, err
	}
	return jws.ParsePrivateKeyPEM(raw)
}

// sign prints the X-JWS-Signature value of the body on stdin, signed with
// a local key (a dev helper for tests and the lab).
func sign(args []string, stdin io.Reader, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "PEM file of the RSA private key")
	kid := fs.String("kid", "", "key id of that key")
	maxBytes := fs.Int64("max-bytes", maxSignBytes, "largest body accepted")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *keyFile == "" || *kid == "" {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: --key: %v\n", err)
		return exitFailed
	}
	body, err := readBody(stdin, *maxBytes)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	sig, err := coreauth.SignDetached(coreauth.SigningKey{KID: *kid, Key: key}, body, now)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: sign: %v\n", err)
		return exitFailed
	}
	_, _ = fmt.Fprintln(stdout, sig)
	return exitOK
}

// verifySignature checks a detached signature of the body on stdin with
// the public half of a local key, through the DetachedVerifier the api
// uses (a dev helper: the end-to-end check of rotate-key and sign).
func verifySignature(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, now time.Time) int {
	fs := flag.NewFlagSet("verify-signature", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "PEM file of the RSA private key whose public half verifies")
	kid := fs.String("kid", "", "key id of that key")
	sig := fs.String("sig", "", "the X-JWS-Signature value")
	maxSkew := fs.Duration("max-skew", 5*time.Minute, "how far iat may be from now")
	maxBytes := fs.Int64("max-bytes", maxSignBytes, "largest body accepted")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *keyFile == "" || *kid == "" {
		_, _ = fmt.Fprint(stderr, usage)
		return exitUsage
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: --key: %v\n", err)
		return exitFailed
	}
	pub, err := jwk.Import(&key.PublicKey)
	if err == nil {
		err = errors.Join(pub.Set(jwk.KeyIDKey, *kid), pub.Set(jwk.AlgorithmKey, jwa.RS256()), pub.Set(jwk.KeyUsageKey, "sig"))
	}
	set := jwk.NewSet()
	if err == nil {
		err = set.AddKey(pub)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: --key: %v\n", err)
		return exitFailed
	}
	body, err := readBody(stdin, *maxBytes)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	const publisher = "local-key"
	v, err := jws.NewDetachedVerifier(ctx, jws.KeySource{Publisher: publisher, Keys: coreauth.IssuerConfig{Keys: set}},
		*maxSkew, jws.Options{MaxPayloadBytes: *maxBytes, Now: func() time.Time { return now }})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: %v\n", err)
		return exitFailed
	}
	s, err := v.Verify(ctx, *sig, body)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cispctl: signature refused: %v\n", err)
		return exitFailed
	}
	_, _ = fmt.Fprintf(stdout, "signature ok: kid %s, iat %s, %d bytes\n", s.KID, s.IssuedAt.UTC().Format(time.RFC3339), len(body))
	return exitOK
}
