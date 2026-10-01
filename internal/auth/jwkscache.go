package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// Counters of the JWKS disk cache, in the component given to it.
const (
	CounterJWKSCacheWritten     = "jwks_cache_written"
	CounterJWKSCacheWriteFailed = "jwks_cache_write_failed"
)

// maxCacheFileBytes bounds the cache file read at start: a few JWKS of
// at most core's MaxJWKSBytes each.
const maxCacheFileBytes = 8 * coreauth.DefaultMaxJWKSBytes

// cacheFile is the on-disk form: the last good JWKS of every URL, with
// the time it was fetched. JWKS hold public keys only.
type cacheFile struct {
	Entries map[string]cacheEntry `json:"entries"`
}

type cacheEntry struct {
	FetchedAt time.Time       `json:"fetched_at"`
	JWKS      json.RawMessage `json:"jwks"`
}

// JWKSCache keeps the last good JWKS of every issuer on disk, so that a
// process can start while an issuer is down (docs/WORKPACKAGES/WP-2.md).
// Every successful fetch through Client is written; Lookup reads it back.
// It is safe for concurrent use.
type JWKSCache struct {
	path   string
	client *http.Client
	now    func() time.Time
	comp   *obs.Component

	mu      sync.Mutex
	entries map[string]cacheEntry
}

// JWKSCacheOptions configure OpenJWKSCache.
type JWKSCacheOptions struct {
	// Transport is the base transport; nil is http.DefaultTransport.
	Transport http.RoundTripper
	// Timeout bounds one request (default core's DefaultHTTPTimeout).
	Timeout time.Duration
	// Component counts writes and write failures; nil counts nowhere.
	Component *obs.Component
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// OpenJWKSCache reads the cache file at path when it exists. A missing
// file is an empty cache; a file that cannot be read or parsed is an
// error naming it (a corrupt copy must not be trusted silently, nor
// overwritten unseen).
func OpenJWKSCache(path string, opts JWKSCacheOptions) (*JWKSCache, error) {
	if path == "" {
		return nil, errors.New("JWKS cache: no file configured")
	}
	if opts.Transport == nil {
		opts.Transport = http.DefaultTransport
	}
	if opts.Timeout <= 0 {
		opts.Timeout = coreauth.DefaultHTTPTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	c := &JWKSCache{path: path, now: opts.Now, comp: opts.Component, entries: map[string]cacheEntry{}}
	c.client = &http.Client{
		Transport:     &recordingTransport{base: opts.Transport, cache: c},
		Timeout:       opts.Timeout,
		CheckRedirect: refuseInsecureRedirect,
	}
	raw, err := readBounded(path, maxCacheFileBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return c, nil
	case err != nil:
		return nil, fmt.Errorf("JWKS cache %s: %w", path, err)
	}
	var f cacheFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("JWKS cache %s does not parse: %w", path, err)
	}
	for u, e := range f.Entries {
		c.entries[u] = e
	}
	return c, nil
}

func readBounded(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the operator's configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxBytes)
	}
	return raw, nil
}

// Path is the cache file.
func (c *JWKSCache) Path() string { return c.path }

// Client is the HTTP client every JWKS fetch goes through (give it to
// core's Config.HTTPClient): it records every good JWKS response, and,
// because a client given to core replaces core's redirect check, it
// refuses a redirect to anything but https (or http on loopback).
func (c *JWKSCache) Client() *http.Client { return c.client }

// Lookup returns the cached JWKS of url and when it was fetched.
func (c *JWKSCache) Lookup(u string) (jwk.Set, time.Time, bool) {
	c.mu.Lock()
	e, ok := c.entries[u]
	c.mu.Unlock()
	if !ok {
		return nil, time.Time{}, false
	}
	set, err := parseJWKS(e.JWKS)
	if err != nil {
		return nil, time.Time{}, false
	}
	return set, e.FetchedAt, true
}

// Fetch GETs url through Client (recording it when good) and reports
// whether it answered with a usable JWKS.
func (c *JWKSCache) Fetch(ctx context.Context, u string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return fmt.Errorf("JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("JWKS fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS fetch: HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, coreauth.DefaultMaxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("JWKS read: %w", err)
	}
	return checkJWKS(body)
}

// checkJWKS reports whether body is a JWKS core would take: within its
// size bound, with at least one key.
func checkJWKS(body []byte) error {
	if int64(len(body)) > coreauth.DefaultMaxJWKSBytes {
		return fmt.Errorf("JWKS larger than %d bytes", coreauth.DefaultMaxJWKSBytes)
	}
	_, err := parseJWKS(body)
	return err
}

func parseJWKS(body []byte) (jwk.Set, error) {
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("JWKS does not parse: %w", err)
	}
	if set.Len() == 0 {
		return nil, errors.New("JWKS has no keys")
	}
	return set, nil
}

// record stores a good JWKS of u and rewrites the file. A write failure
// is counted and leaves the previous file in place.
func (c *JWKSCache) record(u string, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[u] = cacheEntry{FetchedAt: c.now().UTC(), JWKS: append(json.RawMessage(nil), body...)}
	if err := c.writeLocked(); err != nil {
		c.count(CounterJWKSCacheWriteFailed, "JWKS cache file writes that failed (the previous copy stays).")
		return
	}
	c.count(CounterJWKSCacheWritten, "JWKS cache file writes.")
}

func (c *JWKSCache) count(name, help string) {
	if c.comp != nil {
		c.comp.Counter(name, help).Inc()
	}
}

// writeLocked writes the file atomically (temporary file, then rename),
// readable by the owner only.
func (c *JWKSCache) writeLocked() error {
	raw, err := json.Marshal(cacheFile{Entries: c.entries})
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".jwks-cache-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, c.path)
}

// recordingTransport passes every request through and records the body
// of a good GET answer (200, at most core's MaxJWKSBytes, a JWKS with at
// least one key) in the cache. The caller reads the same bytes.
type recordingTransport struct {
	base  http.RoundTripper
	cache *JWKSCache
}

// RoundTrip implements http.RoundTripper.
func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || req.Method != http.MethodGet || resp.StatusCode != http.StatusOK {
		return resp, err
	}
	head, err := io.ReadAll(io.LimitReader(resp.Body, coreauth.DefaultMaxJWKSBytes+1))
	if err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	resp.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(head), resp.Body), Closer: resp.Body}
	if checkJWKS(head) == nil {
		t.cache.record(req.URL.String(), head)
	}
	return resp, nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

// refuseInsecureRedirect follows at most ten redirects and only to https,
// or to http on a loopback host (the rule core applies to JWKS URLs).
func refuseInsecureRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("JWKS fetch: more than 10 redirects")
	}
	if !secureURL(req.URL) {
		return fmt.Errorf("JWKS fetch: redirect to %s refused: https only", req.URL.Redacted())
	}
	return nil
}

func secureURL(u *url.URL) bool {
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}
