package auth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// Source is one allow-listed key owner: a token issuer (ID = its iss) or
// a publisher (ID = its client id), with the URL of its JWKS or, in tests
// and static deployments, the key set itself.
type Source struct {
	ID      string
	JWKSURL string
	Keys    jwk.Set
}

// ReloadConfig configures StartReloading.
type ReloadConfig[T any] struct {
	// Name says what the verifier is for, in errors ("token issuers").
	Name string
	// Sources are the key owners; at least one.
	Sources []Source
	// Cache is the disk copy of the JWKS. nil: no fallback, and a JWKS
	// unreachable at start stops the start.
	Cache *JWKSCache
	// Build makes the verifier from one IssuerConfig per source ID. It
	// must fetch through Cache.Client() so every good fetch is recorded.
	Build func(ctx context.Context, sources map[string]coreauth.IssuerConfig) (*T, error)
	// Component shows "stale since T" while a source runs on its disk
	// copy; nil shows it nowhere.
	Component *obs.Component
}

// Reloading holds a verifier built from the issuers' JWKS, and, when an
// issuer was unreachable at start, the verifier built on its disk copy
// until the issuer answers again (Retry). It is safe for concurrent use.
type Reloading[T any] struct {
	cfg ReloadConfig[T]
	cur atomic.Pointer[T]

	mu    sync.Mutex
	stale map[string]time.Time // source ID -> fetched_at of the copy in use
}

// StartReloading builds the verifier. When the build fails and a cache
// is configured, every URL source that does not answer now is replaced
// by its cached copy; a source with neither fails the start, naming it.
func StartReloading[T any](ctx context.Context, cfg ReloadConfig[T]) (*Reloading[T], error) {
	if len(cfg.Sources) == 0 || cfg.Build == nil {
		return nil, fmt.Errorf("%s: no sources or no build function", cfg.Name)
	}
	r := &Reloading[T]{cfg: cfg, stale: map[string]time.Time{}}
	v, err := cfg.Build(ctx, r.configs(nil))
	if err == nil {
		r.cur.Store(v)
		r.report()
		return r, nil
	}
	if cfg.Cache == nil {
		return nil, fmt.Errorf("%s: %w", cfg.Name, err)
	}
	stale := map[string]time.Time{}
	cached := map[string]jwk.Set{}
	for _, s := range cfg.Sources {
		if s.JWKSURL == "" {
			continue
		}
		ferr := cfg.Cache.Fetch(context.WithoutCancel(ctx), s.JWKSURL)
		if ferr == nil {
			continue
		}
		set, at, ok := cfg.Cache.Lookup(s.JWKSURL)
		if !ok {
			return nil, fmt.Errorf("%s: the JWKS of %s is unreachable at start (%w) and %s holds no copy of it",
				cfg.Name, s.ID, ferr, cfg.Cache.Path())
		}
		stale[s.ID], cached[s.ID] = at, set
	}
	v, err = cfg.Build(ctx, r.configs(cached))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.Name, err)
	}
	r.cur.Store(v)
	r.mu.Lock()
	r.stale = stale
	r.mu.Unlock()
	r.report()
	return r, nil
}

// configs is one IssuerConfig per source: the cached set for the IDs in
// cached, the URL or static set otherwise.
func (r *Reloading[T]) configs(cached map[string]jwk.Set) map[string]coreauth.IssuerConfig {
	out := make(map[string]coreauth.IssuerConfig, len(r.cfg.Sources))
	for _, s := range r.cfg.Sources {
		switch {
		case cached[s.ID] != nil:
			out[s.ID] = coreauth.IssuerConfig{Keys: cached[s.ID]}
		case s.JWKSURL != "":
			out[s.ID] = coreauth.IssuerConfig{JWKSURL: s.JWKSURL}
		default:
			out[s.ID] = coreauth.IssuerConfig{Keys: s.Keys}
		}
	}
	return out
}

// Current is the verifier in use.
func (r *Reloading[T]) Current() *T { return r.cur.Load() }

// Stale returns the sources running on their disk copy, with the time
// each copy was fetched; empty when every source is live.
func (r *Reloading[T]) Stale() map[string]time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]time.Time, len(r.stale))
	for k, v := range r.stale {
		out[k] = v
	}
	return out
}

// Retry asks every stale source again; the ones that answer go back to
// their URL and the verifier is rebuilt and swapped in. It returns nil
// when nothing is stale or something recovered, and the last error
// otherwise. The fetch runs on a context of its own (E-14).
func (r *Reloading[T]) Retry(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx)
	stale := r.Stale()
	if len(stale) == 0 {
		return nil
	}
	cached := map[string]jwk.Set{}
	var lastErr error
	recovered := false
	for _, s := range r.cfg.Sources {
		if _, ok := stale[s.ID]; !ok {
			continue
		}
		if err := r.cfg.Cache.Fetch(ctx, s.JWKSURL); err != nil {
			lastErr = err
			set, _, ok := r.cfg.Cache.Lookup(s.JWKSURL)
			if !ok {
				return fmt.Errorf("%s: the copy of %s vanished from %s", r.cfg.Name, s.ID, r.cfg.Cache.Path())
			}
			cached[s.ID] = set
			continue
		}
		recovered = true
		delete(stale, s.ID)
	}
	if !recovered {
		return lastErr
	}
	v, err := r.cfg.Build(ctx, r.configs(cached))
	if err != nil {
		return fmt.Errorf("%s: rebuild: %w", r.cfg.Name, err)
	}
	r.cur.Store(v)
	r.mu.Lock()
	r.stale = stale
	r.mu.Unlock()
	r.report()
	return nil
}

// report sets the component: healthy when every source is live,
// otherwise "stale since <the oldest copy> (<ids>)".
func (r *Reloading[T]) report() {
	if r.cfg.Component == nil {
		return
	}
	stale := r.Stale()
	if len(stale) == 0 {
		r.cfg.Component.SetHealthy()
		return
	}
	ids := make([]string, 0, len(stale))
	var oldest time.Time
	for id, at := range stale {
		ids = append(ids, id)
		if oldest.IsZero() || at.Before(oldest) {
			oldest = at
		}
	}
	sort.Strings(ids)
	r.cfg.Component.SetDegraded(StaleReason(oldest, ids))
}

// StaleReason is the degraded text of a verifier running on disk copies.
func StaleReason(since time.Time, ids []string) string {
	return "stale since " + since.UTC().Format(time.RFC3339) + " (" + strings.Join(ids, ", ") + " unreachable; serving the cached JWKS)"
}
