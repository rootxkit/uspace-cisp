package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// Token verification settings of docs/PLAN.md section 8.2: 30 s of
// clock skew and a 24 h JWKS cache, core's defaults, named here so a
// change in core's defaults does not silently change the CISP.
const (
	MachineMaxSkew      = 30 * time.Second
	MachineJWKSCacheTTL = 24 * time.Hour
)

// MachineConfig configures NewMachineVerifier.
type MachineConfig struct {
	// Issuers are the allow-listed token issuers (ID = iss).
	Issuers []Source
	// Audiences are the accepted aud values (CISP_AUDIENCES); at least one.
	Audiences []string
	// Cache is the JWKS disk copy; nil: none (start fails when an issuer
	// is down). Its client fetches every JWKS when set.
	Cache *JWKSCache
	// HTTPClient fetches the JWKS when Cache is nil; nil: core's client.
	HTTPClient *http.Client
	// Component shows the stale state ("jwks: stale since T").
	Component *obs.Component
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// MinRefreshInterval rate-limits JWKS fetches per issuer (0: core's
	// default, one minute). Tests shorten it.
	MinRefreshInterval time.Duration
}

// MachineConfigFrom is the machine verifier configuration of the api.
func MachineConfigFrom(cfg *config.API, cache *JWKSCache, comp *obs.Component) MachineConfig {
	issuers := []Source{{ID: cfg.TokenIssuer, JWKSURL: cfg.TokenJWKSURL}}
	if cfg.LabIssuer != "" {
		issuers = append(issuers, Source{ID: cfg.LabIssuer, JWKSURL: cfg.LabJWKSURL})
	}
	return MachineConfig{Issuers: issuers, Audiences: cfg.Audiences, Cache: cache, Component: comp}
}

// MachineVerifier verifies ecosystem bearer tokens with uspace-core's
// verifier, one per process, rebuilt only when an issuer that was down at
// start comes back (Reloading).
type MachineVerifier struct {
	r *Reloading[coreauth.Verifier]
}

// NewMachineVerifier builds the verifier and fetches every issuer's JWKS
// (see the package documentation for the disk copy). Call Retry
// periodically to go back to an issuer that was down at start.
func NewMachineVerifier(ctx context.Context, mc MachineConfig) (*MachineVerifier, error) {
	if len(mc.Audiences) == 0 {
		return nil, errors.New("machine verifier: no audience configured")
	}
	client := mc.HTTPClient
	if mc.Cache != nil {
		client = mc.Cache.Client()
	}
	r, err := StartReloading(ctx, ReloadConfig[coreauth.Verifier]{
		Name:      "token issuers",
		Sources:   mc.Issuers,
		Cache:     mc.Cache,
		Component: mc.Component,
		Build: func(ctx context.Context, issuers map[string]coreauth.IssuerConfig) (*coreauth.Verifier, error) {
			return coreauth.NewVerifier(ctx, coreauth.Config{
				Issuers:             issuers,
				Audience:            mc.Audiences[0],
				Audiences:           mc.Audiences,
				StrictSessionClaims: true,
				MaxSkew:             MachineMaxSkew,
				JWKSCacheTTL:        MachineJWKSCacheTTL,
				MinRefreshInterval:  mc.MinRefreshInterval,
				HTTPClient:          client,
				Now:                 mc.Now,
			})
		},
	})
	if err != nil {
		return nil, err
	}
	return &MachineVerifier{r: r}, nil
}

// Verify verifies a compact token. Every refusal is a *coreauth.TokenError
// naming the claim.
func (m *MachineVerifier) Verify(ctx context.Context, token string) (coreauth.Claims, error) {
	return m.r.Current().Verify(ctx, token)
}

// Stale returns the issuers whose disk copy is in use, with its time.
func (m *MachineVerifier) Stale() map[string]time.Time { return m.r.Stale() }

// Retry asks the stale issuers again (see Reloading.Retry).
func (m *MachineVerifier) Retry(ctx context.Context) error { return m.r.Retry(ctx) }
