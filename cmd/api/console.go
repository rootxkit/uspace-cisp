package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/httpapi"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// revocationRefresh is how often every replica reloads the revoked
// sessions (docs/WORKPACKAGES/WP-8.md: a revoked session is refused
// within 10 s).
const revocationRefresh = 10 * time.Second

// maxSessionKeyBytes bounds the session key file read.
const maxSessionKeyBytes = 64 << 10

// consoleNotConfigured is the console component's warning while the
// console variables are unset.
const consoleNotConfigured = "not configured (" + config.EnvSessionKeyFile + ", " + config.EnvConsoleIssuer + ", " +
	config.EnvSecretsKey + "): every /v1/console/* operation answers 503"

// consoleKeys are the console's keys, loaded at start: the session
// issuer and the TOTP sealer. Both nil when the console is not
// configured.
type consoleKeys struct {
	issuer *auth.SessionIssuer
	sealer *console.Sealer
}

// loadConsoleKeys reads the session key and the secrets key; a key that
// does not load stops the start, naming its variable.
func loadConsoleKeys(cfg *config.API) (consoleKeys, error) {
	if !cfg.ConsoleConfigured() {
		return consoleKeys{}, nil
	}
	sealer, err := console.NewSealer(cfg.SecretsKey)
	if err != nil {
		return consoleKeys{}, err
	}
	raw, err := readBounded(cfg.SessionKeyFile, maxSessionKeyBytes)
	if err != nil {
		return consoleKeys{}, fmt.Errorf("%s: %w", config.EnvSessionKeyFile, err)
	}
	key, err := jws.ParsePrivateKeyPEM(raw)
	if err != nil {
		return consoleKeys{}, fmt.Errorf("%s: %w", config.EnvSessionKeyFile, err)
	}
	if bits := key.N.BitLen(); bits < jws.MinRSABits {
		return consoleKeys{}, fmt.Errorf("%s: %d bits, shorter than %d", config.EnvSessionKeyFile, bits, jws.MinRSABits)
	}
	issuer, err := auth.NewSessionIssuer(key, cfg.ConsoleIssuer, cfg.Audiences[0])
	if err != nil {
		return consoleKeys{}, err
	}
	return consoleKeys{issuer: issuer, sealer: sealer}, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the operator's configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("larger than %d bytes: not a PEM key", limit)
	}
	return raw, nil
}

// consoleParts is what serve wires for the console: the server's
// console, the guard the stream verifies cookies with, and the route
// middleware.
type consoleParts struct {
	server *httpapi.Console
	guard  *auth.SessionGuard
	routes map[string]func(http.Handler) http.Handler
}

// startConsole builds the console on the store: the revocation cache
// (refreshed every 10 s until ctx ends), the session guard on the
// shared verifier, the account service, the handlers and the routes
// with the per-address login limiter. Without the console variables the
// console's routes answer 503 and the status line warns.
func startConsole(ctx context.Context, cfg *config.API, keys consoleKeys, sec *security, st *store.Store,
	server *httpapi.Server, status *obs.Status, logger *slog.Logger,
) (consoleParts, error) {
	comp := status.Component("console")
	if keys.issuer == nil || st == nil {
		comp.SetWarning(consoleNotConfigured)
		return consoleParts{routes: httpapi.ConsoleOffRoutes()}, nil
	}
	cache := auth.NewRevocationCache(auth.RevocationCacheConfig{Source: st, Component: status.Component("console_auth")})
	if err := cache.Refresh(ctx); err != nil {
		// The cache is bypassed until a refresh succeeds: every check
		// asks the database, and fails closed while it is down.
		logger.WarnContext(ctx, "console: revoked sessions not read at start; checking each session in the database", "error", err.Error())
	}
	tick := time.NewTicker(revocationRefresh)
	go func() {
		defer tick.Stop()
		cache.Run(ctx, tick.C)
	}()
	guard, err := auth.NewSessionGuard(auth.SessionGuardConfig{
		Verifier: sec.machine, Issuer: keys.issuer.Issuer(), Revocations: cache, Problems: httpapi.WriteProblem,
		Component: status.Component("console_auth"), Logger: logger, LogEvery: cfg.StatusInterval,
	})
	if err != nil {
		return consoleParts{}, err
	}
	accounts, err := console.NewAccounts(console.Config{Store: st, Sessions: keys.issuer, Sealer: keys.sealer, Revoker: cache})
	if err != nil {
		return consoleParts{}, err
	}
	limiter := httpapi.NewRateLimiter(httpapi.RateLimiterConfig{
		Burst: httpapi.LoginBurst, Window: httpapi.LoginWindow, TrustedProxies: cfg.TrustedProxies(),
		Component: status.Component("console_login_ratelimit"),
	})
	routes, err := httpapi.ConsoleAuth{Sessions: guard, Login: limiter}.Routes()
	if err != nil {
		return consoleParts{}, err
	}
	c := &httpapi.Console{
		Accounts: accounts, Store: st, Subscriptions: server.Subscriptions, Restrictions: server.Restrictions,
		Report: server.Status, Registry: status, PublicBaseURL: cfg.PublicBaseURL, Logger: logger,
	}
	comp.SetHealthy()
	logger.InfoContext(ctx, "console ready", "issuer", keys.issuer.Issuer(), "session_kid", keys.issuer.KID())
	return consoleParts{server: c, guard: guard, routes: routes}, nil
}
