package console

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// Login limits (docs/WORKPACKAGES/WP-8.md, predecessor S-15): five
// failed attempts lock an account for 15 minutes.
const (
	DefaultMaxFailedLogins = 5
	DefaultLockout         = 15 * time.Minute
	// DefaultHashSlots bounds the argon2id computations running at once
	// (each holds 64 MiB): a burst of logins waits, it never multiplies
	// the process's memory (E-10).
	DefaultHashSlots = 4
	// MaxUsernameBytes and the pattern below bound a username.
	MaxUsernameBytes = 64
	// MaxListedAccounts bounds GET /v1/console/accounts.
	MaxListedAccounts = 1000
	// TOTPLabel is the issuer an authenticator app shows.
	TOTPLabel = "uspace-cisp"
	// initialPasswordBytes is the entropy of a one-time initial password
	// (160 bits, 32 base32 characters).
	initialPasswordBytes = 20
	// DefaultChallengeTTL is how long an MFA challenge of the password
	// step lives (the uspace-authority's default).
	DefaultChallengeTTL = 5 * time.Minute
	// DefaultMaxChallengeAttempts is the wrong codes one challenge takes
	// before it is exhausted (the per-account lockout counts them too).
	DefaultMaxChallengeAttempts = 5
	// MaxChallengeTokenBytes bounds a challenge token read from a body.
	MaxChallengeTokenBytes = 256
	// challengeTokenBytes is the entropy of a challenge token (256 bits,
	// 43 base64url characters).
	challengeTokenBytes = 32
)

// Account statuses.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// The audit events of accounts and sessions.
const (
	EventSessionIssued = "session_issued"
	// EventChallengeIssued is a password accepted for an account with
	// MFA: a challenge was opened, no session yet.
	EventChallengeIssued = "login_challenge_issued"
	EventSessionRevoked  = "session_revoked"
	EventLoginFailed     = "login_failed"
	EventAccountLocked   = "account_locked"
	EventAccountCreated  = "account_created"
	EventAccountChanged  = "account_changed"
)

// Login refusal slugs (problem types).
const (
	SlugInvalidCredentials = "invalid_credentials" //nolint:gosec // G101: a problem slug, not a credential
	SlugLocked             = "locked"
	SlugMFARequired        = "mfa_required"
	SlugInvalidTOTP        = "invalid_totp"
	SlugTOTPReused         = "totp_reused"
	SlugLastAdmin          = "last_admin"
	SlugUsernameTaken      = "username_taken"
	SlugBusy               = "busy"
	// SlugChallengeInvalid is a challenge that is unknown, spent,
	// expired, exhausted, or whose account can no longer sign in: sign
	// in again from the password.
	SlugChallengeInvalid = "challenge_invalid"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,63}$`)

// Error is a refusal of the account service: the HTTP status, the
// problem slug, the field and the detail. RetryAfter is set on a lockout.
type Error struct {
	Status     int
	Slug       string
	Field      string
	Detail     string
	RetryAfter time.Duration
}

func (e *Error) Error() string { return e.Detail }

func refusal(status int, slug, field, detail string) *Error {
	return &Error{Status: status, Slug: slug, Field: field, Detail: detail}
}

// Store is what the account service needs of the store.
type Store interface {
	DatabaseNow(ctx context.Context) (time.Time, error)
	Login(ctx context.Context, username string, decide func(a *store.Account, now time.Time) (store.LoginOutcome, error)) error
	CreateAccount(ctx context.Context, a store.Account, e store.Event) error
	Accounts(ctx context.Context, limit int) ([]store.Account, error)
	Account(ctx context.Context, id string) (store.Account, error)
	PatchAccount(ctx context.Context, id string, decide func(a store.Account, activeAdmins []string, now time.Time) (store.AccountChange, error)) (store.Account, []string, error)
	Session(ctx context.Context, jti string) (store.Session, error)
	RevokeSession(ctx context.Context, jti string, e store.Event) (bool, error)
	ExchangeChallenge(ctx context.Context, tokenHash string, decide func(ch *store.LoginChallenge, a *store.Account, now time.Time) (store.LoginOutcome, error)) error
}

// SessionSigner signs a session token (*auth.SessionIssuer).
type SessionSigner interface {
	Issue(accountID, role, jti string, iat, exp time.Time) (string, error)
}

// Revoker learns at once of a session this replica revoked
// (*auth.RevocationCache).
type Revoker interface {
	Add(jti string)
}

// Config configures the account service.
type Config struct {
	Store    Store
	Sessions SessionSigner
	Sealer   *Sealer
	// Revoker is told of every revoked jti; nil: none.
	Revoker Revoker
	// Argon2 is the parameter set of new hashes (auth.DefaultArgon2).
	Argon2          auth.Argon2Params
	MaxFailedLogins int
	Lockout         time.Duration
	HashSlots       int
	// ChallengeTTL is the life of an MFA challenge (DefaultChallengeTTL);
	// MaxChallengeAttempts the wrong codes it takes
	// (DefaultMaxChallengeAttempts).
	ChallengeTTL         time.Duration
	MaxChallengeAttempts int
	// NewID makes account and session ids (store.NewID).
	NewID func(time.Time) string
}

// Accounts is the console's account and session service: login with
// the lockout and the TOTP replay rule judged under the account row's
// lock on the database's clock, the admin's account changes with the
// last-admin invariant, and logout.
type Accounts struct {
	cfg   Config
	slots chan struct{}
	dummy string
}

// NewAccounts returns the service; it refuses a config without a store,
// a session signer or a sealer.
func NewAccounts(cfg Config) (*Accounts, error) {
	if cfg.Store == nil || cfg.Sessions == nil || cfg.Sealer == nil {
		return nil, errors.New("console accounts: a store, a session signer and a sealer are required")
	}
	if cfg.Argon2 == (auth.Argon2Params{}) {
		cfg.Argon2 = auth.DefaultArgon2
	}
	if cfg.MaxFailedLogins <= 0 {
		cfg.MaxFailedLogins = DefaultMaxFailedLogins
	}
	if cfg.Lockout <= 0 {
		cfg.Lockout = DefaultLockout
	}
	if cfg.HashSlots <= 0 {
		cfg.HashSlots = DefaultHashSlots
	}
	if cfg.ChallengeTTL <= 0 {
		cfg.ChallengeTTL = DefaultChallengeTTL
	}
	if cfg.MaxChallengeAttempts <= 0 {
		cfg.MaxChallengeAttempts = DefaultMaxChallengeAttempts
	}
	if cfg.NewID == nil {
		cfg.NewID = store.NewID
	}
	// A hash of nothing anyone knows: an unknown username costs the same
	// argon2id work as a known one.
	dummy, err := auth.HashPassword(cfg.NewID(time.Now()), cfg.Argon2)
	if err != nil {
		return nil, fmt.Errorf("console accounts: %w", err)
	}
	return &Accounts{cfg: cfg, slots: make(chan struct{}, cfg.HashSlots), dummy: dummy}, nil
}

// Actor is the console account acting.
type Actor struct {
	ID   string
	Role string
	// Type is the events actor_type: account (a console session) or
	// system (cispctl).
	Type string
}

// AccountActor is the actor of a console session.
func AccountActor(id, role string) Actor { return Actor{ID: id, Role: role, Type: store.ActorAccount} }

func (a *Accounts) acquire(ctx context.Context) error {
	select {
	case a.slots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return refusal(http.StatusServiceUnavailable, SlugBusy, "", "too many logins at once; try again")
	}
}

func (a *Accounts) release() { <-a.slots }

// LoginRequest is the body of POST /v1/console/session.
type LoginRequest struct {
	Username string
	Password string
	TOTP     *string
}

// LoginResult is an issued session or, from the password step of an
// account with MFA and no code, an MFA challenge (Challenge set, no
// session).
type LoginResult struct {
	Token     string
	JTI       string
	ExpiresAt time.Time
	Account   store.Account
	Challenge *Challenge
}

// Challenge is an MFA challenge as the password step answers it: the
// token (shown once; only its SHA-256 is stored) and its expiry.
type Challenge struct {
	Token     string
	ExpiresAt time.Time
}

// NormaliseUsername is the stored form of a username (lower case).
func NormaliseUsername(u string) string { return strings.ToLower(u) }

// Login verifies the credentials and issues a session. Five failures
// (a wrong password, a wrong or reused TOTP code) lock the account for
// 15 minutes, judged on the database's clock; a locked account answers
// 423 locked whatever the password. An unknown or disabled username is
// refused as a wrong password is (401 invalid_credentials), after the
// same argon2id work.
//
// An account with MFA and an authenticator, asked without a code, gets
// an MFA challenge in place of a session (the two-step sign-in): the
// right password opens it, counts nothing and resets nothing, so the
// failed-login counter keeps counting the codes VerifyMFA is then sent.
// With a code, the one request still issues the session.
func (a *Accounts) Login(ctx context.Context, req LoginRequest) (LoginResult, error) {
	if err := a.acquire(ctx); err != nil {
		return LoginResult{}, err
	}
	defer a.release()
	username := NormaliseUsername(req.Username)
	invalid := refusal(http.StatusUnauthorized, SlugInvalidCredentials, "password", "the username or the password is wrong")
	if len(username) > MaxUsernameBytes || len(req.Password) > auth.MaxPasswordBytes {
		return LoginResult{}, invalid
	}
	var res LoginResult
	err := a.cfg.Store.Login(ctx, username, func(acc *store.Account, now time.Time) (store.LoginOutcome, error) {
		if acc == nil || acc.Status != StatusActive {
			_, _, _ = auth.VerifyPassword(a.dummy, req.Password, a.cfg.Argon2)
			return store.LoginOutcome{Refusal: invalid}, nil
		}
		if acc.LockedUntil != nil && acc.LockedUntil.After(now) {
			e := refusal(http.StatusLocked, SlugLocked, "username", "the account is locked after repeated failures; try again later")
			e.RetryAfter = acc.LockedUntil.Sub(now)
			return store.LoginOutcome{Refusal: e}, nil
		}
		ok, rehash, err := auth.VerifyPassword(acc.PasswordHash, req.Password, a.cfg.Argon2)
		if err != nil {
			return store.LoginOutcome{}, fmt.Errorf("account %s: %w", acc.ID, err)
		}
		if !ok {
			return a.failed(acc, now, invalid, "password"), nil
		}
		hash := acc.PasswordHash
		if rehash {
			if hash, err = auth.HashPassword(req.Password, a.cfg.Argon2); err != nil {
				return store.LoginOutcome{}, err
			}
		}
		step := acc.TOTPLastStep
		if acc.MFARequired && (req.TOTP == nil || *req.TOTP == "") && len(acc.TOTPSecretEnc) > 0 {
			return a.openChallenge(acc, now, hash, rehash, &res)
		}
		if acc.MFARequired {
			s, refused, err := a.checkTOTP(acc, req.TOTP, now)
			if err != nil {
				return store.LoginOutcome{}, err
			}
			if refused != nil {
				if refused.Slug == SlugMFARequired {
					return store.LoginOutcome{Refusal: refused}, nil
				}
				return a.failed(acc, now, refused, "totp"), nil
			}
			step = &s
		}
		return a.issue(acc, now, hash, step, rehash, false, &res)
	})
	if err != nil {
		return LoginResult{}, err
	}
	return res, nil
}

// issue signs a session for acc and writes it with the account's
// successful login (the counter reset, the last login, the password
// hash, the TOTP step) and its session_issued row; *res is the session.
func (a *Accounts) issue(acc *store.Account, now time.Time, hash string, step *int64, rehash, challenge bool, res *LoginResult) (store.LoginOutcome, error) {
	iat := now.Truncate(time.Second)
	exp := iat.Add(auth.SessionTTL)
	jti := a.cfg.NewID(now)
	token, err := a.cfg.Sessions.Issue(acc.ID, acc.Role, jti, iat, exp)
	if err != nil {
		return store.LoginOutcome{}, fmt.Errorf("session: %w", err)
	}
	last := now
	*res = LoginResult{Token: token, JTI: jti, ExpiresAt: exp, Account: *acc}
	res.Account.LastLoginAt, res.Account.FailedLogins, res.Account.LockedUntil = &last, 0, nil
	return store.LoginOutcome{
		Update:  &store.AccountLoginUpdate{FailedLogins: 0, LastLoginAt: &last, PasswordHash: hash, TOTPLastStep: step},
		Session: &store.NewSession{JTI: jti, AccountID: acc.ID, IssuedAt: iat, ExpiresAt: exp},
		Events: []store.Event{{
			TS: now, ActorType: store.ActorAccount, ActorID: acc.ID, EventType: EventSessionIssued,
			EntityType: "session", EntityID: jti,
			Payload: map[string]any{"role": acc.Role, "expires_at": exp.Format(time.RFC3339), "mfa": acc.MFARequired, "rehashed": rehash, "challenge": challenge},
		}},
	}, nil
}

// openChallenge opens an MFA challenge for acc after its password was
// accepted: a 256-bit token whose SHA-256 is stored, bound to the
// account, expiring after ChallengeTTL. The account row keeps its
// counter and lockout; only a rehashed password is written.
func (a *Accounts) openChallenge(acc *store.Account, now time.Time, hash string, rehash bool, res *LoginResult) (store.LoginOutcome, error) {
	token, tokenHash, err := newChallengeToken()
	if err != nil {
		return store.LoginOutcome{}, err
	}
	exp := now.Add(a.cfg.ChallengeTTL)
	*res = LoginResult{Account: *acc, Challenge: &Challenge{Token: token, ExpiresAt: exp}}
	out := store.LoginOutcome{
		Challenge: &store.NewLoginChallenge{TokenHash: tokenHash, AccountID: acc.ID, CreatedAt: now, ExpiresAt: exp},
		Events: []store.Event{{
			TS: now, ActorType: store.ActorAccount, ActorID: acc.ID, EventType: EventChallengeIssued,
			EntityType: "account", EntityID: acc.ID,
			Payload: map[string]any{"expires_at": exp.Format(time.RFC3339), "rehashed": rehash},
		}},
	}
	if rehash {
		out.Update = &store.AccountLoginUpdate{
			FailedLogins: acc.FailedLogins, LockedUntil: acc.LockedUntil, LastLoginAt: acc.LastLoginAt,
			PasswordHash: hash, TOTPLastStep: acc.TOTPLastStep,
		}
	}
	return out, nil
}

// newChallengeToken is 256 random bits, base64url without padding, and
// the SHA-256 of the token in hex: only the hash is stored.
func newChallengeToken() (token, tokenHash string, err error) {
	b := make([]byte, challengeTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("challenge: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, ChallengeHash(token), nil
}

// ChallengeHash is the stored form of a challenge token: SHA-256, hex.
func ChallengeHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// MFARequest is the body of POST /v1/console/session/mfa.
type MFARequest struct {
	Challenge string
	Code      string
}

// VerifyMFA exchanges an MFA challenge and a TOTP code for a session (the
// second step of the two-step sign-in), judged under the account's and
// the challenge's row locks on the database's clock. A challenge is
// single use, expires after ChallengeTTL and takes MaxChallengeAttempts
// wrong codes; an unknown, spent, expired or exhausted one, or one whose
// account is disabled, is 401 challenge_invalid (sign in again). A
// locked account is 423 locked. A wrong or reused code is 401
// invalid_totp or totp_reused, counts one attempt on the challenge and
// one failure towards the account's lockout, as in the one-step login.
func (a *Accounts) VerifyMFA(ctx context.Context, req MFARequest) (LoginResult, error) {
	invalid := func(detail string) *Error {
		return refusal(http.StatusUnauthorized, SlugChallengeInvalid, "mfa_token", detail)
	}
	if req.Challenge == "" || len(req.Challenge) > MaxChallengeTokenBytes {
		return LoginResult{}, invalid("the sign-in challenge is not valid; sign in again")
	}
	var res LoginResult
	err := a.cfg.Store.ExchangeChallenge(ctx, ChallengeHash(req.Challenge), func(ch *store.LoginChallenge, acc *store.Account, now time.Time) (store.LoginOutcome, error) {
		if ch == nil || acc == nil {
			return store.LoginOutcome{Refusal: invalid("the sign-in challenge is not valid; sign in again")}, nil
		}
		refuse := func(reason, detail string) store.LoginOutcome {
			return store.LoginOutcome{Refusal: invalid(detail), Events: []store.Event{{
				TS: now, ActorType: store.ActorAccount, ActorID: acc.ID, EventType: EventLoginFailed,
				EntityType: "account", EntityID: acc.ID,
				Payload: map[string]any{"field": "mfa_token", "reason": reason, "failed_logins": acc.FailedLogins},
			}}}
		}
		switch {
		case ch.UsedAt != nil:
			return refuse("challenge_used", "the sign-in challenge was used; sign in again"), nil
		case !now.Before(ch.ExpiresAt):
			return refuse("challenge_expired", "the sign-in challenge expired; sign in again"), nil
		case ch.Attempts >= a.cfg.MaxChallengeAttempts:
			return refuse("challenge_exhausted", "too many wrong codes for this sign-in; sign in again"), nil
		case acc.Status != StatusActive:
			return refuse("account_disabled", "the sign-in challenge is not valid; sign in again"), nil
		}
		if acc.LockedUntil != nil && acc.LockedUntil.After(now) {
			e := refusal(http.StatusLocked, SlugLocked, "username", "the account is locked after repeated failures; try again later")
			e.RetryAfter = acc.LockedUntil.Sub(now)
			return store.LoginOutcome{Refusal: e}, nil
		}
		code := req.Code
		step, refused, err := a.checkTOTP(acc, &code, now)
		if err != nil {
			return store.LoginOutcome{}, err
		}
		if refused != nil {
			if refused.Slug == SlugMFARequired {
				return store.LoginOutcome{Refusal: refused}, nil
			}
			out := a.failed(acc, now, refused, "totp")
			out.ChallengeAttempt = true
			return out, nil
		}
		out, err := a.issue(acc, now, acc.PasswordHash, &step, false, true, &res)
		if err != nil {
			return store.LoginOutcome{}, err
		}
		out.ChallengeUsed = true
		return out, nil
	})
	if err != nil {
		return LoginResult{}, err
	}
	return res, nil
}

// failed counts a failure on acc and locks it at the limit.
func (a *Accounts) failed(acc *store.Account, now time.Time, refused *Error, field string) store.LoginOutcome {
	n := acc.FailedLogins + 1
	out := store.LoginOutcome{Refusal: refused}
	ev := store.Event{
		TS: now, ActorType: store.ActorAccount, ActorID: acc.ID, EventType: EventLoginFailed,
		EntityType: "account", EntityID: acc.ID, Payload: map[string]any{"failed_logins": n, "field": field, "reason": refused.Slug},
	}
	out.Events = append(out.Events, ev)
	u := &store.AccountLoginUpdate{FailedLogins: n, LastLoginAt: acc.LastLoginAt, PasswordHash: acc.PasswordHash, TOTPLastStep: acc.TOTPLastStep}
	if n >= a.cfg.MaxFailedLogins {
		until := now.Add(a.cfg.Lockout)
		u.FailedLogins, u.LockedUntil = 0, &until
		out.Events = append(out.Events, store.Event{
			TS: now, ActorType: store.ActorSystem, ActorID: "console", EventType: EventAccountLocked,
			EntityType: "account", EntityID: acc.ID, Payload: map[string]any{"locked_until": until.Format(time.RFC3339), "after_failures": n},
		})
	}
	out.Update = u
	return out
}

// checkTOTP judges a TOTP code: absent is mfa_required (not a failure);
// one that matches no step within the skew is invalid_totp, one whose
// step is not above the account's last accepted step totp_reused.
func (a *Accounts) checkTOTP(acc *store.Account, code *string, now time.Time) (int64, *Error, error) {
	if len(acc.TOTPSecretEnc) == 0 {
		return 0, refusal(http.StatusUnauthorized, SlugMFARequired, "totp", "this account needs a TOTP code but has no authenticator enrolled; an admin resets its MFA"), nil
	}
	if code == nil || *code == "" {
		return 0, refusal(http.StatusUnauthorized, SlugMFARequired, "totp", "this account needs a TOTP code"), nil
	}
	secret, err := a.cfg.Sealer.Open(acc.ID, acc.TOTPSecretEnc)
	if err != nil {
		return 0, nil, fmt.Errorf("account %s: %w", acc.ID, err)
	}
	step, ok := auth.MatchTOTP(string(secret), *code, now)
	if !ok {
		return 0, refusal(http.StatusUnauthorized, SlugInvalidTOTP, "totp", "the TOTP code is wrong"), nil
	}
	if acc.TOTPLastStep != nil && step <= *acc.TOTPLastStep {
		return 0, refusal(http.StatusUnauthorized, SlugTOTPReused, "totp", "this TOTP code was already used; wait for the next one"), nil
	}
	return step, nil, nil
}

// Created is a new account with its one-time secrets: the initial
// password and, when MFA is required, the otpauth URL. Neither is stored
// in the clear or shown again.
type Created struct {
	Account  store.Account
	Password string
	TOTPURL  string
}

// Create makes an account: the username (lower case, 3-64 of a-z 0-9 .
// _ -), the role, a generated one-time password and, for admin (always)
// or when asked, MFA with a new TOTP secret sealed under
// CISP_SECRETS_KEY_FILE.
func (a *Accounts) Create(ctx context.Context, actor Actor, username, role string, mfa bool) (Created, error) {
	username = NormaliseUsername(username)
	if !usernamePattern.MatchString(username) {
		return Created{}, refusal(http.StatusBadRequest, "bad_request", "username", "3-64 characters of a-z 0-9 . _ - starting with a letter or digit")
	}
	if _, ok := auth.RoleRank(role); !ok {
		return Created{}, refusal(http.StatusBadRequest, "bad_request", "role", "one of viewer, publisher_admin, admin")
	}
	mfa = mfa || role == auth.RoleAdmin
	now, err := a.cfg.Store.DatabaseNow(ctx)
	if err != nil {
		return Created{}, err
	}
	password, err := NewPassword()
	if err != nil {
		return Created{}, err
	}
	if err := a.acquire(ctx); err != nil {
		return Created{}, err
	}
	hash, err := auth.HashPassword(password, a.cfg.Argon2)
	a.release()
	if err != nil {
		return Created{}, err
	}
	acc := store.Account{ID: a.cfg.NewID(now), Username: username, PasswordHash: hash, Role: role, MFARequired: mfa, Status: StatusActive, CreatedAt: now}
	out := Created{Account: acc, Password: password}
	if mfa {
		sealed, url, err := a.newTOTP(acc.ID, username)
		if err != nil {
			return Created{}, err
		}
		out.Account.TOTPSecretEnc, out.TOTPURL = sealed, url
	}
	err = a.cfg.Store.CreateAccount(ctx, out.Account, store.Event{
		TS: now, ActorType: actor.Type, ActorID: actor.ID, EventType: EventAccountCreated, EntityType: "account", EntityID: acc.ID,
		Payload: map[string]any{"username": username, "role": role, "mfa_required": mfa, "actor_role": actor.Role},
	})
	if errors.Is(err, store.ErrUsernameTaken) {
		return Created{}, refusal(http.StatusConflict, SlugUsernameTaken, "username", "another account has this username")
	}
	if err != nil {
		return Created{}, err
	}
	return out, nil
}

func (a *Accounts) newTOTP(accountID, username string) ([]byte, string, error) {
	secret, url, err := auth.NewTOTPSecret(TOTPLabel, username)
	if err != nil {
		return nil, "", err
	}
	sealed, err := a.cfg.Sealer.Seal(accountID, []byte(secret))
	if err != nil {
		return nil, "", err
	}
	return sealed, url, nil
}

// NewPassword is a one-time initial password: 160 random bits as 32
// base32 characters.
func NewPassword() (string, error) {
	b := make([]byte, initialPasswordBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("password: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// Patch is an admin's change to an account; nil members are unchanged.
type Patch struct {
	Role     *string
	Status   *string
	ResetMFA bool
}

// Patched is the account as written, the otpauth URL of a new TOTP
// secret (once), and the sessions revoked.
type Patched struct {
	Account store.Account
	TOTPURL string
	Revoked []string
}

// Patch changes role, status or MFA. The last active admin can be
// neither demoted nor disabled (409 last_admin, judged under the locks
// of every active admin row). An admin always has MFA: a promotion to
// admin enrols it. A changed role or status revokes the account's open
// sessions (the role travels in the token).
func (a *Accounts) Patch(ctx context.Context, actor Actor, id string, p Patch) (Patched, error) {
	if p.Role != nil {
		if _, ok := auth.RoleRank(*p.Role); !ok {
			return Patched{}, refusal(http.StatusBadRequest, "bad_request", "role", "one of viewer, publisher_admin, admin")
		}
	}
	if p.Status != nil && *p.Status != StatusActive && *p.Status != StatusDisabled {
		return Patched{}, refusal(http.StatusBadRequest, "bad_request", "status", "one of active, disabled")
	}
	var url string
	acc, revoked, err := a.cfg.Store.PatchAccount(ctx, id, func(cur store.Account, admins []string, now time.Time) (store.AccountChange, error) {
		ch := store.AccountChange{Role: cur.Role, Status: cur.Status, MFARequired: cur.MFARequired, TOTPSecretEnc: cur.TOTPSecretEnc, TOTPLastStep: cur.TOTPLastStep}
		if p.Role != nil {
			ch.Role = *p.Role
		}
		if p.Status != nil {
			ch.Status = *p.Status
		}
		wasAdmin := cur.Role == auth.RoleAdmin && cur.Status == StatusActive
		staysAdmin := ch.Role == auth.RoleAdmin && ch.Status == StatusActive
		if wasAdmin && !staysAdmin && len(admins) <= 1 {
			return ch, refusal(http.StatusConflict, SlugLastAdmin, "role", "this is the last active admin; promote another account first")
		}
		if ch.Role == auth.RoleAdmin {
			ch.MFARequired = true
		}
		changes := map[string]any{}
		if ch.Role != cur.Role {
			changes["role"] = map[string]any{"from": cur.Role, "to": ch.Role}
		}
		if ch.Status != cur.Status {
			changes["status"] = map[string]any{"from": cur.Status, "to": ch.Status}
		}
		if p.ResetMFA || (ch.MFARequired && len(cur.TOTPSecretEnc) == 0) {
			sealed, u, err := a.newTOTP(cur.ID, cur.Username)
			if err != nil {
				return ch, err
			}
			ch.TOTPSecretEnc, ch.TOTPLastStep, url = sealed, nil, u
			changes["mfa"] = "reset"
		}
		ch.RevokeSessions = ch.Role != cur.Role || ch.Status != cur.Status
		ch.Event = store.Event{
			TS: now, ActorType: actor.Type, ActorID: actor.ID, EventType: EventAccountChanged, EntityType: "account", EntityID: cur.ID,
			Payload: map[string]any{"changes": changes, "actor_role": actor.Role, "sessions_revoked": ch.RevokeSessions},
		}
		return ch, nil
	})
	if errors.Is(err, store.ErrNotFound) {
		return Patched{}, refusal(http.StatusNotFound, "not_found", "id", "no such account")
	}
	if err != nil {
		return Patched{}, err
	}
	if a.cfg.Revoker != nil {
		for _, j := range revoked {
			a.cfg.Revoker.Add(j)
		}
	}
	return Patched{Account: acc, TOTPURL: url, Revoked: revoked}, nil
}

// List is the accounts by username.
func (a *Accounts) List(ctx context.Context) ([]store.Account, error) {
	return a.cfg.Store.Accounts(ctx, MaxListedAccounts)
}

// Me is the caller's account and its session.
func (a *Accounts) Me(ctx context.Context, accountID, jti string) (store.Account, store.Session, error) {
	acc, err := a.cfg.Store.Account(ctx, accountID)
	if errors.Is(err, store.ErrNotFound) {
		return store.Account{}, store.Session{}, refusal(http.StatusNotFound, "not_found", "sub", "the session's account no longer exists")
	}
	if err != nil {
		return store.Account{}, store.Session{}, err
	}
	s, err := a.cfg.Store.Session(ctx, jti)
	if errors.Is(err, store.ErrNotFound) {
		return store.Account{}, store.Session{}, refusal(http.StatusNotFound, "not_found", "jti", "no such session")
	}
	if err != nil {
		return store.Account{}, store.Session{}, err
	}
	return acc, s, nil
}

// Logout revokes the caller's session with its audit row and tells the
// revocation cache at once.
func (a *Accounts) Logout(ctx context.Context, actor Actor, jti string) error {
	now, err := a.cfg.Store.DatabaseNow(ctx)
	if err != nil {
		return err
	}
	if _, err := a.cfg.Store.RevokeSession(ctx, jti, store.Event{
		TS: now, ActorType: actor.Type, ActorID: actor.ID, EventType: EventSessionRevoked, EntityType: "session", EntityID: jti,
		Payload: map[string]any{"actor_role": actor.Role, "by": "logout"},
	}); err != nil {
		return err
	}
	if a.cfg.Revoker != nil {
		a.cfg.Revoker.Add(jti)
	}
	return nil
}

// RetryAfterSeconds is the Retry-After value of a lockout (at least 1).
func RetryAfterSeconds(d time.Duration) string {
	s := int64((d + time.Second - 1) / time.Second)
	if s < 1 {
		s = 1
	}
	return strconv.FormatInt(s, 10)
}
