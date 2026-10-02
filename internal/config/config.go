// Package config loads, validates and redacts the CISP_* environment of
// each process (docs/PLAN.md section 11). One struct per process; every
// problem is reported at once as a *core.FieldError naming the variable;
// a CISP_* variable that is not in the catalogue is refused, so a typo
// never silently takes a default.
package config

import (
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Common is what every process reads.
type Common struct {
	LogLevel        string
	StatusInterval  time.Duration
	ShutdownTimeout time.Duration
	OTelEndpoint    string

	vars map[string]string
}

// API is the configuration of cmd/api.
type API struct {
	Common

	HTTPAddr       string
	HandlerTimeout time.Duration
	MaxBodyBytes   int64
	// BodyReadMinBytesPerS is the slowest upload accepted: a body gets
	// its route cap divided by this rate (at least HandlerTimeout) to
	// arrive, before the handler deadline starts.
	BodyReadMinBytesPerS int64

	DatabaseURL   string
	TimeseriesURL string
	NATSURL       string
	NATSCredsFile string

	DatabaseMaxConns   int64
	TimeseriesMaxConns int64

	TokenIssuer       string
	TokenJWKSURL      string
	LabIssuer         string
	LabJWKSURL        string
	JWKSCacheFile     string
	Audiences         []string
	AuthorityClientID string
	ANSPClientID      string
	ANSPJWKSURL       string
	ANSPMTLSSubject   string
	MTLSMode          string

	SigningKeyFile     string
	SigningKID         string
	SigningKeyPrevFile string
	SigningKIDPrev     string
	SessionKeyFile     string
	SecretsKey         string

	// PublisherSignatureMaxSkew bounds how far the iat of a publisher's
	// detached signature may be from now, either way.
	PublisherSignatureMaxSkew time.Duration

	PublicBaseURL string
	IssuerURL     string
	ReadMaxAge    time.Duration
	PublicRPM     int64
	// TrustedProxyCIDR lists the proxies (Caddy) whose X-Forwarded-For
	// names the client of a public read.
	TrustedProxyCIDR          []string
	MaxPublicationBytes       int64
	MaxSubscriptionsPerClient int64
	// AllowPrivateCallbacks and AllowInsecureCallbacks are the callback
	// URL policy a registration is judged by (deliver judges every dial
	// by the same two variables).
	AllowPrivateCallbacks  bool
	AllowInsecureCallbacks bool
	BrandingFile           string
	// MaxRestrictionBytes caps a restriction body (POST and PATCH
	// /v1/restrictions; 256 KiB).
	MaxRestrictionBytes int64
	// ExpiryInterval is the restriction expiry's tick; ExpiryStaleAfter
	// is how old its last run may be before the status line errs.
	ExpiryInterval   time.Duration
	ExpiryStaleAfter time.Duration
}

// Deliver is the configuration of cmd/deliver.
type Deliver struct {
	Common

	HTTPAddr string

	DatabaseURL   string
	TimeseriesURL string
	NATSURL       string
	NATSCredsFile string

	DatabaseMaxConns   int64
	TimeseriesMaxConns int64

	SigningKeyFile string
	SigningKID     string
	IssuerURL      string
	// PublicBaseURL prefixes every pull_url (M5: receivers honour a
	// pull_url only on the CISP's own host).
	PublicBaseURL string

	DeliveryLogRetentionDays int64
	AllowPrivateCallbacks    bool
	AllowInsecureCallbacks   bool
}

// Ctl is the configuration of cmd/cispctl.
type Ctl struct {
	Common

	DatabaseURL   string
	TimeseriesURL string

	DatabaseMaxConns   int64
	TimeseriesMaxConns int64

	SigningKeyFile     string
	SigningKID         string
	SigningKeyPrevFile string
	SigningKIDPrev     string
	SessionKeyFile     string
	SecretsKey         string
}

func loadCommon(e *env) Common {
	return Common{
		LogLevel:        e.str(EnvLogLevel),
		StatusInterval:  e.seconds(EnvStatusIntervalS),
		ShutdownTimeout: e.seconds(EnvShutdownTimeoutS),
		OTelEndpoint:    e.str(EnvOTelEndpoint),
	}
}

// LoadAPI reads the api configuration from environ (os.Environ() form)
// and validates it. The error, when not nil, is FieldErrors.
func LoadAPI(environ []string) (*API, error) {
	e := newEnv(environ)
	c := &API{
		Common:         loadCommon(e),
		HTTPAddr:       e.str(EnvHTTPAddr),
		HandlerTimeout: e.seconds(EnvHandlerTimeoutS),
		MaxBodyBytes:   e.integer(EnvMaxBodyBytes),

		BodyReadMinBytesPerS: e.integer(EnvBodyReadMinBytesPerS),

		DatabaseURL:   e.str(EnvDatabaseURL),
		TimeseriesURL: e.str(EnvTimeseriesURL),
		NATSURL:       e.str(EnvNATSURL),
		NATSCredsFile: e.str(EnvNATSCredsFile),

		DatabaseMaxConns:   e.integer(EnvDatabaseMaxConns),
		TimeseriesMaxConns: e.integer(EnvTimeseriesMaxConns),

		TokenIssuer:       e.str(EnvTokenIssuer),
		TokenJWKSURL:      e.str(EnvTokenJWKSURL),
		LabIssuer:         e.str(EnvLabIssuer),
		LabJWKSURL:        e.str(EnvLabJWKSURL),
		JWKSCacheFile:     e.str(EnvJWKSCacheFile),
		Audiences:         e.list(EnvAudiences),
		AuthorityClientID: e.str(EnvAuthorityClientID),
		ANSPClientID:      e.str(EnvANSPClientID),
		ANSPJWKSURL:       e.str(EnvANSPJWKSURL),
		ANSPMTLSSubject:   e.str(EnvANSPMTLSSubject),
		MTLSMode:          e.str(EnvMTLSMode),

		SigningKeyFile:     e.str(EnvSigningKeyFile),
		SigningKID:         e.str(EnvSigningKID),
		SigningKeyPrevFile: e.str(EnvSigningKeyPrevFile),
		SigningKIDPrev:     e.str(EnvSigningKIDPrev),
		SessionKeyFile:     e.str(EnvSessionKeyFile),
		SecretsKey:         e.str(EnvSecretsKey),

		PublisherSignatureMaxSkew: e.seconds(EnvPublisherSigMaxSkewS),

		PublicBaseURL:             e.str(EnvPublicBaseURL),
		IssuerURL:                 e.str(EnvIssuerURL),
		ReadMaxAge:                e.seconds(EnvReadMaxAgeS),
		PublicRPM:                 e.integer(EnvPublicRPM),
		TrustedProxyCIDR:          e.list(EnvTrustedProxyCIDR),
		MaxPublicationBytes:       e.integer(EnvMaxPublicationBytes),
		MaxSubscriptionsPerClient: e.integer(EnvMaxSubscriptionsPerClient),
		AllowPrivateCallbacks:     e.boolean(EnvAllowPrivateCallbacks),
		AllowInsecureCallbacks:    e.boolean(EnvAllowInsecureCallbacks),
		BrandingFile:              e.str(EnvBrandingFile),
		MaxRestrictionBytes:       e.integer(EnvMaxRestrictionBytes),
		ExpiryInterval:            e.seconds(EnvExpiryIntervalS),
		ExpiryStaleAfter:          e.seconds(EnvExpiryStaleAfterS),
	}
	return c, finish(e, &c.Common, c.Validate)
}

// LoadDeliver reads and validates the deliver configuration.
func LoadDeliver(environ []string) (*Deliver, error) {
	e := newEnv(environ)
	c := &Deliver{
		Common:   loadCommon(e),
		HTTPAddr: e.str(EnvDeliverHTTPAddr),

		DatabaseURL:   e.str(EnvDatabaseURL),
		TimeseriesURL: e.str(EnvTimeseriesURL),
		NATSURL:       e.str(EnvNATSURL),
		NATSCredsFile: e.str(EnvNATSCredsFile),

		DatabaseMaxConns:   e.integer(EnvDatabaseMaxConns),
		TimeseriesMaxConns: e.integer(EnvTimeseriesMaxConns),

		SigningKeyFile: e.str(EnvSigningKeyFile),
		SigningKID:     e.str(EnvSigningKID),
		IssuerURL:      e.str(EnvIssuerURL),
		PublicBaseURL:  e.str(EnvPublicBaseURL),

		DeliveryLogRetentionDays: e.integer(EnvDeliveryLogRetentionDays),
		AllowPrivateCallbacks:    e.boolean(EnvAllowPrivateCallbacks),
		AllowInsecureCallbacks:   e.boolean(EnvAllowInsecureCallbacks),
	}
	return c, finish(e, &c.Common, c.Validate)
}

// LoadCtl reads and validates the cispctl configuration.
func LoadCtl(environ []string) (*Ctl, error) {
	e := newEnv(environ)
	c := &Ctl{
		Common:        loadCommon(e),
		DatabaseURL:   e.str(EnvDatabaseURL),
		TimeseriesURL: e.str(EnvTimeseriesURL),

		DatabaseMaxConns:   e.integer(EnvDatabaseMaxConns),
		TimeseriesMaxConns: e.integer(EnvTimeseriesMaxConns),

		SigningKeyFile:     e.str(EnvSigningKeyFile),
		SigningKID:         e.str(EnvSigningKID),
		SigningKeyPrevFile: e.str(EnvSigningKeyPrevFile),
		SigningKIDPrev:     e.str(EnvSigningKIDPrev),
		SessionKeyFile:     e.str(EnvSessionKeyFile),
		SecretsKey:         e.str(EnvSecretsKey),
	}
	return c, finish(e, &c.Common, c.Validate)
}

func finish(e *env, common *Common, validate func() error) error {
	common.vars = e.used
	e.unknown()
	probs := e.probs
	if err := validate(); err != nil {
		if more, ok := err.(FieldErrors); ok { //nolint:errorlint // Validate returns FieldErrors unwrapped
			probs = append(probs, more...)
		}
	}
	if len(probs) == 0 {
		return nil
	}
	return probs
}

// Level is the slog level named by LogLevel (info when it is not valid;
// Validate reports that case).
func (c *Common) Level() slog.Level {
	var l slog.Level
	if err := l.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return slog.LevelInfo
	}
	return l
}

// Redacted is every variable this process read with its effective value,
// for the startup log: secrets are "***", the credentials inside URLs are
// "***", file paths and everything else are printed as they are.
func (c *Common) Redacted() map[string]string {
	out := make(map[string]string, len(c.vars))
	for name, value := range c.vars {
		v, _ := lookupVar(name)
		switch {
		case value == "":
			out[name] = ""
		case v.Secret:
			out[name] = "***"
		case v.SecretURL:
			out[name] = redactURL(value)
		default:
			out[name] = value
		}
	}
	return out
}

// RedactedNames is the sorted list of the variables Redacted covers.
func (c *Common) RedactedNames() []string {
	names := make([]string, 0, len(c.vars))
	for name := range c.vars {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

var credentialParams = []string{"password", "pass", "token", "sslpassword", "secret"}

// redactURL replaces the userinfo password (or a bare token in the user
// position) and credential query parameters with "***". A value that does
// not parse is redacted whole: it cannot be shown safely.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "***"
	}
	var b strings.Builder
	b.WriteString(u.Scheme)
	b.WriteString("://")
	if u.User != nil {
		if _, hasPassword := u.User.Password(); hasPassword {
			b.WriteString(u.User.Username())
			b.WriteString(":***@")
		} else {
			b.WriteString("***@")
		}
	}
	b.WriteString(u.Host)
	b.WriteString(u.EscapedPath())
	if u.RawQuery != "" {
		q := u.Query()
		for key := range q {
			for _, p := range credentialParams {
				if strings.EqualFold(key, p) {
					q.Set(key, "***")
				}
			}
		}
		b.WriteString("?")
		b.WriteString(strings.ReplaceAll(q.Encode(), "%2A%2A%2A", "***"))
	}
	return b.String()
}

// Validate checks the common variables.
func (c *Common) Validate() error {
	var p FieldErrors
	if c.LogLevel != "debug" && c.LogLevel != "info" && c.LogLevel != "warn" && c.LogLevel != "error" {
		p = append(p, core.Fieldf(EnvLogLevel, "%q is not one of debug, info, warn, error", c.LogLevel))
	}
	p = durationIn(p, EnvStatusIntervalS, c.StatusInterval, time.Second, time.Hour)
	p = durationIn(p, EnvShutdownTimeoutS, c.ShutdownTimeout, time.Second, 5*time.Minute)
	p = urlOK(p, EnvOTelEndpoint, c.OTelEndpoint, "http", "https")
	return orNil(p)
}

// Validate checks every api variable and returns every problem at once.
func (c *API) Validate() error {
	p := asProblems(c.Common.Validate())
	p = addrOK(p, EnvHTTPAddr, c.HTTPAddr)
	p = durationIn(p, EnvHandlerTimeoutS, c.HandlerTimeout, time.Second, 5*time.Minute)
	p = intIn(p, EnvMaxBodyBytes, c.MaxBodyBytes, 1024, 1<<30)
	p = intIn(p, EnvBodyReadMinBytesPerS, c.BodyReadMinBytesPerS, 1024, 1<<30)
	p = urlOK(p, EnvDatabaseURL, c.DatabaseURL, "postgres", "postgresql")
	p = urlOK(p, EnvTimeseriesURL, c.TimeseriesURL, "postgres", "postgresql")
	p = intIn(p, EnvDatabaseMaxConns, c.DatabaseMaxConns, 1, 1000)
	p = intIn(p, EnvTimeseriesMaxConns, c.TimeseriesMaxConns, 1, 1000)
	p = urlOK(p, EnvNATSURL, c.NATSURL, "nats", "tls")
	p = required(p, EnvTokenIssuer, c.TokenIssuer)
	p = urlOK(p, EnvTokenIssuer, c.TokenIssuer, "http", "https")
	p = required(p, EnvTokenJWKSURL, c.TokenJWKSURL)
	p = jwksURLOK(p, EnvTokenJWKSURL, c.TokenJWKSURL)
	p = urlOK(p, EnvLabIssuer, c.LabIssuer, "http", "https")
	p = jwksURLOK(p, EnvLabJWKSURL, c.LabJWKSURL)
	p = together(p, EnvLabIssuer, c.LabIssuer, EnvLabJWKSURL, c.LabJWKSURL)
	if c.LabIssuer != "" && c.LabIssuer == c.TokenIssuer {
		p = append(p, core.Fieldf(EnvLabIssuer, "equals %s; the lab issuer is a second, different issuer", EnvTokenIssuer))
	}
	p = required(p, EnvJWKSCacheFile, c.JWKSCacheFile)
	if len(c.Audiences) == 0 {
		p = append(p, core.Fieldf(EnvAudiences, "not set: list the hosts tokens for this CISP name in aud (no default)"))
	}
	for i, h := range c.Audiences {
		if !hostOK(h) {
			p = append(p, core.Fieldf(EnvAudiences+"["+strconv.Itoa(i)+"]", "%q is not a host name (no scheme, path or spaces)", h))
		}
	}
	p = clientIDOK(p, EnvAuthorityClientID, c.AuthorityClientID)
	p = clientIDOK(p, EnvANSPClientID, c.ANSPClientID)
	if c.AuthorityClientID == c.ANSPClientID {
		p = append(p, core.Fieldf(EnvANSPClientID, "equals %s; each publisher has its own client id", EnvAuthorityClientID))
	}
	p = jwksURLOK(p, EnvANSPJWKSURL, c.ANSPJWKSURL)
	switch c.MTLSMode {
	case MTLSRequired:
		p = required(p, EnvANSPMTLSSubject, c.ANSPMTLSSubject)
	case MTLSOff:
	default:
		p = append(p, core.Fieldf(EnvMTLSMode, "%q is not one of required, off", c.MTLSMode))
	}
	p = signingKeysOK(p, c.SigningKeyFile, c.SigningKID, c.SigningKeyPrevFile, c.SigningKIDPrev)
	p = durationIn(p, EnvPublisherSigMaxSkewS, c.PublisherSignatureMaxSkew, time.Second, time.Hour)
	p = urlOK(p, EnvPublicBaseURL, c.PublicBaseURL, "http", "https")
	p = urlOK(p, EnvIssuerURL, c.IssuerURL, "http", "https")
	p = durationIn(p, EnvReadMaxAgeS, c.ReadMaxAge, 0, 24*time.Hour)
	p = intIn(p, EnvPublicRPM, c.PublicRPM, 1, 1_000_000)
	for i, cidr := range c.TrustedProxyCIDR {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			p = append(p, core.Fieldf(EnvTrustedProxyCIDR+"["+strconv.Itoa(i)+"]", "%q is not a CIDR (10.0.0.0/8, 2001:db8::/32, 127.0.0.1/32)", cidr))
		}
	}
	p = intIn(p, EnvMaxPublicationBytes, c.MaxPublicationBytes, 1024, 1<<30)
	p = intIn(p, EnvMaxSubscriptionsPerClient, c.MaxSubscriptionsPerClient, 1, 10_000)
	p = intIn(p, EnvMaxRestrictionBytes, c.MaxRestrictionBytes, 1024, 16<<20)
	p = durationIn(p, EnvExpiryIntervalS, c.ExpiryInterval, time.Second, time.Minute)
	p = durationIn(p, EnvExpiryStaleAfterS, c.ExpiryStaleAfter, 2*time.Second, time.Hour)
	if c.ExpiryStaleAfter <= c.ExpiryInterval {
		p = append(p, core.Fieldf(EnvExpiryStaleAfterS, "%d s is not above %s (%d s): every healthy tick would read as a dead ticker",
			int64(c.ExpiryStaleAfter/time.Second), EnvExpiryIntervalS, int64(c.ExpiryInterval/time.Second)))
	}
	return orNil(p)
}

// TrustedProxies is TrustedProxyCIDR parsed; Validate has refused a
// value that does not parse, so none is left out.
func (c *API) TrustedProxies() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(c.TrustedProxyCIDR))
	for _, cidr := range c.TrustedProxyCIDR {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// Validate checks every deliver variable and returns every problem at once.
func (c *Deliver) Validate() error {
	p := asProblems(c.Common.Validate())
	p = addrOK(p, EnvDeliverHTTPAddr, c.HTTPAddr)
	p = urlOK(p, EnvDatabaseURL, c.DatabaseURL, "postgres", "postgresql")
	p = urlOK(p, EnvTimeseriesURL, c.TimeseriesURL, "postgres", "postgresql")
	p = intIn(p, EnvDatabaseMaxConns, c.DatabaseMaxConns, 1, 1000)
	p = intIn(p, EnvTimeseriesMaxConns, c.TimeseriesMaxConns, 1, 1000)
	p = urlOK(p, EnvNATSURL, c.NATSURL, "nats", "tls")
	if c.SigningKID != "" && !idPattern.MatchString(c.SigningKID) {
		p = append(p, core.Fieldf(EnvSigningKID, "%q must be 1-64 of A-Z a-z 0-9 . _ -", c.SigningKID))
	}
	p = urlOK(p, EnvIssuerURL, c.IssuerURL, "http", "https")
	p = urlOK(p, EnvPublicBaseURL, c.PublicBaseURL, "http", "https")
	if c.DatabaseURL != "" {
		// With a database deliver signs and sends: everything a webhook
		// carries must be configured (no default names this CISP).
		p = required(p, EnvSigningKeyFile, c.SigningKeyFile)
		p = required(p, EnvSigningKID, c.SigningKID)
		p = required(p, EnvIssuerURL, c.IssuerURL)
		p = required(p, EnvPublicBaseURL, c.PublicBaseURL)
	}
	p = intIn(p, EnvDeliveryLogRetentionDays, c.DeliveryLogRetentionDays, 1, 3650)
	return orNil(p)
}

// Validate checks every cispctl variable and returns every problem at once.
func (c *Ctl) Validate() error {
	p := asProblems(c.Common.Validate())
	p = urlOK(p, EnvDatabaseURL, c.DatabaseURL, "postgres", "postgresql")
	p = urlOK(p, EnvTimeseriesURL, c.TimeseriesURL, "postgres", "postgresql")
	p = intIn(p, EnvDatabaseMaxConns, c.DatabaseMaxConns, 1, 1000)
	p = intIn(p, EnvTimeseriesMaxConns, c.TimeseriesMaxConns, 1, 1000)
	p = signingKeysOK(p, c.SigningKeyFile, c.SigningKID, c.SigningKeyPrevFile, c.SigningKIDPrev)
	return orNil(p)
}

// signingKeysOK checks the kids of the signing key and of the previous
// one: well-formed, each set with its file, and distinct.
func signingKeysOK(p FieldErrors, file, kid, prevFile, prevKID string) FieldErrors {
	if kid != "" && !idPattern.MatchString(kid) {
		p = append(p, core.Fieldf(EnvSigningKID, "%q must be 1-64 of A-Z a-z 0-9 . _ -", kid))
	}
	if prevKID != "" && !idPattern.MatchString(prevKID) {
		p = append(p, core.Fieldf(EnvSigningKIDPrev, "%q must be 1-64 of A-Z a-z 0-9 . _ -", prevKID))
	}
	p = together(p, EnvSigningKeyFile, file, EnvSigningKID, kid)
	p = together(p, EnvSigningKeyPrevFile, prevFile, EnvSigningKIDPrev, prevKID)
	if prevFile != "" && file == "" {
		p = append(p, core.Fieldf(EnvSigningKeyPrevFile, "set without %s: a previous key needs a current one", EnvSigningKeyFile))
	}
	if kid != "" && kid == prevKID {
		p = append(p, core.Fieldf(EnvSigningKIDPrev, "equals %s; the two keys need distinct kids", EnvSigningKID))
	}
	return p
}

// required reports an empty value of a variable that has no default.
func required(p FieldErrors, name, value string) FieldErrors {
	if value == "" {
		return append(p, core.Fieldf(name, "not set; it has no default"))
	}
	return p
}

// together reports one of a pair set without the other.
func together(p FieldErrors, nameA, a, nameB, b string) FieldErrors {
	switch {
	case a != "" && b == "":
		return append(p, core.Fieldf(nameB, "not set, but %s is: set both or neither", nameA))
	case a == "" && b != "":
		return append(p, core.Fieldf(nameA, "not set, but %s is: set both or neither", nameB))
	}
	return p
}

// jwksURLOK accepts an empty value or an https URL; plain http only for
// a loopback host (uspace-core/auth refuses the rest at start; this says
// so with the variable's name first).
func jwksURLOK(p FieldErrors, name, raw string) FieldErrors {
	before := len(p)
	p = urlOK(p, name, raw, "http", "https")
	if raw == "" || len(p) > before {
		return p
	}
	u, err := url.Parse(raw)
	if err == nil && strings.EqualFold(u.Scheme, "http") && !loopback(u.Hostname()) {
		return append(p, core.Fieldf(name, "plain http is allowed for localhost only; use https"))
	}
	return p
}

// loopback is the hosts uspace-core/auth lets a JWKS URL reach over
// plain http.
func loopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func asProblems(err error) FieldErrors {
	if p, ok := err.(FieldErrors); ok { //nolint:errorlint // Validate returns FieldErrors unwrapped
		return p
	}
	return nil
}

func orNil(p FieldErrors) error {
	if len(p) == 0 {
		return nil
	}
	return p
}

func durationIn(p FieldErrors, name string, d, lo, hi time.Duration) FieldErrors {
	if d < lo || d > hi {
		return append(p, core.Fieldf(name, "%d s is outside %d..%d s", int64(d/time.Second), int64(lo/time.Second), int64(hi/time.Second)))
	}
	return p
}

func intIn(p FieldErrors, name string, n, lo, hi int64) FieldErrors {
	if n < lo || n > hi {
		return append(p, core.Fieldf(name, "%d is outside %d..%d", n, lo, hi))
	}
	return p
}

func addrOK(p FieldErrors, name, addr string) FieldErrors {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return append(p, core.Fieldf(name, "%q is not host:port", addr))
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return append(p, core.Fieldf(name, "port %q is not 0..65535", port))
	}
	return p
}

// urlOK accepts an empty value (not configured) or an absolute URL with
// one of the schemes and a host. The problem never repeats the value: a
// URL may carry a password.
func urlOK(p FieldErrors, name, raw string, schemes ...string) FieldErrors {
	if raw == "" {
		return p
	}
	u, err := url.Parse(raw)
	if err != nil {
		return append(p, core.Fieldf(name, "not a URL"))
	}
	ok := false
	for _, s := range schemes {
		if strings.EqualFold(u.Scheme, s) {
			ok = true
		}
	}
	if !ok {
		return append(p, core.Fieldf(name, "scheme %q is not one of %s", u.Scheme, strings.Join(schemes, ", ")))
	}
	if u.Host == "" {
		return append(p, core.Fieldf(name, "has no host"))
	}
	return p
}

func hostOK(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	return !strings.ContainsAny(h, "/ \t@?#") && !strings.Contains(h, "://")
}

func clientIDOK(p FieldErrors, name, id string) FieldErrors {
	if !idPattern.MatchString(id) {
		return append(p, core.Fieldf(name, "%q must be 1-64 of A-Z a-z 0-9 . _ -", id))
	}
	return p
}
