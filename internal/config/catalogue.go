package config

// Var is one CISP_* environment variable: its name, its default (the
// value used when the variable is unset or empty) and how it is redacted
// in the startup log.
type Var struct {
	Name    string
	Default string
	// Secret: the whole value is printed as "***".
	Secret bool
	// SecretURL: a URL whose userinfo (password or token) and credential
	// query parameters are printed as "***"; the rest stays readable.
	SecretURL bool
}

// TestPrefix is the namespace of the variables the integration tests
// read (CISP_TEST_DATABASE_URL and friends). No process reads them, and
// they are not reported as unknown, so a shell that exports them can
// still start a process.
const TestPrefix = "CISP_TEST_"

// Variable names. Every process reads a subset; the catalogue below is
// the union, and a CISP_* variable outside it is refused at start.
const (
	EnvHTTPAddr                  = "CISP_HTTP_ADDR"
	EnvDeliverHTTPAddr           = "CISP_DELIVER_HTTP_ADDR"
	EnvLogLevel                  = "CISP_LOG_LEVEL"
	EnvStatusIntervalS           = "CISP_STATUS_INTERVAL_S"
	EnvShutdownTimeoutS          = "CISP_SHUTDOWN_TIMEOUT_S"
	EnvHandlerTimeoutS           = "CISP_HANDLER_TIMEOUT_S"
	EnvMaxBodyBytes              = "CISP_MAX_BODY_BYTES"
	EnvBodyReadMinBytesPerS      = "CISP_BODY_READ_MIN_BYTES_PER_S"
	EnvOTelEndpoint              = "CISP_OTEL_ENDPOINT"
	EnvDatabaseURL               = "CISP_DATABASE_URL"
	EnvTimeseriesURL             = "CISP_TIMESERIES_URL"
	EnvDatabaseMaxConns          = "CISP_DATABASE_MAX_CONNS"
	EnvTimeseriesMaxConns        = "CISP_TIMESERIES_MAX_CONNS"
	EnvNATSURL                   = "CISP_NATS_URL"
	EnvNATSCredsFile             = "CISP_NATS_CREDS_FILE" //nolint:gosec // G101: a variable name, not a credential
	EnvTokenIssuer               = "CISP_TOKEN_ISSUER"    //nolint:gosec // G101: a variable name, not a credential
	EnvTokenJWKSURL              = "CISP_TOKEN_JWKS_URL"  //nolint:gosec // G101: a variable name, not a credential
	EnvLabIssuer                 = "CISP_LAB_ISSUER"
	EnvLabJWKSURL                = "CISP_LAB_JWKS_URL"
	EnvJWKSCacheFile             = "CISP_JWKS_CACHE_FILE"
	EnvAudiences                 = "CISP_AUDIENCES"
	EnvAuthorityClientID         = "CISP_AUTHORITY_CLIENT_ID"
	EnvANSPClientID              = "CISP_ANSP_CLIENT_ID"
	EnvANSPJWKSURL               = "CISP_ANSP_JWKS_URL"
	EnvANSPMTLSSubject           = "CISP_ANSP_MTLS_SUBJECT"
	EnvMTLSMode                  = "CISP_MTLS_MODE"
	EnvSigningKeyFile            = "CISP_SIGNING_KEY_FILE"
	EnvSigningKID                = "CISP_SIGNING_KID"
	EnvSigningKeyPrevFile        = "CISP_SIGNING_KEY_PREV_FILE"
	EnvSigningKIDPrev            = "CISP_SIGNING_KID_PREV"
	EnvPublisherSigMaxSkewS      = "CISP_PUBLISHER_SIGNATURE_MAX_SKEW_S"
	EnvSessionKeyFile            = "CISP_SESSION_KEY_FILE"
	EnvSecretsKey                = "CISP_SECRETS_KEY" //nolint:gosec // G101: a variable name, not a credential
	EnvPublicBaseURL             = "CISP_PUBLIC_BASE_URL"
	EnvIssuerURL                 = "CISP_ISSUER_URL"
	EnvReadMaxAgeS               = "CISP_READ_MAX_AGE_S"
	EnvPublicRPM                 = "CISP_PUBLIC_RPM"
	EnvMaxPublicationBytes       = "CISP_MAX_PUBLICATION_BYTES"
	EnvMaxSubscriptionsPerClient = "CISP_MAX_SUBSCRIPTIONS_PER_CLIENT"
	EnvDeliveryLogRetentionDays  = "CISP_DELIVERY_LOG_RETENTION_DAYS"
	EnvAllowPrivateCallbacks     = "CISP_ALLOW_PRIVATE_CALLBACKS"
	EnvAllowInsecureCallbacks    = "CISP_ALLOW_INSECURE_CALLBACKS"
	EnvBrandingFile              = "CISP_BRANDING_FILE"
)

// Catalogue is every CISP_* variable with its default, in the order
// deploy/.env.example documents them. A test keeps the two in step.
var Catalogue = []Var{
	// Common to every process.
	{Name: EnvLogLevel, Default: "info"},
	{Name: EnvStatusIntervalS, Default: "30"},
	{Name: EnvShutdownTimeoutS, Default: "10"},
	{Name: EnvOTelEndpoint, Default: ""},

	// Stores and the bus.
	{Name: EnvDatabaseURL, Default: "", SecretURL: true},
	{Name: EnvTimeseriesURL, Default: "", SecretURL: true},
	{Name: EnvDatabaseMaxConns, Default: "8"},
	{Name: EnvTimeseriesMaxConns, Default: "2"},
	{Name: EnvNATSURL, Default: "", SecretURL: true},
	{Name: EnvNATSCredsFile, Default: ""},

	// api.
	{Name: EnvHTTPAddr, Default: ":8080"},
	{Name: EnvHandlerTimeoutS, Default: "10"},
	{Name: EnvMaxBodyBytes, Default: "65536"},
	{Name: EnvBodyReadMinBytesPerS, Default: "65536"},
	{Name: EnvTokenIssuer, Default: ""},
	{Name: EnvTokenJWKSURL, Default: ""},
	{Name: EnvLabIssuer, Default: ""},
	{Name: EnvLabJWKSURL, Default: ""},
	{Name: EnvJWKSCacheFile, Default: "local/jwks-cache.json"},
	{Name: EnvAudiences, Default: ""},
	{Name: EnvAuthorityClientID, Default: "authority-01"},
	{Name: EnvANSPClientID, Default: "ansp-01"},
	{Name: EnvANSPJWKSURL, Default: ""},
	{Name: EnvANSPMTLSSubject, Default: ""},
	{Name: EnvMTLSMode, Default: MTLSRequired},
	{Name: EnvSigningKeyFile, Default: ""},
	{Name: EnvSigningKID, Default: ""},
	{Name: EnvSigningKeyPrevFile, Default: ""},
	{Name: EnvSigningKIDPrev, Default: ""},
	{Name: EnvPublisherSigMaxSkewS, Default: "300"},
	{Name: EnvSessionKeyFile, Default: ""},
	{Name: EnvSecretsKey, Default: "", Secret: true},
	{Name: EnvPublicBaseURL, Default: ""},
	{Name: EnvIssuerURL, Default: ""},
	{Name: EnvReadMaxAgeS, Default: "60"},
	{Name: EnvPublicRPM, Default: "60"},
	{Name: EnvMaxPublicationBytes, Default: "33554432"},
	{Name: EnvMaxSubscriptionsPerClient, Default: "20"},
	{Name: EnvBrandingFile, Default: ""},

	// deliver.
	{Name: EnvDeliverHTTPAddr, Default: ":8081"},
	{Name: EnvDeliveryLogRetentionDays, Default: "90"},
	{Name: EnvAllowPrivateCallbacks, Default: "false"},
	{Name: EnvAllowInsecureCallbacks, Default: "false"},
}

// MTLS modes (CISP_MTLS_MODE).
const (
	MTLSRequired = "required"
	MTLSOff      = "off"
)

func lookupVar(name string) (Var, bool) {
	for _, v := range Catalogue {
		if v.Name == name {
			return v, true
		}
	}
	return Var{}, false
}
