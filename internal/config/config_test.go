package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// problemsOf returns the variables named by err's problems.
func problemsOf(t *testing.T, err error) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err == nil {
		return out
	}
	var p FieldErrors
	if !errors.As(err, &p) {
		t.Fatalf("error %v is not FieldErrors", err)
	}
	for _, fe := range p {
		out[fe.Field] = fe.Reason
	}
	return out
}

// apiBase is the smallest api environment that validates: the variables
// with no default (the token issuer, its JWKS, the audiences and, in the
// default mTLS mode, the ANSP's certificate subject).
var apiBase = []string{
	"CISP_TOKEN_ISSUER=https://authority.example.test/",
	"CISP_TOKEN_JWKS_URL=https://authority.example.test/.well-known/jwks.json",
	"CISP_AUDIENCES=uspace-cisp.example.test",
	"CISP_ANSP_MTLS_SUBJECT=CN=ansp-01",
}

func withBase(env ...string) []string { return append(append([]string{}, apiBase...), env...) }

// The api refuses to start without the variables that have no default,
// naming each.
func TestAPIRequiredVariables(t *testing.T) {
	_, err := LoadAPI(nil)
	probs := problemsOf(t, err)
	for _, name := range []string{EnvTokenIssuer, EnvTokenJWKSURL, EnvAudiences, EnvANSPMTLSSubject} {
		if _, ok := probs[name]; !ok {
			t.Errorf("no problem for %s in %v", name, probs)
		}
	}
	if len(probs) != 4 {
		t.Errorf("problems = %v, want exactly the four", probs)
	}
	if _, err := LoadAPI(apiBase); err != nil {
		t.Fatalf("the four set: %v", err)
	}
	// mTLS off needs no subject.
	if _, err := LoadAPI([]string{apiBase[0], apiBase[1], apiBase[2], "CISP_MTLS_MODE=off"}); err != nil {
		t.Errorf("mTLS off without a subject: %v", err)
	}
}

// Pairs that must be set together, kids that must differ, issuers and
// client ids that must differ, beside their accepted twins.
func TestAPICrossChecks(t *testing.T) {
	key := []string{"CISP_SIGNING_KEY_FILE=/k.pem", "CISP_SIGNING_KID=k2"}
	cases := []struct {
		name      string
		bad, good []string
		field     string
	}{
		{"lab issuer without JWKS", []string{"CISP_LAB_ISSUER=https://lab.example.test/"},
			[]string{"CISP_LAB_ISSUER=https://lab.example.test/", "CISP_LAB_JWKS_URL=http://localhost:8099/jwks"}, EnvLabJWKSURL},
		{"lab JWKS without issuer", []string{"CISP_LAB_JWKS_URL=https://lab.example.test/jwks"},
			[]string{"CISP_LAB_ISSUER=https://lab.example.test/", "CISP_LAB_JWKS_URL=https://lab.example.test/jwks"}, EnvLabIssuer},
		{"lab issuer equals the token issuer", []string{"CISP_LAB_ISSUER=https://authority.example.test/", "CISP_LAB_JWKS_URL=https://lab.example.test/jwks"},
			[]string{"CISP_LAB_ISSUER=https://lab.example.test/", "CISP_LAB_JWKS_URL=https://lab.example.test/jwks"}, EnvLabIssuer},
		{"same client id twice", []string{"CISP_ANSP_CLIENT_ID=authority-01"}, []string{"CISP_ANSP_CLIENT_ID=ansp-02"}, EnvANSPClientID},
		{"signing key without kid", []string{"CISP_SIGNING_KEY_FILE=/k.pem"}, key, EnvSigningKID},
		{"kid without signing key", []string{"CISP_SIGNING_KID=k2"}, key, EnvSigningKeyFile},
		{"malformed kid", []string{"CISP_SIGNING_KEY_FILE=/k.pem", "CISP_SIGNING_KID=kid/1"}, key, EnvSigningKID},
		{"previous key without kid", append([]string{"CISP_SIGNING_KEY_PREV_FILE=/p.pem"}, key...),
			append([]string{"CISP_SIGNING_KEY_PREV_FILE=/p.pem", "CISP_SIGNING_KID_PREV=k1"}, key...), EnvSigningKIDPrev},
		{"malformed previous kid", append([]string{"CISP_SIGNING_KEY_PREV_FILE=/p.pem", "CISP_SIGNING_KID_PREV=k 1"}, key...),
			append([]string{"CISP_SIGNING_KEY_PREV_FILE=/p.pem", "CISP_SIGNING_KID_PREV=k1"}, key...), EnvSigningKIDPrev},
		{"previous key without a current one", []string{"CISP_SIGNING_KEY_PREV_FILE=/p.pem", "CISP_SIGNING_KID_PREV=k1"},
			append([]string{"CISP_SIGNING_KEY_PREV_FILE=/p.pem", "CISP_SIGNING_KID_PREV=k1"}, key...), EnvSigningKeyPrevFile},
		{"same kid twice", append([]string{"CISP_SIGNING_KEY_PREV_FILE=/p.pem", "CISP_SIGNING_KID_PREV=k2"}, key...),
			append([]string{"CISP_SIGNING_KEY_PREV_FILE=/p.pem", "CISP_SIGNING_KID_PREV=k1"}, key...), EnvSigningKIDPrev},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			probs := problemsOf(t, loadAPIErr(c.bad))
			if _, ok := probs[c.field]; !ok || len(probs) != 1 {
				t.Errorf("problems %v, want exactly one on %s", probs, c.field)
			}
			if err := loadAPIErr(c.good); err != nil {
				t.Errorf("twin refused: %v", err)
			}
		})
	}
	ctl := problemsOf(t, loadCtlErr([]string{"CISP_SIGNING_KEY_FILE=/k.pem"}))
	if _, ok := ctl[EnvSigningKID]; !ok || len(ctl) != 1 {
		t.Errorf("cispctl: %v", ctl)
	}
	if err := loadCtlErr(key); err != nil {
		t.Errorf("cispctl twin: %v", err)
	}
}

func TestDefaults(t *testing.T) {
	api, err := LoadAPI(apiBase)
	if err != nil {
		t.Fatalf("LoadAPI with only the required variables: %v", err)
	}
	checks := []struct {
		name string
		got  any
		want any
	}{
		{EnvLogLevel, api.LogLevel, "info"},
		{EnvStatusIntervalS, api.StatusInterval, 30 * time.Second},
		{EnvShutdownTimeoutS, api.ShutdownTimeout, 10 * time.Second},
		{EnvOTelEndpoint, api.OTelEndpoint, ""},
		{EnvHTTPAddr, api.HTTPAddr, ":8080"},
		{EnvHandlerTimeoutS, api.HandlerTimeout, 10 * time.Second},
		{EnvMaxBodyBytes, api.MaxBodyBytes, int64(65536)},
		{EnvBodyReadMinBytesPerS, api.BodyReadMinBytesPerS, int64(65536)},
		{EnvDatabaseURL, api.DatabaseURL, ""},
		{EnvTimeseriesURL, api.TimeseriesURL, ""},
		{EnvNATSURL, api.NATSURL, ""},
		{EnvNATSCredsFile, api.NATSCredsFile, ""},
		{EnvTokenIssuer, api.TokenIssuer, "https://authority.example.test/"},
		{EnvTokenJWKSURL, api.TokenJWKSURL, "https://authority.example.test/.well-known/jwks.json"},
		{EnvLabIssuer, api.LabIssuer, ""},
		{EnvLabJWKSURL, api.LabJWKSURL, ""},
		{EnvJWKSCacheFile, api.JWKSCacheFile, "local/jwks-cache.json"},
		{EnvAudiences, len(api.Audiences), 1},
		{EnvSigningKIDPrev, api.SigningKIDPrev, ""},
		{EnvPublisherSigMaxSkewS, api.PublisherSignatureMaxSkew, 5 * time.Minute},
		{EnvAuthorityClientID, api.AuthorityClientID, "authority-01"},
		{EnvANSPClientID, api.ANSPClientID, "ansp-01"},
		{EnvANSPJWKSURL, api.ANSPJWKSURL, ""},
		{EnvANSPMTLSSubject, api.ANSPMTLSSubject, "CN=ansp-01"},
		{EnvMTLSMode, api.MTLSMode, MTLSRequired},
		{EnvSigningKeyFile, api.SigningKeyFile, ""},
		{EnvSigningKID, api.SigningKID, ""},
		{EnvSigningKeyPrevFile, api.SigningKeyPrevFile, ""},
		{EnvSessionKeyFile, api.SessionKeyFile, ""},
		{EnvSecretsKey, api.SecretsKey, ""},
		{EnvPublicBaseURL, api.PublicBaseURL, ""},
		{EnvIssuerURL, api.IssuerURL, ""},
		{EnvReadMaxAgeS, api.ReadMaxAge, 60 * time.Second},
		{EnvPublicRPM, api.PublicRPM, int64(60)},
		{EnvMaxPublicationBytes, api.MaxPublicationBytes, int64(32 << 20)},
		{EnvMaxSubscriptionsPerClient, api.MaxSubscriptionsPerClient, int64(20)},
		{EnvBrandingFile, api.BrandingFile, ""},
		{EnvMaxRestrictionBytes, api.MaxRestrictionBytes, int64(256 << 10)},
		{EnvExpiryIntervalS, api.ExpiryInterval, 5 * time.Second},
		{EnvExpiryStaleAfterS, api.ExpiryStaleAfter, 30 * time.Second},
		{EnvDatabaseMaxConns, api.DatabaseMaxConns, int64(8)},
		{EnvTimeseriesMaxConns, api.TimeseriesMaxConns, int64(2)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s default = %v, want %v", c.name, c.got, c.want)
		}
	}

	d, err := LoadDeliver(nil)
	if err != nil {
		t.Fatalf("LoadDeliver with an empty environment: %v", err)
	}
	if d.HTTPAddr != ":8081" || d.DeliveryLogRetentionDays != 90 || d.AllowPrivateCallbacks || d.AllowInsecureCallbacks {
		t.Errorf("deliver defaults = %q %d %v %v", d.HTTPAddr, d.DeliveryLogRetentionDays, d.AllowPrivateCallbacks, d.AllowInsecureCallbacks)
	}
	if _, err := LoadCtl(nil); err != nil {
		t.Fatalf("LoadCtl with an empty environment: %v", err)
	}
}

// Every catalogue variable is read by at least one process, so none is
// documented without effect.
func TestEveryVariableIsRead(t *testing.T) {
	api, _ := LoadAPI(nil)
	d, _ := LoadDeliver(nil)
	c, _ := LoadCtl(nil)
	read := map[string]bool{}
	for _, cm := range []*Common{&api.Common, &d.Common, &c.Common} {
		for _, n := range cm.RedactedNames() {
			read[n] = true
		}
	}
	for _, v := range Catalogue {
		if !read[v.Name] {
			t.Errorf("%s is in the catalogue but no process reads it", v.Name)
		}
	}
}

func TestValuesOverrideDefaults(t *testing.T) {
	env := []string{
		"CISP_HTTP_ADDR=127.0.0.1:9000",
		"CISP_LOG_LEVEL=debug",
		"CISP_AUDIENCES=uspace-cisp.example.test, cisp.lab.test",
		"CISP_MTLS_MODE=off",
		"CISP_READ_MAX_AGE_S=0",
		"CISP_DATABASE_URL=postgres://cisp_api:pw@db:5432/cisp",
		"CISP_NATS_URL=nats://nats:4222",
		"CISP_OTEL_ENDPOINT=http://otel:4318",
		"PATH=/bin",
		"NOT_CISP=1",
	}
	api, err := LoadAPI(withBase(env...))
	if err != nil {
		t.Fatalf("LoadAPI: %v", err)
	}
	if api.HTTPAddr != "127.0.0.1:9000" || api.LogLevel != "debug" || api.MTLSMode != MTLSOff || api.ReadMaxAge != 0 {
		t.Errorf("values not applied: %+v", api)
	}
	if len(api.Audiences) != 2 || api.Audiences[1] != "cisp.lab.test" {
		t.Errorf("audiences = %q", api.Audiences)
	}
	if api.Level().String() != "DEBUG" {
		t.Errorf("Level = %v", api.Level())
	}
	proxies, err := LoadAPI(withBase("CISP_TRUSTED_PROXY_CIDR=172.18.0.7/16, ::1/128"))
	if err != nil {
		t.Fatal(err)
	}
	if got := proxies.TrustedProxies(); len(got) != 2 || got[0].String() != "172.18.0.0/16" || got[1].String() != "::1/128" {
		t.Errorf("trusted proxies = %v", got)
	}
}

// An empty value means "not set": the default applies.
func TestEmptyValueTakesDefault(t *testing.T) {
	api, err := LoadAPI(withBase("CISP_HTTP_ADDR=", "CISP_PUBLIC_RPM=  "))
	if err != nil {
		t.Fatal(err)
	}
	if api.HTTPAddr != ":8080" || api.PublicRPM != 60 {
		t.Errorf("got %q %d", api.HTTPAddr, api.PublicRPM)
	}
}

func TestUnknownVariableRefused(t *testing.T) {
	_, err := LoadAPI(withBase("CISP_HTTP_ADDRESS=:9000"))
	probs := problemsOf(t, err)
	if _, ok := probs["CISP_HTTP_ADDRESS"]; !ok || len(probs) != 1 {
		t.Fatalf("problems = %v, want exactly CISP_HTTP_ADDRESS", probs)
	}
	// The same environment with the correct spelling is accepted.
	if _, err := LoadAPI(withBase("CISP_HTTP_ADDR=:9000")); err != nil {
		t.Fatalf("correct spelling refused: %v", err)
	}
	// Every process refuses it, not only api.
	if _, err := LoadDeliver([]string{"CISP_HTTP_ADDRESS=:9000"}); err == nil {
		t.Error("deliver accepted an unknown variable")
	}
	if _, err := LoadCtl([]string{"CISP_HTTP_ADDRESS=:9000"}); err == nil {
		t.Error("cispctl accepted an unknown variable")
	}
}

// CISP_TEST_* belongs to the integration tests and is never refused.
func TestTestPrefixIgnored(t *testing.T) {
	if _, err := LoadAPI(withBase("CISP_TEST_DATABASE_URL=postgres://x@y/z")); err != nil {
		t.Fatalf("CISP_TEST_ variable refused: %v", err)
	}
}

func TestReadingAnUncataloguedNameIsAProblem(t *testing.T) {
	e := newEnv(nil)
	_ = e.str("CISP_NOT_IN_CATALOGUE")
	if len(e.probs) != 1 || e.probs[0].Field != "CISP_NOT_IN_CATALOGUE" {
		t.Fatalf("probs = %v", e.probs)
	}
}

// Each validation failure, beside the same variable accepted.
func TestValidationFailuresAndSuccesses(t *testing.T) {
	cases := []struct {
		name, bad, good string
		load            func([]string) error
	}{
		{EnvLogLevel, "verbose", "warn", loadAPIErr},
		{EnvStatusIntervalS, "0", "1", loadAPIErr},
		{EnvStatusIntervalS, "soon", "3600", loadAPIErr},
		{EnvShutdownTimeoutS, "301", "300", loadAPIErr},
		{EnvOTelEndpoint, "grpc://otel:4317", "https://otel:4318", loadAPIErr},
		{EnvOTelEndpoint, "http://", "http://otel", loadAPIErr},
		{EnvOTelEndpoint, "http://bad host/%zz", "http://otel/v1/traces", loadAPIErr},
		{EnvHTTPAddr, "8080", ":8080", loadAPIErr},
		{EnvHTTPAddr, ":99999", "0.0.0.0:0", loadAPIErr},
		{EnvHTTPAddr, ":http", ":80", loadAPIErr},
		{EnvHandlerTimeoutS, "0", "10", loadAPIErr},
		{EnvMaxBodyBytes, "100", "1024", loadAPIErr},
		{EnvBodyReadMinBytesPerS, "1000", "1024", loadAPIErr},
		{EnvDatabaseURL, "mysql://db/cisp", "postgresql://db/cisp", loadAPIErr},
		{EnvTimeseriesURL, "http://db/cisp_ts", "postgres://db/cisp_ts", loadAPIErr},
		{EnvNATSURL, "http://nats:4222", "tls://nats:4222", loadAPIErr},
		{EnvTokenIssuer, "ftp://auth", "https://auth.example.test", loadAPIErr},
		{EnvTokenJWKSURL, "auth/jwks.json", "https://auth.example.test/.well-known/jwks.json", loadAPIErr},
		{EnvTokenJWKSURL, "http://auth.example.test/jwks", "http://127.0.0.1:8099/jwks", loadAPIErr},
		{EnvTokenJWKSURL, "http://127.0.0.2/jwks", "http://localhost/jwks", loadAPIErr},
		{EnvPublisherSigMaxSkewS, "0", "3600", loadAPIErr},
		{EnvPublisherSigMaxSkewS, "3601", "1", loadAPIErr},
		{EnvAudiences, "https://cisp.example.test", "cisp.example.test", loadAPIErr},
		{EnvAudiences, "a,,b", "a,b", loadAPIErr},
		{EnvAuthorityClientID, "authority 01", "authority-01", loadAPIErr},
		{EnvANSPClientID, strings.Repeat("a", 65), strings.Repeat("a", 64), loadAPIErr},
		{EnvANSPJWKSURL, "file:///jwks", "https://ansp.example.test/.well-known/jwks.json", loadAPIErr},
		{EnvANSPJWKSURL, "http://ansp.example.test/jwks", "http://[::1]:9000/jwks", loadAPIErr},
		{EnvMTLSMode, "optional", "off", loadAPIErr},
		{EnvPublicBaseURL, "cisp.example.test", "https://cisp.example.test", loadAPIErr},
		{EnvIssuerURL, "mailto:x@y", "https://cisp.example.test", loadAPIErr},
		{EnvReadMaxAgeS, "-1", "86400", loadAPIErr},
		{EnvPublicRPM, "0", "1", loadAPIErr},
		{EnvTrustedProxyCIDR, "10.0.0.1", "10.0.0.1/32", loadAPIErr},
		{EnvTrustedProxyCIDR, "172.18.0.0/16,caddy", "172.18.0.0/16, ::1/128", loadAPIErr},
		{EnvMaxPublicationBytes, "1073741825", "1073741824", loadAPIErr},
		{EnvMaxSubscriptionsPerClient, "twenty", "20", loadAPIErr},
		{EnvMaxRestrictionBytes, "1023", "1024", loadAPIErr},
		{EnvMaxRestrictionBytes, "16777217", "16777216", loadAPIErr},
		{EnvExpiryIntervalS, "0", "1", loadAPIErr},
		{EnvExpiryStaleAfterS, "0", "6", loadAPIErr},
		{EnvExpiryStaleAfterS, "5", "3600", loadAPIErr},
		{EnvDatabaseMaxConns, "0", "1", loadAPIErr},
		{EnvTimeseriesMaxConns, "1001", "1000", loadAPIErr},
		{EnvDatabaseMaxConns, "0", "8", loadDeliverErr},
		{EnvTimeseriesMaxConns, "0", "2", loadDeliverErr},
		{EnvDeliverHTTPAddr, "localhost", "localhost:8081", loadDeliverErr},
		{EnvDeliveryLogRetentionDays, "0", "3650", loadDeliverErr},
		{EnvAllowPrivateCallbacks, "yes", "true", loadDeliverErr},
		{EnvAllowInsecureCallbacks, "2", "0", loadDeliverErr},
		{EnvDatabaseURL, "redis://db", "postgres://db/cisp", loadDeliverSendingErr},
		{EnvPublicBaseURL, "cisp", "https://cisp.lab.test", loadDeliverErr},
		{EnvTimeseriesURL, "redis://db", "postgres://db/cisp_ts", loadDeliverErr},
		{EnvNATSURL, "redis://nats", "nats://nats", loadDeliverErr},
		{EnvSigningKID, "kid 1", "kid-1", loadDeliverErr},
		{EnvIssuerURL, "cisp", "http://cisp.lab.test", loadDeliverErr},
		{EnvDatabaseURL, "redis://db", "postgres://db/cisp", loadCtlErr},
		{EnvTimeseriesURL, "redis://db", "postgres://db/cisp_ts", loadCtlErr},
		{EnvDatabaseMaxConns, "many", "3", loadCtlErr},
		{EnvLogLevel, "loud", "error", loadCtlErr},
	}
	for _, c := range cases {
		t.Run(c.name+"="+c.bad, func(t *testing.T) {
			probs := problemsOf(t, c.load([]string{c.name + "=" + c.bad}))
			found := false
			for field := range probs {
				if field == c.name || strings.HasPrefix(field, c.name+"[") {
					found = true
				}
			}
			if !found || len(probs) != 1 {
				t.Errorf("%s=%q: problems %v, want exactly one on %s", c.name, c.bad, probs, c.name)
			}
			if err := c.load([]string{c.name + "=" + c.good}); err != nil {
				t.Errorf("%s=%q refused: %v", c.name, c.good, err)
			}
		})
	}
}

func loadAPIErr(env []string) error     { _, err := LoadAPI(withBase(env...)); return err }
func loadDeliverErr(env []string) error { _, err := LoadDeliver(env); return err }

// loadDeliverSendingErr loads deliver with what it needs to send.
func loadDeliverSendingErr(env []string) error {
	_, err := LoadDeliver(append([]string{
		EnvSigningKeyFile + "=/run/keys/cisp.pem", EnvSigningKID + "=cisp-1",
		EnvIssuerURL + "=https://cisp.lab.test", EnvPublicBaseURL + "=https://cisp.lab.test",
	}, env...))
	return err
}

// With a database deliver sends webhooks: the signing key, its kid, the
// issuer and the public base URL are required, each named; without one
// it runs idle and needs none of them (E-01).
func TestDeliverSendingNeedsSigning(t *testing.T) {
	probs := problemsOf(t, loadDeliverErr([]string{EnvDatabaseURL + "=postgres://db/cisp"}))
	for _, name := range []string{EnvSigningKeyFile, EnvSigningKID, EnvIssuerURL, EnvPublicBaseURL} {
		if _, ok := probs[name]; !ok {
			t.Errorf("%s not named: %v", name, probs)
		}
	}
	if len(probs) != 4 {
		t.Errorf("problems %v", probs)
	}
	if err := loadDeliverSendingErr([]string{EnvDatabaseURL + "=postgres://db/cisp"}); err != nil {
		t.Errorf("complete: %v", err)
	}
	d, err := LoadDeliver([]string{EnvPublicBaseURL + "=https://cisp.lab.test/"})
	if err != nil || d.PublicBaseURL != "https://cisp.lab.test/" {
		t.Errorf("public base URL %q %v", d.PublicBaseURL, err)
	}
	a, err := LoadAPI(withBase(EnvAllowPrivateCallbacks+"=true", EnvAllowInsecureCallbacks+"=true"))
	if err != nil || !a.AllowPrivateCallbacks || !a.AllowInsecureCallbacks {
		t.Errorf("api callback policy %v %v %v", a.AllowPrivateCallbacks, a.AllowInsecureCallbacks, err)
	}
}
func loadCtlErr(env []string) error { _, err := LoadCtl(env); return err }

// Every problem is reported at once, not only the first.
func TestEveryProblemAtOnce(t *testing.T) {
	_, err := LoadAPI([]string{
		"CISP_LOG_LEVEL=loud",
		"CISP_MTLS_MODE=maybe",
		"CISP_PUBLIC_RPM=x",
		"CISP_TYPO=1",
	})
	probs := problemsOf(t, err)
	for _, name := range []string{EnvLogLevel, EnvMTLSMode, EnvPublicRPM, "CISP_TYPO"} {
		if _, ok := probs[name]; !ok {
			t.Errorf("no problem for %s in %v", name, probs)
		}
	}
	if !strings.Contains(err.Error(), "; ") {
		t.Errorf("Error() does not join the problems: %q", err.Error())
	}
}

// A URL problem never repeats the URL, which may carry a password.
func TestURLProblemDoesNotEchoTheValue(t *testing.T) {
	const secret = "s3cr3t-pa55"
	_, err := LoadAPI([]string{"CISP_DATABASE_URL=mysql://u:" + secret + "@db/x"})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("err = %v", err)
	}
}

func TestRedactedNeverPrintsASecret(t *testing.T) {
	const (
		dbPassword = "db-Pa55word-91"
		tsPassword = "ts-Pa55word-42"
		natsToken  = "nats-T0ken-77"
		secretsKey = "secrets-key-value-for-the-test"
		queryPass  = "q-Pa55-13"
	)
	env := []string{
		"CISP_DATABASE_URL=postgres://cisp_api:" + dbPassword + "@db:5432/cisp?sslmode=disable",
		"CISP_TIMESERIES_URL=postgres://db:5432/cisp_ts?user=cisp_api&password=" + queryPass + "&x=" + tsPassword[:0],
		"CISP_NATS_URL=nats://" + natsToken + "@nats:4222",
		"CISP_SECRETS_KEY=" + secretsKey,
		"CISP_SIGNING_KEY_FILE=/run/secrets/cisp-signing.pem",
		"CISP_SIGNING_KID=cisp-1",
	}
	api, err := LoadAPI(withBase(env...))
	if err != nil {
		t.Fatal(err)
	}
	red := api.Redacted()
	all := fmt.Sprint(red)
	for _, secret := range []string{dbPassword, natsToken, secretsKey, queryPass} {
		if strings.Contains(all, secret) {
			t.Errorf("Redacted output contains a secret %q: %s", secret, all)
		}
	}
	if red[EnvSigningKeyFile] != "/run/secrets/cisp-signing.pem" {
		t.Errorf("file path not kept: %q", red[EnvSigningKeyFile])
	}
	if red[EnvDatabaseURL] != "postgres://cisp_api:***@db:5432/cisp?sslmode=disable" {
		t.Errorf("database URL = %q", red[EnvDatabaseURL])
	}
	if red[EnvNATSURL] != "nats://***@nats:4222" {
		t.Errorf("nats URL = %q", red[EnvNATSURL])
	}
	if red[EnvSecretsKey] != "***" {
		t.Errorf("secrets key = %q", red[EnvSecretsKey])
	}
	if red[EnvHTTPAddr] != ":8080" {
		t.Errorf("plain value changed: %q", red[EnvHTTPAddr])
	}
	if red[EnvLabIssuer] != "" {
		t.Errorf("unset value = %q", red[EnvLabIssuer])
	}
}

func TestRedactURLUnparseable(t *testing.T) {
	if got := redactURL("postgres://u:p@[::1"); got != "***" {
		t.Errorf("unparseable URL = %q, want ***", got)
	}
	if got := redactURL("no-scheme"); got != "***" {
		t.Errorf("scheme-less value = %q, want ***", got)
	}
}

func TestLevelFallsBackToInfo(t *testing.T) {
	c := Common{LogLevel: "loud"}
	if c.Level().String() != "INFO" {
		t.Errorf("Level = %v", c.Level())
	}
}

func TestProblemsError(t *testing.T) {
	var p FieldErrors
	if p.Error() != "" {
		t.Errorf("empty FieldErrors = %q", p.Error())
	}
}

// deploy/.env.example documents every catalogue variable with its
// default, in the catalogue's order, and nothing else.
func TestEnvExampleMatchesCatalogue(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "deploy", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got []Var
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "CISP_") {
			continue
		}
		name, value, _ := strings.Cut(line, "=")
		got = append(got, Var{Name: name, Default: value})
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(Catalogue) {
		t.Fatalf(".env.example has %d CISP_ variables, the catalogue %d", len(got), len(Catalogue))
	}
	for i, v := range Catalogue {
		if got[i].Name != v.Name || got[i].Default != v.Default {
			t.Errorf("line %d: .env.example %s=%q, catalogue %s=%q", i, got[i].Name, got[i].Default, v.Name, v.Default)
		}
	}
}

// The expiry's staleness is above its tick: one that is not would read
// every healthy tick as a dead ticker; the interval past a minute is
// refused too. Each beside the accepted value (E-01).
func TestExpiryStaleAboveInterval(t *testing.T) {
	probs := problemsOf(t, loadAPIErr([]string{EnvExpiryIntervalS + "=30"}))
	if _, ok := probs[EnvExpiryStaleAfterS]; !ok || len(probs) != 1 {
		t.Errorf("interval 30 with stale 30: %v", probs)
	}
	if err := loadAPIErr([]string{EnvExpiryIntervalS + "=29"}); err != nil {
		t.Errorf("interval 29: %v", err)
	}
	probs = problemsOf(t, loadAPIErr([]string{EnvExpiryIntervalS + "=61", EnvExpiryStaleAfterS + "=3600"}))
	if _, ok := probs[EnvExpiryIntervalS]; !ok || len(probs) != 1 {
		t.Errorf("interval 61: %v", probs)
	}
}
