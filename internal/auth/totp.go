package auth

import (
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP settings of the console's MFA (RFC 6238; spec 06 section 3): a
// 30 s step, six digits, SHA-1 (what every authenticator app reads from
// an otpauth URL), and one step of skew either way.
const (
	TOTPStep       = 30 * time.Second
	TOTPDigits     = 6
	TOTPSkewSteps  = 1
	totpSecretSize = 20
)

// NewTOTPSecret generates a TOTP secret for account under issuer and
// returns it (base32, as authenticator apps take it) with its otpauth
// URL, the form shown to the user once.
func NewTOTPSecret(issuer, account string) (secret, url string, err error) {
	k, err := totp.Generate(totp.GenerateOpts{
		Issuer: issuer, AccountName: account, Period: uint(TOTPStep / time.Second),
		SecretSize: totpSecretSize, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("totp secret: %w", err)
	}
	return k.Secret(), k.URL(), nil
}

// TOTPStepAt is the RFC 6238 time step that holds t.
func TOTPStepAt(t time.Time) int64 { return t.Unix() / int64(TOTPStep/time.Second) }

// MatchTOTP finds the step within TOTPSkewSteps of now whose code is
// code, comparing in constant time, and returns it. The caller refuses a
// step not above the account's last accepted one, so a code is never
// accepted twice (the replay memory is one integer per account, kept in
// the database). A code that is not six ASCII digits never matches.
func MatchTOTP(secret, code string, now time.Time) (int64, bool) {
	if len(code) != TOTPDigits {
		return 0, false
	}
	for _, c := range []byte(code) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	opts := totp.ValidateOpts{Period: uint(TOTPStep / time.Second), Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	center := TOTPStepAt(now)
	matched, found := int64(0), false
	for d := int64(-TOTPSkewSteps); d <= TOTPSkewSteps; d++ {
		step := center + d
		want, err := totp.GenerateCodeCustom(secret, time.Unix(step*int64(TOTPStep/time.Second), 0), opts)
		if err != nil {
			return 0, false
		}
		// Every candidate is computed and compared, so the time taken
		// does not say which step matched.
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && !found {
			matched, found = step, true
		}
	}
	return matched, found
}

// TOTPCode is the code of secret at t (tests and the dev transcript).
func TOTPCode(secret string, t time.Time) (string, error) {
	return totp.GenerateCodeCustom(secret, t, totp.ValidateOpts{Period: uint(TOTPStep / time.Second), Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
}
