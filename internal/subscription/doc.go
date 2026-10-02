// Package subscription is the pure model of the F3 push subscriptions
// (docs/PLAN.md section 6.5, docs/WORKPACKAGES/WP-6.md): the
// subscription and its states, the callback URL policy that keeps a
// subscriber's URL from reaching inside the CISP's network (the SSRF
// guard: the scheme, the name and every resolved address), the match of
// a change against a subscription (dataset and bounding box), and the
// retry schedule of a delivery (1 s doubling to 300 s, ±10 % jitter,
// for 24 h after the change) with the suspension rule (50 consecutive
// failures over at least one hour).
//
//	func ValidateCallbackURL(raw string, pol URLPolicy) error
//	func AllowedAddress(ip net.IP, pol URLPolicy) bool
//	func Matches(s Subscription, c publication.Change) bool
//	func NextAttempt(attempt int, changeAt, now time.Time, r Retry) (time.Time, bool)
//	func ShouldSuspend(consecutiveFailures int, failingSince, now time.Time) bool
//
// It does no I/O and never logs: ValidateCallbackURL judges the URL as
// written, and the caller that dials (internal/deliver) applies
// AllowedAddress to the address it actually connects to, after
// resolution, so a name that resolves to a private address is refused
// at dial time whatever it looked like when it was registered.
package subscription
