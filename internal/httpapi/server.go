package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/jws"
)

// Check states shown by /readyz.
const (
	CheckOK            = "ok"
	CheckNotConfigured = "not configured"
)

// Check reports one readiness dependency: a state for the body ("ok",
// "not configured", "unreachable: ...") and whether it is ok.
type Check func(ctx context.Context) (state string, ok bool)

// Readiness holds the checks behind /readyz. A nil check reports "not
// configured" and is not ok.
type Readiness struct {
	Database   Check
	Migrations Check
	NATS       Check
	// Timeout bounds the whole readiness evaluation (default 2 s).
	Timeout time.Duration
}

// Server implements the generated strict server interface. Operations
// that a later work package owns answer 501 not_implemented.
type Server struct {
	Ready Readiness
	// Keys is the CISP's signing key ring; nil: GET /.well-known/jwks.json
	// answers 503.
	Keys *jws.KeyRing
	// Publications serves the publications tag (WP-3); nil (no database
	// configured) answers its operations with 503.
	Publications *Publications
	// Reads serves the datasets tag (WP-4); nil (no database configured)
	// answers its operations with 503.
	Reads *Reads
	// Status is what GET /v1/status reports (WP-4); nil reports the
	// clock and nothing else.
	Status *StatusReport
	// Restrictions serves the restrictions tag (WP-5); nil (no database
	// configured) answers its operations with 503.
	Restrictions *Restrictions
	// Subscriptions serves the subscriptions tag (WP-6); nil (no database
	// configured) answers its operations with 503.
	Subscriptions *Subscriptions
	// Console serves the console tag (WP-8); nil (no database configured)
	// answers its operations with 503.
	Console *Console
}

var _ gen.StrictServerInterface = (*Server)(nil)

// GetHealthz is 200 while the process runs.
func (s *Server) GetHealthz(context.Context, gen.GetHealthzRequestObject) (gen.GetHealthzResponseObject, error) {
	return gen.GetHealthz200JSONResponse{Status: gen.Ok}, nil
}

func run(ctx context.Context, c Check) (string, bool) {
	if c == nil {
		return CheckNotConfigured, false
	}
	return c(ctx)
}

// GetReadyz is 200 only when the database is reachable and its
// migrations are current. NATS is reported but does not decide: an
// instance without the bus is ready, degraded (docs/PLAN.md section 6.3).
func (s *Server) GetReadyz(ctx context.Context, _ gen.GetReadyzRequestObject) (gen.GetReadyzResponseObject, error) {
	timeout := s.Ready.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var body gen.Readiness
	dbState, dbOK := run(ctx, s.Ready.Database)
	migState, migOK := run(ctx, s.Ready.Migrations)
	natsState, _ := run(ctx, s.Ready.NATS)
	body.Checks.Database = dbState
	body.Checks.Migrations = migState
	body.Checks.Nats = natsState
	if dbOK && migOK {
		body.Status = gen.Ready
		return gen.GetReadyz200JSONResponse(body), nil
	}
	body.Status = gen.NotReady
	return gen.GetReadyz503JSONResponse(body), nil
}

// intakeUnavailable answers a publications operation when the api runs
// without a database.
func intakeUnavailable(ctx context.Context) problemResponse {
	return problemOf(ctx, http.StatusServiceUnavailable, SlugIntakeUnavailable, "Publication intake unavailable",
		"the api runs without a database (CISP_DATABASE_URL); nothing can be stored or read")
}

// PutPublication publishes a whole dataset (WP-3).
func (s *Server) PutPublication(ctx context.Context, req gen.PutPublicationRequestObject) (gen.PutPublicationResponseObject, error) {
	if s.Publications == nil {
		return intakeUnavailable(ctx), nil
	}
	return s.Publications.put(ctx, req)
}

// ListPublications is the version history of a dataset (WP-3).
func (s *Server) ListPublications(ctx context.Context, req gen.ListPublicationsRequestObject) (gen.ListPublicationsResponseObject, error) {
	if s.Publications == nil {
		return intakeUnavailable(ctx), nil
	}
	return s.Publications.list(ctx, req)
}

// ListPublicationAttempts is the caller's refused attempts (WP-3).
func (s *Server) ListPublicationAttempts(ctx context.Context, req gen.ListPublicationAttemptsRequestObject) (gen.ListPublicationAttemptsResponseObject, error) {
	if s.Publications == nil {
		return intakeUnavailable(ctx), nil
	}
	return s.Publications.attempts(ctx, req)
}

// PostPublisherHeartbeat records a publisher heartbeat (WP-3).
func (s *Server) PostPublisherHeartbeat(ctx context.Context, req gen.PostPublisherHeartbeatRequestObject) (gen.PostPublisherHeartbeatResponseObject, error) {
	if s.Publications == nil {
		return intakeUnavailable(ctx), nil
	}
	return s.Publications.heartbeat(ctx, req)
}
