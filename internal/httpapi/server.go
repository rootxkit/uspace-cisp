package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
)

// Check states shown by /readyz.
const (
	CheckOK            = "ok"
	CheckNotConfigured = "not configured"
	// MigrationsPendingWP1 is the migrations check until WP-1 ships the
	// goose runner: the state is reported, and it counts as not ready.
	MigrationsPendingWP1 = "pending (WP-1)"
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

// GetStatus is not implemented yet.
func (s *Server) GetStatus(context.Context, gen.GetStatusRequestObject) (gen.GetStatusResponseObject, error) {
	return gen.GetStatus501ApplicationProblemPlusJSONResponse{ProblemApplicationProblemPlusJSONResponse: notImplemented("GET /v1/status")}, nil
}

// notImplemented is the body of every operation whose work package has
// not landed.
func notImplemented(op string) gen.ProblemApplicationProblemPlusJSONResponse {
	return gen.ProblemApplicationProblemPlusJSONResponse(NewProblem(http.StatusNotImplemented, SlugNotImplemented,
		"Not implemented", op+" is in api/openapi.yaml but not implemented yet", ""))
}
