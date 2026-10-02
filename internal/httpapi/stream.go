package httpapi

import (
	"context"
	"net/http"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
)

// StreamRoute is the WS change stream's operation (WP-7).
const StreamRoute = "GET /v1/stream"

// SlugStreamUnavailable is the problem of an api without a stream hub.
const SlugStreamUnavailable = "stream_unavailable"

// VisitGetStreamResponse implements gen.GetStreamResponseObject.
func (p problemResponse) VisitGetStreamResponse(w http.ResponseWriter) error { return p.write(w) }

// GetStream is reached only when no stream handler serves the operation
// (Options.RouteHandlers): the WebSocket upgrade cannot pass through the
// strict server, which has no access to the connection.
func (s *Server) GetStream(ctx context.Context, _ gen.GetStreamRequestObject) (gen.GetStreamResponseObject, error) {
	return problemOf(ctx, http.StatusServiceUnavailable, SlugStreamUnavailable, "Stream unavailable",
		"this instance serves no WebSocket stream"), nil
}

// StreamAuth is the stream's route entry: no token (the stream is
// public, docs/PLAN.md section 8.2), the per-client rate limiter of the
// public reads on the upgrade. The Origin allow-list and the session
// cookie are judged by the stream's handler, which needs them to decide
// between 403, a console client and a 4401 close.
func StreamAuth(limiter *RateLimiter) map[string]func(http.Handler) http.Handler {
	return map[string]func(http.Handler) http.Handler{StreamRoute: limiter.Middleware}
}
