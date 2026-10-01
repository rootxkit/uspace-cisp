package httpapi

import (
	"encoding/json"
	"net/http"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
)

// ProblemTypeBase prefixes every problem slug: the type of a problem is
// ProblemTypeBase + slug (docs/PLAN.md section 6).
const ProblemTypeBase = "https://schemas.uspace.ge/problems/"

// MaxProblemErrors caps errors[] in a problem body; truncated says when
// more existed.
const MaxProblemErrors = 100

// Problem slugs used by the base router.
const (
	SlugNotImplemented   = "not_implemented"
	SlugNotFound         = "not_found"
	SlugMethodNotAllowed = "method_not_allowed"
	SlugBadRequest       = "bad_request"
	SlugBodyTooLarge     = "body_too_large"
	SlugTimeout          = "timeout"
	SlugInternal         = "internal"
)

// NewProblem builds the problem body. errors[] lists at most
// MaxProblemErrors of fields, with truncated set when there were more.
func NewProblem(status int, slug, title, detail, instance string, fields ...*core.FieldError) gen.Problem {
	p := gen.Problem{Type: ProblemTypeBase + slug, Title: title, Status: status}
	if detail != "" {
		p.Detail = &detail
	}
	if instance != "" {
		p.Instance = &instance
	}
	if len(fields) > 0 {
		n := min(len(fields), MaxProblemErrors)
		errs := make([]gen.FieldProblem, 0, n)
		for _, fe := range fields[:n] {
			if fe == nil {
				continue
			}
			errs = append(errs, gen.FieldProblem{Field: fe.Field, Reason: fe.Reason})
		}
		p.Errors = &errs
		if len(fields) > MaxProblemErrors {
			t := true
			p.Truncated = &t
		}
	}
	return p
}

// WriteProblem writes an application/problem+json response. slug names
// the problem (the type is ProblemTypeBase + slug); instance is the
// request id already set on the response by the request id middleware.
func WriteProblem(w http.ResponseWriter, status int, slug, title, detail string, fields ...*core.FieldError) {
	p := NewProblem(status, slug, title, detail, w.Header().Get(HeaderRequestID), fields...)
	body, err := json.Marshal(p)
	if err != nil {
		// gen.Problem holds only strings, ints and bools: Marshal cannot
		// fail on it. Answer with the status regardless.
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}
