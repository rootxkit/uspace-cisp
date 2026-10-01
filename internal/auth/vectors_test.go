package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/httpapi"
)

type jwtFixtures struct {
	Issuer   string          `json:"issuer"`
	Audience string          `json:"audience"`
	MaxSkewS float64         `json:"max_skew_s"`
	JWKS     json.RawMessage `json:"jwks"`
}

type jwtInput struct {
	Token        string `json:"token"`
	NowS         int64  `json:"now_s"`
	RequireScope string `json:"require_scope"`
}

type jwtExpected struct {
	Accepted       bool     `json:"accepted"`
	Reason         string   `json:"reason"`
	Claim          string   `json:"claim"`
	Subject        string   `json:"subject"`
	Scopes         []string `json:"scopes"`
	RequireScopeOK *bool    `json:"require_scope_ok"`
}

// TestVectorsJWTVerify runs every jwt_verify case owned by cisp through
// the middleware in front of a handler that answers 204: an accepted
// token is 204 (403 when the case's RequireScope is refused), a refused
// one is 401 with the case's claim in the problem's detail and in
// errors[0].field, and counted under the case's reason.
func TestVectorsJWTVerify(t *testing.T) {
	f := vectors.Load(t, "jwt_verify.json")
	var fx jwtFixtures
	vectors.Unmarshal(t, f.Fixtures, &fx)
	set, err := jwk.Parse(fx.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(fx.MaxSkewS*float64(time.Second)) != auth.MachineMaxSkew {
		t.Fatalf("the vectors' skew %v s is not the CISP's %v", fx.MaxSkewS, auth.MachineMaxSkew)
	}
	ran := 0
	f.RunOwned(t, "cisp", func(t *testing.T, c vectors.Case) {
		ran++
		var in jwtInput
		var exp jwtExpected
		c.Decode(t, &in, &exp)
		now := time.Unix(in.NowS, 0).UTC()
		mv, err := auth.NewMachineVerifier(context.Background(), auth.MachineConfig{
			Issuers:   []auth.Source{{ID: fx.Issuer, Keys: set}},
			Audiences: []string{fx.Audience},
			Now:       func() time.Time { return now },
		})
		if err != nil {
			t.Fatal(err)
		}
		g, err := auth.NewGuard(auth.GuardConfig{Verifier: mv, Problems: httpapi.WriteProblem, MTLSMode: config.MTLSOff})
		if err != nil {
			t.Fatal(err)
		}
		var scopes []string
		if in.RequireScope != "" {
			scopes = append(scopes, in.RequireScope)
		}
		var subject string
		h := g.RequireScopes(scopes...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject = auth.CallerFrom(r.Context()).ClientID
			w.WriteHeader(http.StatusNoContent)
		}))
		req := httptest.NewRequest(http.MethodGet, "/v1/zones", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+in.Token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		var p problem
		if rec.Code != http.StatusNoContent {
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("problem %q: %v", rec.Body.String(), err)
			}
		}
		switch {
		case !exp.Accepted:
			if rec.Code != http.StatusUnauthorized || len(p.Errors) == 0 || p.Errors[0].Field != exp.Claim ||
				!strings.HasPrefix(p.Detail, exp.Claim+": ") || p.Type != httpapi.ProblemTypeBase+auth.SlugUnauthenticated {
				t.Errorf("got %d %s, want 401 naming %s", rec.Code, rec.Body.String(), exp.Claim)
			}
			if got := mv.Stale(); len(got) != 0 {
				t.Errorf("stale %v", got)
			}
		case exp.RequireScopeOK != nil && !*exp.RequireScopeOK:
			if rec.Code != http.StatusForbidden || len(p.Errors) == 0 || p.Errors[0].Field != "scope" {
				t.Errorf("got %d %s, want 403 on scope", rec.Code, rec.Body.String())
			}
		default:
			if rec.Code != http.StatusNoContent || subject != exp.Subject {
				t.Errorf("got %d (subject %q), want 204 for %s: %s", rec.Code, subject, exp.Subject, rec.Body.String())
			}
		}
	})
	t.Logf("%d jwt_verify cases ran through the middleware", ran)
}
