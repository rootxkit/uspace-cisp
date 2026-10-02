//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// The C-M2 latency WP-5 measured only to a bus subscriber (docs/PLAN.md
// section 15 Q37 (8)): the ANSP activates a restriction, and the
// subscriber container receives the signed restriction_activated change
// within 2 s of its commit (the regulatory channel of spec 02 F2).
func TestRestrictionLatency(t *testing.T) {
	s := env(t)
	s.subscribe(t)
	s.publish(t, "uspace_airspace", uspaceBody(t))
	_, cursor := s.changes(t, 0)

	starts := time.Now().UTC().Truncate(time.Second)
	ends := starts.Add(time.Hour)
	id := fmt.Sprintf("DAR%04d", time.Now().UnixMilli()%10000)
	body, _ := json.Marshal(doc{
		"ansp_ref": "e2e-" + id, "ansp_version": 1, "uspace_airspace_id": "TSU001", "state": "active",
		"starts_at": starts.Format(time.RFC3339), "ends_at": ends.Format(time.RFC3339),
		"feature": doc{
			"type": "Feature",
			"geometry": doc{
				"type":        "Polygon",
				"coordinates": []any{[]any{[]any{44.80, 41.70}, []any{44.82, 41.70}, []any{44.82, 41.72}, []any{44.80, 41.72}, []any{44.80, 41.70}}},
				"layer":       doc{"lower": 0, "lowerReference": "AGL", "upper": 120, "upperReference": "AGL", "uom": "m"},
			},
			"properties": doc{
				"identifier": id, "country": "GEO", "type": "PROHIBITED", "variant": "COMMON", "reason": []any{"DAR"},
				"name":                 []any{doc{"lang": "en-GB", "text": "e2e dynamic restriction"}},
				"limitedApplicability": []any{doc{"startDateTime": starts.Format(time.RFC3339), "endDateTime": ends.Format(time.RFC3339)}},
				"zoneAuthority":        []any{doc{"name": []any{doc{"lang": "en-GB", "text": "e2e ANSP"}}, "purpose": "NOTIFICATION"}},
			},
		},
	})
	tok := s.token(t, anspID, "localhost", "cis.publish:restrictions", "cis.read")
	resp, raw := s.call(t, http.MethodPost, "/v1/restrictions", tok, body, map[string]string{
		"X-JWS-Signature": s.sign(t, s.anspKeyFile, anspKID, body),
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/restrictions = %d %s", resp.StatusCode, raw)
	}
	cs, _ := s.changes(t, cursor)
	var activated []change
	for _, c := range cs {
		if c.Reason == "restriction_activated" {
			activated = append(activated, c)
		}
	}
	if len(activated) != 1 {
		t.Fatalf("changes %+v, want one restriction_activated", cs)
	}
	lat := s.latencies(t, activated, 10*time.Second)[activated[0].MsgID]
	t.Logf("restriction %s activated: received %s after the commit", id, lat.Round(time.Millisecond))
	if lat >= 2*time.Second {
		t.Errorf("restriction notification took %s, over the 2 s budget", lat)
	}
	summary(t, fmt.Sprintf("### Restriction latency (C-M2)\n\nrestriction_activated of %s: received **%s** after its commit (budget 2 s).\n", id, lat.Round(time.Millisecond)))
}
