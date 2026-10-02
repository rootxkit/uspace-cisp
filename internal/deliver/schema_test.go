package deliver

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The body of every webhook is the Change component of api/openapi.yaml
// (cis/change/v1): a change's record and a ping's, each validated
// against the contract, and the twin with an unknown member refused
// (E-01, E-03).
func TestWebhookBodyIsTheChangeSchema(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	schema := doc.Components.Schemas["Change"].Value
	h := newHarness(t, nil)
	c := publication.Change{ID: 12, Dataset: publication.DatasetRestrictions, Version: 3, FeatureIDs: []string{"DAR0001"},
		Reason: publication.ReasonRestrictionActivated, At: time.Now().UTC(), BBox: &geodesy.BBox{MinLon: 44, MinLat: 41, MaxLon: 45, MaxLat: 42}}
	now := time.Now().UTC()
	ping := store.Claim{DeliveryID: store.NewID(now), SubscriptionID: "S1", CreatedAt: now, Datasets: []publication.Dataset{publication.DatasetZones}}
	for name, body := range map[string]any{
		"change": h.s.Body(store.Claim{DeliveryID: "D1"}, &c, nil),
		"ping":   h.s.Body(ping, nil, map[publication.Dataset]int64{}),
	} {
		raw, _ := json.Marshal(body)
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if err := schema.VisitJSON(v); err != nil {
			t.Errorf("%s body does not validate: %v\n%s", name, err, raw)
		}
		v["colour"] = "red"
		if err := schema.VisitJSON(v); err == nil {
			t.Errorf("%s body with an unknown member validates", name)
		}
	}
}
