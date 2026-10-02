//go:build integration

package deliver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// A console republication (WP-8) reaches a subscriber as any change
// does: the console writes a changes row of the current version with
// reason republished and no publication; deliver's scan queues it for
// the matching active subscription, signs it and POSTs it; the
// receiver reads reason republished and the current version.
func TestRepublishReachesTheSubscriber(t *testing.T) {
	p := setup(t)
	ctx := context.Background()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	sub := p.subscribe(t, srv.URL+"/v1/cis/notifications", true, publication.DatasetUSSPList)
	api := store.New(p.api, store.Options{AllowNoopSigner: true})
	body := []byte(`{"schema":"cis/ussp_list/v1","issued":"2026-10-02T00:00:00Z","ussps":[],"n":"` + store.NewID(time.Now()) + `"}`)
	res, err := api.PublishTx(ctx, store.PublishInput{Dataset: publication.DatasetUSSPList, Body: body, ContentType: "application/json",
		PublisherClientID: "authority-01", Reason: publication.ReasonPublication}, store.NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	ch, err := api.Republish(ctx, res.PublicationID, store.Event{ActorType: store.ActorAccount, ActorID: "acc-it",
		EventType: "console_republish", EntityType: "publication", EntityID: res.PublicationID, Payload: map[string]any{"reason": "it"}})
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := p.service(t, "it-republish", func(c *Config) { c.ScanGrace, c.ScanSettle = time.Millisecond, time.Millisecond })
	eventually(t, 10*time.Second, "the republished change queued", func() bool {
		_, _ = svc.Scan(ctx)
		return p.rows(t, ch.ID)[sub.ID] != ""
	})
	svc.Dispatch(ctx)
	svc.Wait()
	if st := p.rows(t, ch.ID)[sub.ID]; st != store.DeliveryDelivered {
		t.Fatalf("delivery %s", st)
	}
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, b := range bodies {
		// The webhook is a compact JWS; its payload carries the record.
		parts := strings.Split(b, ".")
		if len(parts) != 3 {
			continue
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			continue
		}
		var claims struct {
			Body struct {
				Reason  string `json:"reason"`
				Version int64  `json:"version"`
				MsgID   string `json:"msg_id"`
			} `json:"body"`
		}
		if json.Unmarshal(raw, &claims) == nil && claims.Body.Reason == "republished" && claims.Body.Version == res.Version {
			found = true
			t.Logf("subscriber received %s version %d (msg_id %s)", claims.Body.Reason, claims.Body.Version, claims.Body.MsgID)
		}
	}
	if !found {
		t.Errorf("no republished delivery among %d bodies", len(bodies))
	}
}
