package deliver

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// The national zone set going live (5 000 zones, 40 removed) reaches a
// receiver that verifies with core's defaults (8 KiB): the webhook is a
// summary under the bound, delivered with a 2xx, and its body names the
// counts and pull_url (Q49, system F-1). The subscription's failure run
// stays empty.
func TestLargeChangeWebhookFitsCoreDefault(t *testing.T) {
	h := newHarness(t, nil)
	r := newReceiver(t, http.StatusNoContent)
	h.subscribe("S1", r.url(), subscription.Active)
	ids := make([]string, 5000)
	for i := range ids {
		ids[i] = fmt.Sprintf("ZN%05d", i)
	}
	c := publication.Change{ID: 11, Dataset: publication.DatasetZones, Version: 11, FeatureIDs: ids, RemovedIDs: ids[:40],
		Reason: publication.ReasonPublication, At: time.Now().UTC()}
	h.st.mu.Lock()
	h.st.changes[11] = c
	h.st.mu.Unlock()
	if n, err := h.st.InsertChangeDeliveries(context.Background(), 11, []string{"S1"}, time.Now().UTC()); err != nil || n != 1 {
		t.Fatalf("queue: %d %v", n, err)
	}
	h.send(t)
	if r.hits.Load() != 1 {
		t.Fatalf("posted %d times", r.hits.Load())
	}
	got := r.last(t)
	if len(got.token) > coreauth.DefaultMaxTokenBytes {
		t.Fatalf("webhook of %d bytes", len(got.token))
	}
	_, body, err := verifier(t, "cisp-1", h.key, "127.0.0.1").Verify(context.Background(), got.token)
	if err != nil {
		t.Fatalf("a receiver on core's defaults refused it: %v", err)
	}
	var m bus.ChangeMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	if !m.IDsTruncated || *m.FeatureCount != 5000 || *m.RemovedCount != 40 || len(m.FeatureIDs) != 0 ||
		m.PullURL != "https://uspace-cisp.example.test/v1/zones?since_version=10" {
		t.Errorf("body %+v", m)
	}
	h.st.mu.Lock()
	failures := h.st.sub("S1").ConsecutiveFailures
	h.st.mu.Unlock()
	if failures != 0 || h.counter(CounterPayloadTooLarge) != 0 || h.counter(CounterDelivered) != 1 {
		t.Errorf("failures %d, too large %d, delivered %d", failures, h.counter(CounterPayloadTooLarge), h.counter(CounterDelivered))
	}
	t.Logf("5 000-zone webhook: %d bytes", len(got.token))
}

// The largest change still listed, signed in the worst case this CISP
// can be configured into (a 4096-bit key, a 64-character kid and
// instance, a 253-character callback host, long issuer and base URLs),
// still verifies on core's defaults: MaxListedIDBytes leaves room.
func TestLargestListedWebhookFitsCoreDefault(t *testing.T) {
	key := authtest.Key(t, "cisp-worst", 4096)
	pemBytes, err := jws.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	kid := strings.Repeat("k", 64)
	ring, err := jws.LoadKeyRing(pemBytes, kid, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://" + strings.Repeat("i", 120) + ".example.ge"
	base := "https://" + strings.Repeat("p", 120) + ".example.ge/cisp"
	s, err := New(Config{Instance: strings.Repeat("n", 64), IssuerURL: issuer, PublicBaseURL: base},
		newFakeStore(), &fakeLog{}, ring, Options{Status: obs.NewStatus("deliver", nil, time.Now())})
	if err != nil {
		t.Fatal(err)
	}
	host := strings.Repeat("a", 61) + "." + strings.Repeat("b", 61) + "." + strings.Repeat("c", 61) + "." + strings.Repeat("d", 57) + ".ge"
	// The most identifier bytes a listed record can carry: ids sized so
	// the encoded lists sit just inside MaxListedIDBytes.
	var features []string
	for i := 0; i <= bus.MaxListedIDs; i++ {
		id := fmt.Sprintf("%s%03d", strings.Repeat("x", 25), i)
		next := append(append([]string{}, features...), id)
		m := bus.MessageOf(publication.Change{FeatureIDs: next, RemovedIDs: []string{}}, base)
		if m.IDsTruncated {
			break
		}
		features = next
	}
	enc, _ := json.Marshal(features)
	if len(enc) < bus.MaxListedIDBytes-64 {
		t.Fatalf("the lists fill %d of %d bytes: not the worst case", len(enc), bus.MaxListedIDBytes)
	}
	at := time.Now().UTC()
	c := publication.Change{ID: 1 << 62, Dataset: publication.DatasetUSpaceAirspace, Version: 1 << 62, FeatureIDs: features, RemovedIDs: []string{},
		Reason: publication.ReasonRestrictionCancelled, At: at}
	box := [4]float64{-179.123456789012, -89.123456789012, 179.123456789012, 89.123456789012}
	cl := store.Claim{DeliveryID: "01J00000000000000000000000", SubscriptionID: "01J00000000000000000000001", CallbackURL: "https://" + host + "/v1/cis/notifications"}
	body := s.Body(cl, &c, nil)
	body.BBox = box[:]
	if body.IDsTruncated {
		t.Fatal("the worst listed change was summarised")
	}
	token, err := s.Sign(cl, body, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) > coreauth.DefaultMaxTokenBytes {
		t.Fatalf("the largest listed webhook is %d bytes, over core's %d", len(token), coreauth.DefaultMaxTokenBytes)
	}
	set := authtest.PublicSet(t, map[string]*rsa.PrivateKey{kid: key})
	v, err := coreauth.NewCompactVerifier(context.Background(), coreauth.CompactConfig{
		Issuers: map[string]coreauth.IssuerConfig{issuer: {Keys: set}}, Audiences: []string{host},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("refused on core's defaults: %v", err)
	}
	t.Logf("largest listed webhook: %d ids, %d bytes of lists, %d-byte token", len(features), len(enc), len(token))
}
