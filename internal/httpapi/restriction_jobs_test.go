package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/restriction"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// cispJWKSVerifier verifies X-CIS-Signature values the way a consumer
// does: with the CISP's published JWKS (the key ring's bytes, as
// /.well-known/jwks.json serves them) as the publisher "cisp".
func cispJWKSVerifier(t *testing.T, h *pubHarness) *jws.DetachedVerifier {
	t.Helper()
	set, err := jwk.Parse(h.ring.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	v, err := jws.NewDetachedVerifier(context.Background(), jws.KeySource{Publisher: "cisp", Keys: coreauth.IssuerConfig{Keys: set}},
		366*24*time.Hour, jws.Options{MaxPayloadBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The expiry version's bytes are the CISP's expiry record, naming what it
// ends: op expire, the restriction, its ED-318 feature_id and the ends_at
// of the stored window, and the tick's clock as at. The version answer
// has no publisher signature, names uspace-cisp in X-CIS-Publisher, and
// its X-CIS-Signature verifies with the CISP's JWKS over exactly the
// served bytes; the same signature over the bytes with one byte changed
// does not (E-01). Beside it, the ANSP's own version carries its
// signature and its client id.
func TestRestrictionExpiryRecord(t *testing.T) {
	h, t0 := restrictionHarness(t)
	ends := t0.Add(2 * time.Second)
	id := decodeRestriction(t, h.postRestriction(createDoc("NOTAM-R", 1, "active", "DARREC1", t0, ends))).Restriction.Id
	v := h.restrictionsVersion()

	tick := ends.Add(3 * time.Second)
	h.at(tick)
	if n, ran, err := h.rs.ExpireTick(context.Background()); err != nil || !ran || n != 1 {
		t.Fatalf("expiry tick: %d %v %v", n, ran, err)
	}
	head := h.fake.rs().heads[id]
	if head.State != restriction.StateEnded || h.restrictionsVersion() != v+1 {
		t.Fatalf("head %+v, version %d", head.Head, h.restrictionsVersion())
	}

	rec := h.read(http.MethodGet, "/v1/restrictions/versions/"+i64toa(v+1))
	if rec.Code != http.StatusOK {
		t.Fatalf("expiry version = %d %s", rec.Code, rec.Body.String())
	}
	served := rec.Body.Bytes()
	var got map[string]string
	if err := json.Unmarshal(served, &got); err != nil {
		t.Fatalf("%v: %s", err, served)
	}
	endsAt, errEnds := time.Parse(time.RFC3339Nano, got["ends_at"])
	at, errAt := time.Parse(time.RFC3339Nano, got["at"])
	if len(got) != 5 || got["op"] != string(restriction.OpExpire) || got["restriction_id"] != id || got["feature_id"] != "DARREC1" ||
		got["feature_id"] != head.FeatureID || errEnds != nil || !endsAt.Equal(head.EndsAt) || !endsAt.Equal(ends) ||
		errAt != nil || !at.Equal(tick) {
		t.Errorf("expiry record %s (head feature %s ends_at %s, tick %s)", served, head.FeatureID, head.EndsAt, tick)
	}
	hd := rec.Header()
	if hd.Get(HeaderPublisherSig) != "" || hd.Get(HeaderPublisherKID) != "" || hd.Get(HeaderCISPublisher) != store.SystemPublisher ||
		hd.Get("Content-Type") != mediaJSONRestriction {
		t.Errorf("expiry version headers %v", hd)
	}
	t.Logf("GET /v1/restrictions/versions/%d = %d %s; X-CIS-Publisher %s", v+1, rec.Code, served, hd.Get(HeaderCISPublisher))

	verifier := cispJWKSVerifier(t, h)
	sig := hd.Get(HeaderSignature)
	if _, err := verifier.Verify(context.Background(), sig, served); err != nil {
		t.Fatalf("X-CIS-Signature does not verify with the CISP's JWKS over the served bytes: %v", err)
	}
	tampered := append([]byte(nil), served...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := verifier.Verify(context.Background(), sig, tampered); err == nil {
		t.Error("X-CIS-Signature verifies over bytes with one byte changed")
	} else {
		t.Logf("one byte changed: %v", err)
	}

	// The ANSP's version beside it: its signature and its client id.
	pubRec := h.read(http.MethodGet, "/v1/restrictions/versions/"+i64toa(v))
	if pubRec.Code != http.StatusOK || pubRec.Header().Get(HeaderPublisherSig) == "" || pubRec.Header().Get(HeaderPublisherKID) != anspKID ||
		pubRec.Header().Get(HeaderCISPublisher) != anspID {
		t.Errorf("ANSP version = %d %v", pubRec.Code, pubRec.Header())
	}
	if _, err := verifier.Verify(context.Background(), pubRec.Header().Get(HeaderSignature), pubRec.Body.Bytes()); err != nil {
		t.Errorf("X-CIS-Signature over the ANSP's version: %v", err)
	}
}

// op expire is the CISP's own: a publisher's PATCH carrying it is 400
// naming op, and leaves the restriction and the dataset as they were;
// the same PATCH with op end, its acceptance twin, ends it (E-01).
func TestRestrictionPatchExpireRefused(t *testing.T) {
	h, t0 := restrictionHarness(t)
	id := decodeRestriction(t, h.postRestriction(createDoc("NOTAM-PE", 1, "active", "DARPE01", t0, t0.Add(time.Hour)))).Restriction.Id
	v := h.restrictionsVersion()

	refused := h.sendRaw(h.restrictionReq(http.MethodPatch, "/v1/restrictions/"+id, jsonBytes(t, doc{"op": "expire", "ansp_version": 2})))
	if refused.Code != http.StatusBadRequest {
		t.Fatalf("PATCH op expire = %d %s", refused.Code, refused.Body.String())
	}
	if p := decodeProblem(t, refused); !hasProblemPrefix(p, "op") {
		t.Errorf("problem %+v", p.Errors)
	}
	if h.restrictionsVersion() != v || h.fake.rs().heads[id].State != restriction.StateActive {
		t.Fatalf("a refused expire changed something: version %d, state %s", h.restrictionsVersion(), h.fake.rs().heads[id].State)
	}
	t.Logf("PATCH op expire = %d %s", refused.Code, refused.Body.String())

	ended := h.patchRestriction(id, doc{"op": "end", "ansp_version": 2})
	if ended.Code != http.StatusOK || h.restrictionsVersion() != v+1 || h.fake.rs().heads[id].State != restriction.StateEnded {
		t.Fatalf("PATCH op end = %d %s", ended.Code, ended.Body.String())
	}
	if c := h.lastChange(); c.Reason != publication.ReasonRestrictionEnded {
		t.Errorf("change %+v", c)
	}
}

// movingStore is the fake store with an extend landing between the
// expiry's read of a head and its write under the lock.
type movingStore struct {
	*fakeStore
	extendTo time.Time
	moved    bool
}

func (m *movingStore) Restriction(ctx context.Context, ref string, byAnspRef bool) (store.RestrictionRecord, error) {
	rec, err := m.fakeStore.Restriction(ctx, ref, byAnspRef)
	if err == nil && !m.moved {
		m.moved = true
		m.mu.Lock()
		m.rs().heads[rec.ID].EndsAt = m.extendTo
		m.mu.Unlock()
	}
	return rec, err
}

// A head whose ends_at moved between the expiry's read and its lock is
// not expired on the read's window, even when the new end has passed
// too: nothing is written, so the record never names an end the head no
// longer has. Its twin: the next tick expires it, and the record names
// the moved ends_at.
func TestRestrictionExpiryHeadMoved(t *testing.T) {
	h, t0 := restrictionHarness(t)
	ends := t0.Add(2 * time.Second)
	extended := ends.Add(500 * time.Millisecond) // past at the tick as well
	id := decodeRestriction(t, h.postRestriction(createDoc("NOTAM-MV", 1, "active", "DARMV01", t0, ends))).Restriction.Id
	v := h.restrictionsVersion()
	h.rs.Store = &movingStore{fakeStore: h.fake, extendTo: extended}

	h.at(ends.Add(time.Second))
	if n, ran, err := h.rs.ExpireTick(context.Background()); err != nil || !ran || n != 0 {
		t.Fatalf("moved head: %d %v %v", n, ran, err)
	}
	if h.restrictionsVersion() != v || h.fake.rs().heads[id].State != restriction.StateActive {
		t.Fatalf("a moved head was expired: version %d, state %s", h.restrictionsVersion(), h.fake.rs().heads[id].State)
	}

	if n, _, err := h.rs.ExpireTick(context.Background()); err != nil || n != 1 {
		t.Fatalf("the next tick: %d %v", n, err)
	}
	var got map[string]string
	if err := json.Unmarshal(h.fake.heads[publication.DatasetRestrictions][v+1].Body, &got); err != nil {
		t.Fatal(err)
	}
	if e, err := time.Parse(time.RFC3339Nano, got["ends_at"]); err != nil || !e.Equal(extended) || got["feature_id"] != "DARMV01" {
		t.Errorf("record after the extend %v", got)
	}
}
