package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/authtest"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/restriction"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// restrictionHarness is the harness on the fake store with TSU001
// published and the restrictions' clock at t0.
func restrictionHarness(t *testing.T) (*pubHarness, time.Time) {
	t.Helper()
	h := newPubHarness(t, nil)
	h.publishAirspace()
	t0 := time.Now().UTC().Truncate(time.Second)
	h.at(t0)
	return h, t0
}

func withKey(v string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Idempotency-Key", v) }
}

// The lifecycle on the fake store: create planned, activate, extend,
// end; each accepted op a new version with its reason in the change
// record; the served feature carries cis_restriction; the ended one
// leaves the current set and stays in history by version.
func TestRestrictionLifecycle(t *testing.T) {
	h, t0 := restrictionHarness(t)
	starts, ends := t0.Add(10*time.Minute), t0.Add(2*time.Hour)
	v0 := h.restrictionsVersion()

	rec := h.postRestriction(createDoc("NOTAM-1", 1, "planned", "DAR1A2B", starts, ends))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	res := decodeRestriction(t, rec)
	id := res.Restriction.Id
	if res.Replay || res.Version != v0+1 || res.Reason == nil || *res.Reason != gen.RestrictionResultReason(publication.ReasonRestrictionCreated) ||
		res.Restriction.State != "planned" || res.Restriction.FeatureId != "DAR1A2B" || len(res.Restriction.Events) != 1 ||
		rec.Header().Get("ETag") != publication.ETag(publication.DatasetRestrictions, v0+1) {
		t.Fatalf("create result %+v", res)
	}
	if c := h.lastChange(); c.Reason != publication.ReasonRestrictionCreated || c.Version != v0+1 || strings.Join(c.FeatureIDs, ",") != "DAR1A2B" {
		t.Errorf("create change %+v", c)
	}
	_, served := h.servedRestrictions("")
	if m := served["DAR1A2B"]; m.State != restriction.StatePlanned || m.ID != id || m.AnspRef != "NOTAM-1" || m.AnspVersion != 1 ||
		!m.StartsAt.Equal(starts) || !m.EndsAt.Equal(ends) || m.EndedBy != nil || m.UspaceAirspaceID != "TSU001" {
		t.Errorf("served member %+v", m)
	}

	steps := []struct {
		body   doc
		state  string
		reason publication.Reason
	}{
		{doc{"op": "activate", "ansp_version": 2}, "active", publication.ReasonRestrictionActivated},
		{doc{"op": "extend", "ansp_version": 3, "ends_at": ends.Add(time.Hour).Format(time.RFC3339), "feature": darDoc("DAR1A2B", starts, ends.Add(time.Hour))}, "active", publication.ReasonRestrictionExtended},
		{doc{"op": "end", "ansp_version": 4}, "ended", publication.ReasonRestrictionEnded},
	}
	for i, s := range steps {
		before := h.restrictionsVersion()
		rec := h.patchRestriction(id, s.body)
		if rec.Code != http.StatusOK {
			t.Fatalf("step %d = %d %s", i, rec.Code, rec.Body.String())
		}
		r := decodeRestriction(t, rec)
		if r.Replay || r.Version != before+1 || string(r.Restriction.State) != s.state || *r.Reason != gen.RestrictionResultReason(s.reason) {
			t.Fatalf("step %d result %+v", i, r)
		}
		if c := h.lastChange(); c.Reason != s.reason || c.Version != before+1 {
			t.Errorf("step %d change %+v", i, c)
		}
	}
	// The extension moved both truths: the member and the period.
	ended := decodeRestriction(t, h.patchRestriction(id, doc{"op": "end", "ansp_version": 4})).Restriction
	if ended.EndedBy == nil || *ended.EndedBy != "ansp" || !ended.EndsAt.Equal(ends.Add(time.Hour)) || len(ended.Events) != 4 {
		t.Errorf("ended head %+v", ended)
	}
	if _, served := h.servedRestrictions(""); len(served) != 0 {
		t.Errorf("an ended restriction is still current: %v", served)
	}
	// History by version: the extended version still holds it, with the
	// new ends_at in the member and in the feature's period.
	vext := v0 + 3
	old := h.read(http.MethodGet, "/v1/restrictions/versions/"+i64toa(vext))
	if old.Code != http.StatusOK || old.Header().Get(HeaderPublisherKID) != anspKID || !strings.Contains(old.Body.String(), `"op":"extend"`) {
		t.Errorf("version %d = %d %s", vext, old.Code, old.Body.String())
	}
	ver := h.read(http.MethodGet, "/v1/restrictions/versions")
	if ver.Code != http.StatusOK || !strings.Contains(ver.Body.String(), `"reason":"restriction_extended"`) {
		t.Errorf("versions = %d %s", ver.Code, ver.Body.String())
	}
	snap, err := h.fake.Snapshot(context.Background(), publication.DatasetRestrictions, vext)
	if err != nil {
		t.Fatal(err)
	}
	body := string(inflate(t, snap.BodyGz))
	if !strings.Contains(body, `"ends_at":"`+ends.Add(time.Hour).Format(time.RFC3339)+`"`) ||
		!strings.Contains(body, `"endDateTime":"`+ends.Add(time.Hour).Format(time.RFC3339)+`"`) {
		t.Errorf("version %d snapshot: %s", vext, body)
	}
}

// Every op replayed with the same (ansp_ref, ansp_version) pair, with no
// Idempotency-Key, with one, and with a different one on the same pair:
// 200, replay true, the same head, no new version and no change (E-01:
// beside it, the next version is a new version).
func TestRestrictionReplay(t *testing.T) {
	h, t0 := restrictionHarness(t)
	starts, ends := t0, t0.Add(time.Hour)
	create := createDoc("NOTAM-R", 1, "active", "DARR001", starts, ends)
	first := h.postRestriction(create, withKey("k-1"))
	if first.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", first.Code, first.Body.String())
	}
	id := decodeRestriction(t, first).Restriction.Id
	ops := []doc{
		create,
		{"op": "extend", "ansp_version": 2, "ends_at": ends.Add(time.Hour).Format(time.RFC3339), "feature": darDoc("DARR001", starts, ends.Add(time.Hour))},
		{"op": "end", "ansp_version": 3},
	}
	for i, op := range ops {
		if i > 0 {
			if rec := h.patchRestriction(id, op); rec.Code != http.StatusOK || decodeRestriction(t, rec).Replay {
				t.Fatalf("op %d = %d %s", i, rec.Code, rec.Body.String())
			}
		}
		version, changes := h.restrictionsVersion(), len(h.fake.changes)
		head := h.fake.rs().heads[id].Head
		for _, edit := range []func(*http.Request){func(*http.Request) {}, withKey("k-1"), withKey("k-2-different")} {
			var rec *httptest.ResponseRecorder
			if i == 0 {
				rec = h.postRestriction(op, edit)
			} else {
				rec = h.patchRestriction(id, op, edit)
			}
			r := decodeRestriction(t, rec)
			if rec.Code != http.StatusOK || !r.Replay || r.Version != version || r.Reason != nil || r.Restriction.Id != id ||
				r.Restriction.AnspVersion != head.AnspVersion || string(r.Restriction.State) != string(head.State) {
				t.Fatalf("op %d replay = %d %+v", i, rec.Code, r)
			}
		}
		if h.restrictionsVersion() != version || len(h.fake.changes) != changes || h.fake.rs().heads[id].Head != head {
			t.Fatalf("op %d: a replay wrote: version %d -> %d, changes %d -> %d", i, version, h.restrictionsVersion(), changes, len(h.fake.changes))
		}
	}
	if got := h.counter("restrictions", CounterRestrictionsReplayed); got != 9 {
		t.Errorf("replays counted %d", got)
	}
	// The same ansp_version with another body is 409, never a replay:
	// another op, and the create with another window.
	version := h.restrictionsVersion()
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"another op":     h.patchRestriction(id, doc{"op": "cancel", "ansp_version": 3}),
		"another create": h.postRestriction(createDoc("NOTAM-R", 1, "active", "DARR001", starts, ends.Add(time.Minute))),
	} {
		if rec.Code != http.StatusConflict || !strings.HasSuffix(decodeProblem(t, rec).Type, "/"+SlugAnspVersion) {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if h.restrictionsVersion() != version {
		t.Error("a conflicting body wrote")
	}
}

// 409 ansp_version for a lower version and 409 state for an op the state
// does not take, each beside the accepted op one field away (E-01); the
// refusals are attempts the ANSP reads back.
func TestRestrictionConflicts(t *testing.T) {
	h, t0 := restrictionHarness(t)
	rec := h.postRestriction(createDoc("NOTAM-C", 5, "planned", "DARC001", t0.Add(time.Hour), t0.Add(2*time.Hour)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	id := decodeRestriction(t, rec).Restriction.Id
	check := func(rec *httptest.ResponseRecorder, status int, slug, field string) {
		t.Helper()
		if rec.Code != status {
			t.Fatalf("= %d %s", rec.Code, rec.Body.String())
		}
		if status >= 400 {
			p := decodeProblem(t, rec)
			if !strings.HasSuffix(p.Type, "/"+slug) || p.Errors == nil || (*p.Errors)[0].Field != field {
				t.Errorf("problem %+v", p)
			}
		}
	}
	check(h.patchRestriction(id, doc{"op": "activate", "ansp_version": 4}), http.StatusConflict, SlugAnspVersion, "ansp_version")
	check(h.patchRestriction(id, doc{"op": "end", "ansp_version": 6}), http.StatusConflict, SlugState, "state")
	check(h.postRestriction(createDoc("NOTAM-C", 6, "planned", "DARC001", t0.Add(time.Hour), t0.Add(2*time.Hour))), http.StatusConflict, SlugState, "state")
	check(h.patchRestriction(id, doc{"op": "cancel", "ansp_version": 6}), http.StatusOK, "", "")
	check(h.patchRestriction(id, doc{"op": "activate", "ansp_version": 7}), http.StatusConflict, SlugState, "state")
	// The POST of a stored ansp_ref with a lower version is 409 too.
	check(h.postRestriction(createDoc("NOTAM-C", 1, "planned", "DARC001", t0.Add(time.Hour), t0.Add(2*time.Hour))), http.StatusConflict, SlugAnspVersion, "ansp_version")
	att := h.get("/v1/publications/restrictions/attempts", h.anspToken())
	if att.Code != http.StatusOK || strings.Count(att.Body.String(), `"outcome":"refused"`) != 5 {
		t.Errorf("attempts = %d %s", att.Code, att.Body.String())
	}
	// An unknown id and an unknown ansp_ref are 404.
	if rec := h.patchRestriction("01NOSUCHRESTRICTION0000000", doc{"op": "end", "ansp_version": 9}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d", rec.Code)
	}
	raw := jsonBytes(t, doc{"op": "end", "ansp_version": 9})
	if rec := h.send(h.restrictionReq(http.MethodPatch, "/v1/restrictions/NOTAM-NONE?by=ansp_ref", raw), raw); rec.Code != http.StatusNotFound {
		t.Errorf("unknown ansp_ref = %d", rec.Code)
	}
}

// The ANSP addresses a restriction by its ansp_ref with by=ansp_ref.
func TestRestrictionByAnspRef(t *testing.T) {
	h, t0 := restrictionHarness(t)
	if rec := h.postRestriction(createDoc("NOTAM/26 A1", 1, "planned", "DARB001", t0.Add(time.Hour), t0.Add(2*time.Hour))); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	ref := url.PathEscape("NOTAM/26 A1")
	raw := jsonBytes(t, doc{"op": "activate", "ansp_version": 2})
	rec := h.send(h.restrictionReq(http.MethodPatch, "/v1/restrictions/"+ref+"?by=ansp_ref", raw), raw)
	if rec.Code != http.StatusOK || decodeRestriction(t, rec).Restriction.State != "active" {
		t.Fatalf("by ansp_ref = %d %s", rec.Code, rec.Body.String())
	}
	got := h.read(http.MethodGet, "/v1/restrictions/"+ref+"?by=ansp_ref")
	if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"ansp_ref":"NOTAM/26 A1"`) {
		t.Errorf("GET by ansp_ref = %d %s", got.Code, got.Body.String())
	}
	// The same reference as an id is 404 (E-01).
	if got := h.read(http.MethodGet, "/v1/restrictions/"+ref); got.Code != http.StatusNotFound {
		t.Errorf("GET by id = %d", got.Code)
	}
}

// The dataset rules through the handler, each refusal beside the DAR
// restriction it differs from in one thing (E-01): the ANSP's DAR + 4
// base-36 identifier is accepted beside one of 8 characters; an
// identifier a zone holds, one another restriction holds, an unknown
// airspace, an outline outside it and one over 10 000 km2 are refused.
func TestRestrictionRefusals(t *testing.T) {
	h, t0 := restrictionHarness(t)
	z := zonesDoc(t)
	fprops(z, 0)["identifier"] = "ZONE0A1"
	if rec := h.put("zones", jsonBytes(t, z)); rec.Code != http.StatusCreated {
		t.Fatalf("zones = %d %s", rec.Code, rec.Body.String())
	}
	starts, ends := t0, t0.Add(time.Hour)
	if rec := h.postRestriction(createDoc("NOTAM-HELD", 1, "active", "DARHELD", starts, ends)); rec.Code != http.StatusCreated {
		t.Fatalf("holder = %d %s", rec.Code, rec.Body.String())
	}
	cases := []struct {
		name  string
		edit  func(d doc)
		field string
	}{
		{"accepted: DAR + 4 base-36", func(doc) {}, ""},
		{"an 8-character identifier", func(d doc) { d["feature"].(doc)["properties"].(doc)["identifier"] = "DAR1A2BC" }, "feature.properties.identifier"},
		{"a reason without DAR", func(d doc) { d["feature"].(doc)["properties"].(doc)["reason"] = []any{"EMERGENCY"} }, "feature.properties.reason"},
		{"NO_RESTRICTION", func(d doc) { d["feature"].(doc)["properties"].(doc)["type"] = "NO_RESTRICTION" }, "feature.properties.type"},
		{"an identifier a zone holds", func(d doc) { d["feature"].(doc)["properties"].(doc)["identifier"] = "ZONE0A1" }, "feature.properties.identifier"},
		{"an identifier another restriction holds", func(d doc) { d["feature"].(doc)["properties"].(doc)["identifier"] = "DARHELD" }, "feature.properties.identifier"},
		{"an unknown airspace", func(d doc) { d["uspace_airspace_id"] = "TSU999" }, "uspace_airspace_id"},
		{"outside its airspace", func(d doc) {
			d["feature"].(doc)["geometry"].(doc)["coordinates"] = []any{[]any{[]any{45.80, 42.70}, []any{45.82, 42.70}, []any{45.82, 42.72}, []any{45.80, 42.72}, []any{45.80, 42.70}}}
		}, "uspace_airspace_id"},
		{"a window over 24 h", func(d doc) {
			end := starts.Add(25 * time.Hour)
			d["ends_at"] = end.Format(time.RFC3339)
			d["feature"] = darDoc("DAR1A2B", starts, end)
		}, "ends_at"},
		{"an unknown member", func(d doc) { d["version"] = 1 }, "version"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := createDoc("NOTAM-RF-"+i64toa(int64(i)), 1, "active", "DAR1A2B", starts, ends)
			if c.field == "" {
				d["feature"].(doc)["properties"].(doc)["identifier"] = "DAR9Z9Z"
			}
			c.edit(d)
			var rec *httptest.ResponseRecorder
			if c.field == "" {
				rec = h.postRestriction(d)
			} else {
				rec = h.postRestrictionRaw(d)
			}
			if c.field == "" {
				if rec.Code != http.StatusCreated {
					t.Fatalf("= %d %s", rec.Code, rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("= %d %s", rec.Code, rec.Body.String())
			}
			p := decodeProblem(t, rec)
			if !strings.HasSuffix(p.Type, "/"+SlugRestrictionRefused) || !hasProblemPrefix(p, c.field) {
				t.Errorf("problem %+v", p.Errors)
			}
		})
	}
	// Over 10 000 km2, measured by the store.
	h.fake.rs().placement = &store.Placement{AreaM2: 10_001e6, AirspaceCurrent: true, Intersects: true}
	rec := h.postRestriction(createDoc("NOTAM-BIG", 1, "active", "DARBIG1", starts, ends))
	if rec.Code != http.StatusBadRequest || !hasProblemPrefix(decodeProblem(t, rec), "feature.geometry") {
		t.Errorf("over 10 000 km2 = %d %s", rec.Code, rec.Body.String())
	}
	h.fake.rs().placement = &store.Placement{AreaM2: 10_000e6, AirspaceCurrent: true, Intersects: true}
	if rec := h.postRestriction(createDoc("NOTAM-BIG", 1, "active", "DARBIG1", starts, ends)); rec.Code != http.StatusCreated {
		t.Errorf("exactly 10 000 km2 = %d %s", rec.Code, rec.Body.String())
	}
}

func hasProblemPrefix(p gen.Problem, field string) bool {
	if p.Errors == nil {
		return false
	}
	for _, e := range *p.Errors {
		if strings.HasPrefix(e.Field, field) {
			return true
		}
	}
	return false
}

// An extend republishes the feature: without it, with another
// identifier, or with a period that is not the new window, it is
// refused; the accepted extend beside them (E-01).
func TestRestrictionExtendFeature(t *testing.T) {
	h, t0 := restrictionHarness(t)
	starts, ends := t0, t0.Add(time.Hour)
	id := decodeRestriction(t, h.postRestriction(createDoc("NOTAM-E", 1, "active", "DARE001", starts, ends))).Restriction.Id
	newEnd := ends.Add(time.Hour)
	for name, c := range map[string]struct {
		body  doc
		field string
	}{
		"no feature":           {doc{"op": "extend", "ansp_version": 2, "ends_at": newEnd.Format(time.RFC3339)}, "feature"},
		"the old period":       {doc{"op": "extend", "ansp_version": 2, "ends_at": newEnd.Format(time.RFC3339), "feature": darDoc("DARE001", starts, ends)}, "feature.properties.limitedApplicability[0].endDateTime"},
		"an earlier ends_at":   {doc{"op": "extend", "ansp_version": 2, "ends_at": ends.Add(-time.Minute).Format(time.RFC3339), "feature": darDoc("DARE001", starts, ends.Add(-time.Minute))}, "ends_at"},
		"a window over 24 h":   {doc{"op": "extend", "ansp_version": 2, "ends_at": starts.Add(25 * time.Hour).Format(time.RFC3339), "feature": darDoc("DARE001", starts, starts.Add(25*time.Hour))}, "ends_at"},
		"ends_at on an end op": {doc{"op": "end", "ansp_version": 2, "ends_at": newEnd.Format(time.RFC3339)}, "ends_at"},
	} {
		rec := h.patchRestriction(id, c.body)
		if rec.Code != http.StatusBadRequest || !hasProblemPrefix(decodeProblem(t, rec), c.field) {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// A valid feature that differs in anything but the period's end is a
	// conflict (409), beside the accepted extend that changes only it.
	edited := func(edit func(f doc)) doc {
		f := darDoc("DARE001", starts, newEnd)
		edit(f)
		return f
	}
	version := h.restrictionsVersion()
	for name, f := range map[string]doc{
		"another identifier": darDoc("DARE002", starts, newEnd),
		"another name":       edited(func(f doc) { f["properties"].(doc)["name"] = []any{doc{"lang": "en-GB", "text": "Renamed"}} }),
		"another type":       edited(func(f doc) { f["properties"].(doc)["type"] = "CONDITIONAL" }),
		"another outline": edited(func(f doc) {
			f["geometry"].(doc)["coordinates"] = []any{[]any{[]any{44.80, 41.70}, []any{44.83, 41.70}, []any{44.83, 41.72}, []any{44.80, 41.72}, []any{44.80, 41.70}}}
		}),
		"another upper limit": edited(func(f doc) { f["geometry"].(doc)["layer"].(doc)["upper"] = 150 }),
	} {
		rec := h.patchRestriction(id, doc{"op": "extend", "ansp_version": 2, "ends_at": newEnd.Format(time.RFC3339), "feature": f})
		if rec.Code != http.StatusConflict || !strings.HasSuffix(decodeProblem(t, rec).Type, "/"+SlugFeatureChanged) {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	if h.restrictionsVersion() != version {
		t.Error("a conflicting extend wrote")
	}
	rec := h.patchRestriction(id, doc{"op": "extend", "ansp_version": 2, "ends_at": newEnd.Format(time.RFC3339), "feature": darDoc("DARE001", starts, newEnd)})
	if rec.Code != http.StatusOK || !decodeRestriction(t, rec).Restriction.EndsAt.Equal(newEnd) {
		t.Errorf("extend = %d %s", rec.Code, rec.Body.String())
	}
}

// The route authentication of the writes: each refusal beside the
// accepted write (E-01).
func TestRestrictionAuth(t *testing.T) {
	h, t0 := restrictionHarness(t)
	body := jsonBytes(t, createDoc("NOTAM-AUTH", 1, "planned", "DARA001", t0.Add(time.Hour), t0.Add(2*time.Hour)))
	post := func(edit ...func(*http.Request)) *httptest.ResponseRecorder {
		if len(edit) == 0 {
			return h.send(h.restrictionReq(http.MethodPost, "/v1/restrictions", body), body)
		}
		return h.sendRaw(h.restrictionReq(http.MethodPost, "/v1/restrictions", body, edit...))
	}
	for name, c := range map[string]struct {
		edit   func(*http.Request)
		status int
		slug   string
	}{
		"no token":        {func(r *http.Request) { r.Header.Del("Authorization") }, 401, auth.SlugUnauthenticated},
		"read scope only": {func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+h.token(anspID, auth.ScopeRead)) }, 403, auth.SlugForbidden},
		"the authority": {func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+h.token(authorityID, auth.ScopePublishRestrictions))
		}, 403, auth.SlugNotAPublisher},
		"no certificate":    {func(r *http.Request) { r.Header.Del(auth.HeaderClientCertSubject) }, 403, auth.SlugMTLSRequired},
		"wrong certificate": {func(r *http.Request) { r.Header.Set(auth.HeaderClientCertSubject, "CN=impostor") }, 403, auth.SlugMTLSRequired},
		"no signature":      {func(r *http.Request) { r.Header.Del(jws.HeaderSignature) }, 403, jws.SlugSignature},
		"the authority's signature": {func(r *http.Request) {
			r.Header.Set(jws.HeaderSignature, h.sign(body))
		}, 403, jws.SlugSignature},
		"text/plain": {func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415, SlugUnsupportedMediaType},
	} {
		rec := post(c.edit)
		if rec.Code != c.status || !strings.HasSuffix(decodeProblem(t, rec).Type, "/"+c.slug) {
			t.Errorf("%s = %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// A body altered after signing.
	req := h.restrictionReq(http.MethodPost, "/v1/restrictions", body)
	altered := bytes.Replace(body, []byte("NOTAM-AUTH"), []byte("NOTAM-AUTX"), 1)
	req.Body = http.NoBody
	req = httptest.NewRequest(http.MethodPost, "/v1/restrictions", bytes.NewReader(altered))
	for k, v := range h.restrictionReq(http.MethodPost, "/v1/restrictions", body).Header {
		req.Header[k] = v
	}
	if rec := h.do(req); rec.Code != 403 {
		t.Errorf("altered = %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(); rec.Code != http.StatusCreated {
		t.Fatalf("accepted = %d %s", rec.Code, rec.Body.String())
	}
	// Past the 256 KiB cap: 413 (E-10).
	big := jsonBytes(t, doc{"ansp_ref": strings.Repeat("x", restrictionMaxBytes)})
	if rec := h.do(h.restrictionReq(http.MethodPost, "/v1/restrictions", big)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("past the cap = %d", rec.Code)
	}
	// The reads take cis.read.
	req = httptest.NewRequest(http.MethodGet, "/v1/restrictions/heads", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+h.token(anspID, auth.ScopePublishRestrictions))
	if rec := h.do(req); rec.Code != http.StatusForbidden {
		t.Errorf("heads without cis.read = %d", rec.Code)
	}
}

// In mode off the certificate is not checked: a write without it passes
// and the mtls component is degraded, so the status line is at error
// level (hard rule 4), read back.
func TestRestrictionMTLSOff(t *testing.T) {
	var buf bytes.Buffer
	status := obs.NewStatus("api", nil, time.Now())
	auth.ReportMTLS(status.Component("mtls"), config.MTLSOff)
	h, t0 := restrictionHarness(t)
	g, err := auth.NewGuard(auth.GuardConfig{
		Verifier: tokenVerifier(t, h), Problems: WriteProblem, AuthorityClientID: authorityID, ANSPClientID: anspID,
		MTLSMode: config.MTLSOff, Component: status.Component("auth"),
	})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	mw := g.RequireMTLSSubject()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := h.restrictionReq(http.MethodPost, "/v1/restrictions", []byte(`{}`), func(r *http.Request) { r.Header.Del(auth.HeaderClientCertSubject) })
	mw.ServeHTTP(httptest.NewRecorder(), req)
	if !called || status.Component("auth").Counter(auth.CounterMTLSOffPassed, "").Value() != 1 {
		t.Errorf("mode off: called %v", called)
	}
	status.Log(context.Background(), obs.NewLogger(&buf, "api", slog.LevelInfo), t0)
	var line map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &line); err != nil || line["level"] != "ERROR" ||
		!strings.Contains(buf.String(), "CISP_MTLS_MODE=off") {
		t.Errorf("status line: %s", buf.String())
	}
}

// tokenVerifier is the harness's machine verifier.
func tokenVerifier(t *testing.T, h *pubHarness) auth.TokenVerifier {
	t.Helper()
	mv, err := auth.NewMachineVerifier(context.Background(), auth.MachineConfig{
		Issuers: []auth.Source{{ID: tokenIssuer, Keys: h.iss.JWKS()}}, Audiences: []string{tokenAudience},
	})
	if err != nil {
		t.Fatal(err)
	}
	return mv
}

// Expiry (E-02 both branches): an active restriction one second before
// its ends_at stays; one second past it the next tick ends it with
// ended_by expiry, a restriction_expired version and change with no
// publisher signature and actor system, and the gauge moves; with the
// ticker stopped for 31 s the status line goes to error, read back; the
// next tick clears it.
func TestRestrictionExpiry(t *testing.T) {
	h, t0 := restrictionHarness(t)
	ends := t0.Add(2 * time.Second)
	id := decodeRestriction(t, h.postRestriction(createDoc("NOTAM-X", 1, "active", "DARX001", t0, ends))).Restriction.Id
	v := h.restrictionsVersion()

	h.at(ends.Add(-time.Second))
	if n, ran, err := h.rs.ExpireTick(context.Background()); err != nil || !ran || n != 0 {
		t.Fatalf("before ends_at: %d %v %v", n, ran, err)
	}
	h.rs.Probe(context.Background())
	gauge := h.status.Component("restrictions").Gauge(GaugeRestrictionsActive, "")
	if h.restrictionsVersion() != v || gauge.Value() != 1 {
		t.Fatalf("expired early: version %d, active %v", h.restrictionsVersion(), gauge.Value())
	}

	h.at(ends.Add(time.Second))
	n, ran, err := h.rs.ExpireTick(context.Background())
	if err != nil || !ran || n != 1 {
		t.Fatalf("past ends_at: %d %v %v", n, ran, err)
	}
	head := h.fake.rs().heads[id]
	if head.State != restriction.StateEnded || head.EndedBy == nil || *head.EndedBy != restriction.EndedByExpiry {
		t.Fatalf("head %+v", head.Head)
	}
	if last := head.Events[len(head.Events)-1]; last.Op != restriction.OpExpire || last.Actor != store.SystemActor {
		t.Errorf("event %+v", last)
	}
	if c := h.lastChange(); c.Reason != publication.ReasonRestrictionExpired || c.Version != v+1 || strings.Join(c.RemovedIDs, ",") != "DARX001" {
		t.Errorf("change %+v", c)
	}
	pub := h.fake.heads[publication.DatasetRestrictions][v+1]
	if pub.PublisherSignature != nil || pub.PublisherClientID != store.SystemPublisher || !strings.Contains(string(pub.Body), `"op":"expire"`) {
		t.Errorf("expiry publication %+v %s", pub, pub.Body)
	}
	if gauge.Value() != 0 || h.counter("restrictions", CounterRestrictionsExpired) != 1 || h.counter(ExpiryComponent, CounterExpiryTicks) != 2 {
		t.Errorf("gauge %v expired %d ticks %d", gauge.Value(), h.counter("restrictions", CounterRestrictionsExpired), h.counter(ExpiryComponent, CounterExpiryTicks))
	}
	// A second tick finds nothing.
	if n, _, _ := h.rs.ExpireTick(context.Background()); n != 0 || h.restrictionsVersion() != v+1 {
		t.Errorf("second tick %d", n)
	}

	// The dead ticker: 31 s without a run is an error line.
	last := ends.Add(time.Second)
	var buf bytes.Buffer
	logger := obs.NewLogger(&buf, "api", slog.LevelInfo)
	h.at(last.Add(29 * time.Second))
	h.status.AddProbe(h.rs.Probe)
	h.status.Log(context.Background(), logger, last)
	h.at(last.Add(31 * time.Second))
	h.status.Log(context.Background(), logger, last)
	lines := statusLines(t, &buf)
	if len(lines) != 2 {
		t.Fatalf("lines %s", buf.String())
	}
	if exp, _ := lines[0][ExpiryComponent].(map[string]any); exp["degraded"] != nil {
		t.Errorf("29 s after the run, degraded: %v", exp)
	}
	exp, _ := lines[1][ExpiryComponent].(map[string]any)
	if lines[1]["level"] != "ERROR" || !strings.Contains(exp["degraded"].(string), "restriction expiry last ran") {
		t.Errorf("31 s after the run: %v", lines[1])
	}
	t.Logf("status line with the ticker stopped 31 s: %s", strings.TrimSpace(strings.Split(buf.String(), "\n")[1]))
	st := h.read(http.MethodGet, "/v1/status")
	if !strings.Contains(st.Body.String(), `"stale":true`) {
		t.Errorf("status: %s", st.Body.String())
	}
	if _, _, err := h.rs.ExpireTick(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.rs.Probe(context.Background())
	if r := h.status.Component(ExpiryComponent).DegradedReason(); r != "" {
		t.Errorf("after a tick: %s", r)
	}
}

func statusLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%v: %s", err, l)
		}
		out = append(out, m)
	}
	return out
}

// Before any run the expiry is stale once ExpiryStaleAfter has passed
// since the start; another replica's run is not this one's (not leader);
// an expiry that cannot publish leaves the head active and degrades.
func TestRestrictionExpiryDegraded(t *testing.T) {
	h, t0 := restrictionHarness(t)
	h.rs.Started = t0
	h.at(t0.Add(10 * time.Second))
	h.rs.Probe(context.Background())
	if r := h.status.Component(ExpiryComponent).DegradedReason(); r != "" {
		t.Errorf("10 s after the start: %s", r)
	}
	h.at(t0.Add(31 * time.Second))
	h.rs.Probe(context.Background())
	if r := h.status.Component(ExpiryComponent).DegradedReason(); !strings.Contains(r, "has not run since the start") {
		t.Errorf("31 s after the start: %q", r)
	}

	h.fake.rs().otherLeader = true
	if _, ran, err := h.rs.ExpireTick(context.Background()); ran || err != nil || h.counter(ExpiryComponent, CounterExpiryNotLeader) != 1 {
		t.Errorf("not leader: ran %v err %v", ran, err)
	}
	h.fake.rs().otherLeader = false

	h.at(t0)
	id := decodeRestriction(t, h.postRestriction(createDoc("NOTAM-F", 1, "active", "DARF001", t0, t0.Add(time.Second)))).Restriction.Id
	h.at(t0.Add(2 * time.Second))
	signer := h.rs.Signer
	h.rs.Signer = nil
	if _, ran, err := h.rs.ExpireTick(context.Background()); !ran || err != nil {
		t.Fatalf("tick: %v %v", ran, err)
	}
	if h.fake.rs().heads[id].State != restriction.StateActive || !strings.Contains(h.status.Component(ExpiryComponent).DegradedReason(), "could not be expired") ||
		h.counter(ExpiryComponent, CounterExpiryFailed) != 1 {
		t.Errorf("unpublishable expiry: %s %s", h.fake.rs().heads[id].State, h.status.Component(ExpiryComponent).DegradedReason())
	}
	h.rs.Signer = signer
	if n, _, _ := h.rs.ExpireTick(context.Background()); n != 1 || h.status.Component(ExpiryComponent).DegradedReason() != "" {
		t.Errorf("retried: %d %s", n, h.status.Component(ExpiryComponent).DegradedReason())
	}
	// A store that is down: the tick fails and says so.
	h.fake.down = true
	if _, _, err := h.rs.ExpireTick(context.Background()); err == nil || !strings.Contains(h.status.Component(ExpiryComponent).DegradedReason(), "failed") {
		t.Errorf("store down: %v", err)
	}
	h.rs.Probe(context.Background())
	if !strings.Contains(h.status.Component(ExpiryComponent).DegradedReason(), "cannot be read") {
		t.Errorf("probe with the store down: %s", h.status.Component(ExpiryComponent).DegradedReason())
	}
	h.fake.down = false
	// RunExpiry ticks until its context ends.
	ctx, cancel := context.WithCancel(context.Background())
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() { h.rs.RunExpiry(ctx, tick); close(done) }()
	tick <- time.Now()
	cancel()
	<-done
}

// Staleness: never heard, stale with a null since; a heartbeat clears it;
// 61 s without one is stale with since = heartbeat + 60 s in the heads,
// the dataset, the status and the status line (warning, never error);
// the heartbeat returns and it clears. No version is made and nothing is
// ended (B-04, B-11).
func TestRestrictionPublisherStale(t *testing.T) {
	h, t0 := restrictionHarness(t)
	h.pubs.Now = func() time.Time { return t0 }
	id := decodeRestriction(t, h.postRestriction(createDoc("NOTAM-S", 1, "active", "DARS001", t0, t0.Add(time.Hour)))).Restriction.Id
	v := h.restrictionsVersion()
	heads := func() map[string]json.RawMessage {
		rec := h.read(http.MethodGet, "/v1/restrictions/heads")
		var m map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	dataset := func() (doc, *httptest.ResponseRecorder) {
		rec := h.read(http.MethodGet, "/v1/restrictions")
		d, _ := collection(t, rec)
		return d, rec
	}
	// Never heard from.
	if string(heads()["cis_publisher_stale_since"]) != "null" {
		t.Errorf("never heard: %v", heads())
	}
	d, rec := dataset()
	if _, ok := d[MemberPublisherStaleSince]; !ok || d[MemberPublisherStaleSince] != nil || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("dataset never heard: %v %s", d[MemberPublisherStaleSince], rec.Header().Get("Cache-Control"))
	}
	verifyCISP(t, rec.Header().Get(HeaderSignature), rec.Body.Bytes())

	beat := func(at time.Time) {
		h.pubs.Now = func() time.Time { return at }
		body := `{"sent_at":"` + at.Format(time.RFC3339) + `","active_refs":["NOTAM-S"]}`
		_, rec := h.heartbeat(h.anspToken(), body, func(r *http.Request) { r.Header.Set(auth.HeaderClientCertSubject, anspSubject) })
		if rec.Code != http.StatusNoContent {
			t.Fatalf("heartbeat = %d %s", rec.Code, rec.Body.String())
		}
	}
	beat(t0)
	h.at(t0.Add(15 * time.Second))
	if _, ok := heads()["cis_publisher_stale_since"]; ok {
		t.Error("heard 15 s ago: stale")
	}
	if d, rec := dataset(); d[MemberPublisherStaleSince] != nil || rec.Header().Get("Cache-Control") == "no-store" {
		t.Errorf("heard: %v", d[MemberPublisherStaleSince])
	}
	h.rs.Probe(context.Background())
	if w := h.status.Component(ANSPComponent).Warning(); w != "" {
		t.Errorf("heard: warning %q", w)
	}

	h.at(t0.Add(61 * time.Second))
	since := t0.Add(60 * time.Second).Format(time.RFC3339)
	if got := string(heads()["cis_publisher_stale_since"]); got != `"`+since+`"` {
		t.Errorf("61 s: %s", got)
	}
	d, rec = dataset()
	if d[MemberPublisherStaleSince] != since {
		t.Errorf("dataset 61 s: %v", d[MemberPublisherStaleSince])
	}
	verifyCISP(t, rec.Header().Get(HeaderSignature), rec.Body.Bytes())
	if st := h.read(http.MethodGet, "/v1/status").Body.String(); !strings.Contains(st, `"ansp_stale_since":"`+since+`"`) {
		t.Errorf("status: %s", st)
	}
	var buf bytes.Buffer
	h.rs.Probe(context.Background())
	h.status.Component(ExpiryComponent).SetHealthy()
	h.status.Log(context.Background(), obs.NewLogger(&buf, "api", slog.LevelInfo), t0)
	line := statusLines(t, &buf)[0]
	if line["level"] != "WARN" || !strings.Contains(buf.String(), "ansp-01 stale since "+since) {
		t.Errorf("status line: %s", buf.String())
	}
	t.Logf("status line with the ANSP silent 61 s: %s", strings.TrimSpace(buf.String()))
	// The filtered read carries it too; HEAD has no body to carry it.
	if f := h.read(http.MethodGet, "/v1/restrictions?at="+url.QueryEscape(t0.Add(time.Minute).Format(time.RFC3339))); !strings.Contains(f.Body.String(), `"cis_publisher_stale_since":"`+since+`"`) {
		t.Errorf("filtered: %s", f.Body.String())
	}
	if hd := h.read(http.MethodHead, "/v1/restrictions"); hd.Code != http.StatusOK {
		t.Errorf("HEAD = %d", hd.Code)
	}

	// Nothing changed: no version, the restriction still active.
	if h.restrictionsVersion() != v || h.fake.rs().heads[id].State != restriction.StateActive {
		t.Errorf("staleness acted: version %d, state %s", h.restrictionsVersion(), h.fake.rs().heads[id].State)
	}

	beat(t0.Add(61 * time.Second))
	if _, ok := heads()["cis_publisher_stale_since"]; ok {
		t.Error("the heartbeat returned: still stale")
	}
	h.rs.Probe(context.Background())
	if w := h.status.Component(ANSPComponent).Warning(); w != "" {
		t.Errorf("returned: warning %q", w)
	}
}

// The heartbeat's active_refs: a matching declaration counts nothing; an
// unknown ref and a missing active head each count and show in the
// status; nothing is acted on (versions unchanged).
func TestRestrictionHeartbeatRefs(t *testing.T) {
	h, t0 := restrictionHarness(t)
	h.pubs.Now = func() time.Time { return t0 }
	for _, ref := range []string{"NOTAM-H1", "NOTAM-H2"} {
		if rec := h.postRestriction(createDoc(ref, 1, "active", "DAR"+ref[6:]+"X", t0, t0.Add(time.Hour))); rec.Code != http.StatusCreated {
			t.Fatalf("%s = %d %s", ref, rec.Code, rec.Body.String())
		}
	}
	v := h.restrictionsVersion()
	beat := func(refs string) {
		body := `{"sent_at":"` + t0.Format(time.RFC3339) + `","active_refs":` + refs + `}`
		if _, rec := h.heartbeat(h.anspToken(), body, func(r *http.Request) { r.Header.Set(auth.HeaderClientCertSubject, anspSubject) }); rec.Code != http.StatusNoContent {
			t.Fatalf("heartbeat = %d %s", rec.Code, rec.Body.String())
		}
	}
	beat(`["NOTAM-H1","NOTAM-H2"]`)
	if u, m := h.counter("restrictions", CounterHeartbeatRefUnknown), h.counter("restrictions", CounterHeartbeatRefMissing); u != 0 || m != 0 {
		t.Errorf("matching: unknown %d missing %d", u, m)
	}
	if st := h.read(http.MethodGet, "/v1/status").Body.String(); strings.Contains(st, "heartbeat_ref") {
		t.Errorf("matching status lists refs: %s", st)
	}
	beat(`["NOTAM-H1","NOTAM-GHOST"]`)
	if u, m := h.counter("restrictions", CounterHeartbeatRefUnknown), h.counter("restrictions", CounterHeartbeatRefMissing); u != 1 || m != 1 {
		t.Errorf("disagreeing: unknown %d missing %d", u, m)
	}
	st := h.read(http.MethodGet, "/v1/status").Body.String()
	if !strings.Contains(st, `"heartbeat_ref_unknown":["NOTAM-GHOST"]`) || !strings.Contains(st, `"heartbeat_ref_missing":["NOTAM-H2"]`) {
		t.Errorf("status: %s", st)
	}
	if h.restrictionsVersion() != v {
		t.Error("a heartbeat made a version")
	}
	// A store that cannot list the active refs costs the comparison only.
	h.fake.rs().refsErr = errors.New("boom")
	beat(`["NOTAM-H1"]`)
	h.fake.rs().refsErr = nil
	if u := h.counter("restrictions", CounterHeartbeatRefUnknown); u != 1 {
		t.Errorf("after a failed comparison: %d", u)
	}
}

// The heads: state, airspace and at filter; limit is bounded; a bad at
// is 400; GET one is the head or 404.
func TestRestrictionList(t *testing.T) {
	h, t0 := restrictionHarness(t)
	a := decodeRestriction(t, h.postRestriction(createDoc("NOTAM-L1", 1, "active", "DARL001", t0, t0.Add(time.Hour)))).Restriction.Id
	decodeRestriction(t, h.postRestriction(createDoc("NOTAM-L2", 1, "planned", "DARL002", t0.Add(2*time.Hour), t0.Add(3*time.Hour))))
	list := func(q string) []gen.RestrictionHead {
		rec := h.read(http.MethodGet, "/v1/restrictions/heads"+q)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", q, rec.Code, rec.Body.String())
		}
		var l gen.RestrictionList
		if err := json.Unmarshal(rec.Body.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		return l.Restrictions
	}
	if got := list(""); len(got) != 2 || got[0].AnspRef != "NOTAM-L2" {
		t.Errorf("all: %+v", got)
	}
	if got := list("?state=active"); len(got) != 1 || got[0].Id != a || len(got[0].Events) != 1 {
		t.Errorf("active: %+v", got)
	}
	if got := list("?airspace=TSU999"); len(got) != 0 {
		t.Errorf("another airspace: %+v", got)
	}
	in := url.QueryEscape(t0.Add(150 * time.Minute).Format(time.RFC3339))
	if got := list("?at=" + in); len(got) != 1 || got[0].AnspRef != "NOTAM-L2" {
		t.Errorf("at inside L2: %+v", got)
	}
	if got := list("?at=" + url.QueryEscape(t0.Add(-time.Minute).Format(time.RFC3339))); len(got) != 0 {
		t.Errorf("at before both: %+v", got)
	}
	if got := list("?limit=1"); len(got) != 1 {
		t.Errorf("limit 1: %d", len(got))
	}
	for _, q := range []string{"?at=2026-10-02T12:00:00", "?limit=0", "?limit=501"} {
		if rec := h.readRaw(http.MethodGet, "/v1/restrictions/heads"+q); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d", q, rec.Code)
		}
	}
	if rec := h.read(http.MethodGet, "/v1/restrictions/"+a); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"feature_id":"DARL001"`) {
		t.Errorf("GET one = %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.read(http.MethodGet, "/v1/restrictions/01NOSUCH"); rec.Code != http.StatusNotFound {
		t.Errorf("GET unknown = %d", rec.Code)
	}
	// The dataset-first routes win the literal segment, as in the server.
	if rec := h.read(http.MethodGet, "/v1/restrictions/versions"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"dataset":"restrictions"`) {
		t.Errorf("versions = %d %s", rec.Code, rec.Body.String())
	}
}

// at= on the dataset read keeps a restriction inside its window and
// drops it outside (ed318.Applies on the published period).
func TestRestrictionDatasetAt(t *testing.T) {
	h, t0 := restrictionHarness(t)
	h.postRestriction(createDoc("NOTAM-AT", 1, "planned", "DARAT01", t0.Add(time.Hour), t0.Add(2*time.Hour)))
	at := func(t1 time.Time) []string {
		_, m := collection(t, h.read(http.MethodGet, "/v1/restrictions?at="+url.QueryEscape(t1.Format(time.RFC3339))))
		return ids(m)
	}
	if got := at(t0.Add(90 * time.Minute)); strings.Join(got, ",") != "DARAT01" {
		t.Errorf("inside: %v", got)
	}
	if got := at(t0.Add(3 * time.Hour)); len(got) != 0 {
		t.Errorf("outside: %v", got)
	}
}

// Without a database the operations are 503; without a signing key the
// writes are 503; a store that is down is 503 database_unavailable.
func TestRestrictionsUnavailable(t *testing.T) {
	ctx := context.Background()
	s := &Server{}
	if r, _ := s.CreateRestriction(ctx, gen.CreateRestrictionRequestObject{}); r.(problemResponse).status != 503 {
		t.Error("create")
	}
	if r, _ := s.PatchRestriction(ctx, gen.PatchRestrictionRequestObject{}); r.(problemResponse).status != 503 {
		t.Error("patch")
	}
	if r, _ := s.GetRestriction(ctx, gen.GetRestrictionRequestObject{}); r.(problemResponse).status != 503 {
		t.Error("get")
	}
	if r, _ := s.ListRestrictions(ctx, gen.ListRestrictionsRequestObject{}); r.(problemResponse).status != 503 {
		t.Error("list")
	}
	// A handler reached without its middleware is a wiring fault.
	if _, err := (&Restrictions{}).create(ctx, nil); err == nil {
		t.Error("create without middleware")
	}

	h, t0 := restrictionHarness(t)
	h.rs.Signer = nil
	if rec := h.postRestriction(createDoc("NOTAM-U", 1, "active", "DARU001", t0, t0.Add(time.Hour))); rec.Code != 503 || !strings.HasSuffix(decodeProblem(t, rec).Type, "/"+SlugSigningUnavailable) {
		t.Errorf("no signer = %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.patchRestriction("x", doc{"op": "end", "ansp_version": 1}); rec.Code != 503 {
		t.Errorf("no signer patch = %d", rec.Code)
	}
	h.rs.Signer = KeyRingSigner{Keys: h.ring}
	h.fake.down = true
	if rec := h.postRestriction(createDoc("NOTAM-U", 1, "active", "DARU001", t0, t0.Add(time.Hour))); rec.Code != 503 || rec.Header().Get("Retry-After") == "" {
		t.Errorf("down = %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.read(http.MethodGet, "/v1/restrictions/heads"); rec.Code != 503 {
		t.Errorf("heads down = %d", rec.Code)
	}
	if rec := h.read(http.MethodGet, "/v1/restrictions/01X"); rec.Code != 503 {
		t.Errorf("get down = %d", rec.Code)
	}
	h.fake.down = false
	// A store fault that is not a connectivity failure is 500, logged.
	h.fake.rs().applyErr = errors.New("disk full")
	if rec := h.postRestriction(createDoc("NOTAM-U", 1, "active", "DARU001", t0, t0.Add(time.Hour))); rec.Code != 500 {
		t.Errorf("fault = %d %s", rec.Code, rec.Body.String())
	}
	h.fake.rs().applyErr = nil
	if rec := h.postRestriction(createDoc("NOTAM-U", 1, "active", "DARU001", t0, t0.Add(time.Hour))); rec.Code != 201 {
		t.Errorf("after the fault = %d %s", rec.Code, rec.Body.String())
	}
}

// diffRefs and the stale rule at their edges.
func TestRestrictionHelpers(t *testing.T) {
	u, m := diffRefs([]string{"b", "a", "a"}, []string{"c", "b"})
	if strings.Join(u, ",") != "a" || strings.Join(m, ",") != "c" {
		t.Errorf("diff %v %v", u, m)
	}
	refs := make([]string, MaxListedRefs+5)
	if len(capRefs(refs)) != MaxListedRefs {
		t.Error("capRefs")
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	last := now.Add(-60 * time.Second)
	if stale, _, _ := staleOf(store.PublisherRefs{LastHeartbeatAt: &last, StaleAfterS: 60}, now); stale {
		t.Error("exactly 60 s: stale")
	}
	last = now.Add(-61 * time.Second)
	if stale, since, _ := staleOf(store.PublisherRefs{LastHeartbeatAt: &last}, now); !stale || !since.Equal(now.Add(-time.Second)) {
		t.Errorf("61 s with the default: %v %v", stale, since)
	}
	if got := string(withTopMember([]byte(`{}`), json.RawMessage(`null`))); got != `{"cis_publisher_stale_since":null}` {
		t.Errorf("empty object: %s", got)
	}
	if got := string(withTopMember([]byte(`[]`), json.RawMessage(`null`))); got != `[]` {
		t.Errorf("not an object: %s", got)
	}
	_ = authtest.Key
}

// The member the CISP stamps validates against CisRestriction while the
// restriction is current (ended_by null) and once ended (ended_by set);
// a member with an unknown state does not (E-01).
func TestCisRestrictionMember(t *testing.T) {
	s := components(t)["CisRestriction"].Value
	at := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	h := restriction.Head{ID: "01J0000000000000000000000A", AnspRef: "R", AnspVersion: 3, UspaceAirspaceID: "TSU001",
		FeatureID: "DAR0A1B", State: restriction.StateActive, StartsAt: at, EndsAt: at.Add(time.Hour)}
	check := func(m any, ok bool) {
		t.Helper()
		raw, _ := json.Marshal(m)
		var v any
		_ = json.Unmarshal(raw, &v)
		if err := s.VisitJSON(v); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
	check(restriction.MemberOf(h), true)
	by := restriction.EndedByExpiry
	h.State, h.EndedBy = restriction.StateEnded, &by
	check(restriction.MemberOf(h), true)
	h.State = "gone"
	check(restriction.MemberOf(h), false)
}
