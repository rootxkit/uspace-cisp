package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

func (h *pubHarness) heartbeat(token, body string, edit ...func(*http.Request)) (*http.Request, *httptest.ResponseRecorder) {
	h.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/publishers/heartbeat", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, e := range edit {
		e(req)
	}
	rec := h.do(req)
	return req, rec
}

// The heartbeat: {sent_at} alone and with active_refs are 204 and read
// back; 1001 refs are 400 (E-10), 1000 are 204; a client that is not a
// publisher is 403; the ANSP is bound to its certificate subject.
func TestHeartbeat(t *testing.T) {
	h := newPubHarness(t, nil)
	sent := time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)
	authority := h.token(authorityID, auth.ScopePublishZones)

	req, rec := h.heartbeat(authority, `{"sent_at":"2026-10-02T10:00:00Z"}`)
	conform(t, withBody(req, `{"sent_at":"2026-10-02T10:00:00Z"}`), rec)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("authority = %d %s", rec.Code, rec.Body.String())
	}
	b := h.fake.beats[authorityID]
	if b.Kind != "authority" || !b.SentAt.Equal(sent) || b.ActiveRefs != nil || b.ReceivedAt.IsZero() {
		t.Errorf("read back %+v", b)
	}

	anspTok := h.token(anspID, auth.ScopePublishRestrictions)
	withSubject := func(r *http.Request) { r.Header.Set(auth.HeaderClientCertSubject, anspSubject) }
	body := `{"sent_at":"2026-10-02T10:00:15Z","active_refs":["ansp-ref-1","ansp-ref-2"]}`
	req, rec = h.heartbeat(anspTok, body, withSubject)
	conform(t, withBody(req, body), rec)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("ansp = %d %s", rec.Code, rec.Body.String())
	}
	if b := h.fake.beats[anspID]; b.Kind != "ansp" || !reflect.DeepEqual(b.ActiveRefs, []string{"ansp-ref-1", "ansp-ref-2"}) {
		t.Errorf("ansp read back %+v", b)
	}
	if h.counter("publishers", CounterHeartbeats) != 2 {
		t.Errorf("heartbeats counted %d", h.counter("publishers", CounterHeartbeats))
	}

	// The ANSP without its certificate subject (mode required).
	_, rec = h.heartbeat(anspTok, body)
	if p := decodeProblem(t, rec); rec.Code != http.StatusForbidden || p.Type != ProblemTypeBase+auth.SlugMTLSRequired {
		t.Errorf("ansp without mTLS = %d %s", rec.Code, rec.Body.String())
	}

	// E-10: 1001 refs refused, 1000 accepted.
	refs := func(n int) string {
		list := make([]string, n)
		for i := range list {
			list[i] = "r" + strconv.Itoa(i)
		}
		raw, _ := json.Marshal(map[string]any{"sent_at": "2026-10-02T10:00:30Z", "active_refs": list})
		return string(raw)
	}
	req, rec = h.heartbeat(anspTok, refs(MaxActiveRefs+1), withSubject)
	conformResponse(t, req, rec)
	if p := decodeProblem(t, rec); rec.Code != http.StatusBadRequest || !hasProblem(p, "active_refs", "1001 entries; at most 1000") {
		t.Fatalf("1001 refs = %d %s", rec.Code, rec.Body.String())
	}
	if len(h.fake.beats[anspID].ActiveRefs) != 2 {
		t.Error("a refused heartbeat was stored")
	}
	if _, rec = h.heartbeat(anspTok, refs(MaxActiveRefs), withSubject); rec.Code != http.StatusNoContent || len(h.fake.beats[anspID].ActiveRefs) != MaxActiveRefs {
		t.Fatalf("1000 refs = %d", rec.Code)
	}
	if _, rec = h.heartbeat(anspTok, `{"sent_at":"2026-10-02T10:00:45Z","active_refs":[]}`, withSubject); rec.Code != http.StatusNoContent ||
		h.fake.beats[anspID].ActiveRefs == nil || len(h.fake.beats[anspID].ActiveRefs) != 0 {
		t.Errorf("an empty list = %d %v", rec.Code, h.fake.beats[anspID].ActiveRefs)
	}

	// Not a publisher, though it holds a publish scope: 403, counted.
	_, rec = h.heartbeat(h.token(usspID, auth.ScopePublishZones), `{"sent_at":"2026-10-02T10:00:00Z"}`)
	if p := decodeProblem(t, rec); rec.Code != http.StatusForbidden || p.Type != ProblemTypeBase+auth.SlugNotAPublisher || h.counter("publishers", CounterHeartbeatNotPublisher) != 1 {
		t.Errorf("not a publisher = %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := h.fake.beats[usspID]; ok {
		t.Error("a non-publisher's heartbeat was stored")
	}
	// No publish scope at all: 403; no token: 401.
	if _, rec = h.heartbeat(h.token(authorityID, auth.ScopeRead), `{"sent_at":"2026-10-02T10:00:00Z"}`); rec.Code != http.StatusForbidden {
		t.Errorf("cis.read only = %d", rec.Code)
	}
	if _, rec = h.heartbeat("", `{"sent_at":"2026-10-02T10:00:00Z"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d", rec.Code)
	}
	// sent_at is required.
	_, rec = h.heartbeat(authority, `{}`)
	if p := decodeProblem(t, rec); rec.Code != http.StatusBadRequest || !hasProblem(p, "sent_at", "is required") {
		t.Errorf("no sent_at = %d %s", rec.Code, rec.Body.String())
	}
	// The database gone: 503.
	h.fake.down = true
	if _, rec = h.heartbeat(authority, `{"sent_at":"2026-10-02T10:00:00Z"}`); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("database down = %d", rec.Code)
	}
}

// The handler's own binding, behind a misconfigured route: a caller that
// is neither publisher is refused there too.
func TestHeartbeatHandlerBindsThePublisher(t *testing.T) {
	p := &Publications{Store: newFakeStore(), AuthorityClientID: authorityID, ANSPClientID: anspID}
	ctx := auth.WithCaller(t.Context(), &auth.Caller{ClientID: usspID})
	resp, err := p.heartbeat(ctx, gen.PostPublisherHeartbeatRequestObject{Body: &gen.PublisherHeartbeat{SentAt: time.Now()}})
	if pr, ok := resp.(problemResponse); err != nil || !ok || pr.status != http.StatusForbidden {
		t.Errorf("got %+v %v", resp, err)
	}
	if _, err := p.heartbeat(t.Context(), gen.PostPublisherHeartbeatRequestObject{}); err == nil {
		t.Error("no caller: no error")
	}
}

func withBody(req *http.Request, body string) *http.Request {
	clone := req.Clone(req.Context())
	clone.Body = http.NoBody
	if body != "" {
		clone.Body = io.NopCloser(bytes.NewReader([]byte(body)))
	}
	return clone
}

// The history: cis.read or the publisher reads it; another client
// without cis.read is 403; limit and before page it; an unknown dataset
// is 404.
func TestListPublications(t *testing.T) {
	h := newPubHarness(t, nil)
	d := zonesDoc(t)
	for i := range 3 {
		fprops(d, 1)["restrictionConditions"] = "version " + strconv.Itoa(i)
		if rec := h.put("zones", jsonBytes(t, d)); rec.Code != http.StatusCreated {
			t.Fatalf("PUT %d = %d", i, rec.Code)
		}
	}
	var list gen.PublicationVersionList
	rec := h.get("/v1/publications/zones?limit=2", h.token(usspID, auth.ScopeRead))
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
	if len(list.Versions) != 2 || list.Versions[0].Version != 3 || list.NextBefore == nil || *list.NextBefore != 2 {
		t.Fatalf("page 1 %+v", list)
	}
	v := list.Versions[0]
	if v.Etag != `"zones:3"` || v.Publisher != authorityID || v.Changed != 1 || v.Reason != gen.PublicationVersionReasonPublication || len(v.BodySha256) != 64 || v.SignatureKid == nil {
		t.Errorf("version %+v", v)
	}
	rec = h.get("/v1/publications/zones?limit=2&before=2", h.token(usspID, auth.ScopeRead))
	list = gen.PublicationVersionList{}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Versions) != 1 || list.Versions[0].Version != 1 || list.NextBefore != nil {
		t.Errorf("page 2 %+v", list)
	}
	// The publisher without cis.read reads its own history.
	if rec := h.get("/v1/publications/zones", h.token(authorityID, auth.ScopePublishZones)); rec.Code != 200 {
		t.Errorf("publisher = %d", rec.Code)
	}
	// Another client without cis.read: 403; no token: 401.
	if rec := h.get("/v1/publications/zones", h.token(usspID, auth.ScopePublishZones)); rec.Code != http.StatusForbidden {
		t.Errorf("no cis.read = %d", rec.Code)
	}
	if rec := h.get("/v1/publications/zones", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token = %d", rec.Code)
	}
	// restrictions has a history too (its publisher is the ANSP).
	if rec := h.get("/v1/publications/restrictions", h.token(anspID, auth.ScopePublishRestrictions)); rec.Code != 200 {
		t.Errorf("restrictions by the ANSP = %d", rec.Code)
	}
	// Bad paging and an unknown dataset.
	for _, q := range []string{"?limit=0", "?limit=501", "?before=0"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/publications/zones"+q, http.NoBody)
		req.Header.Set("Authorization", "Bearer "+h.token(usspID, auth.ScopeRead))
		rec := h.do(req)
		if p := decodeProblem(t, rec); rec.Code != 400 || len(p.Errors) == 0 {
			t.Errorf("%s = %d %s", q, rec.Code, rec.Body.String())
		}
		conformResponse(t, req, rec)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/publications/zonez", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+h.token(usspID, auth.ScopeRead))
	if rec := h.do(req); rec.Code != 404 {
		t.Errorf("unknown dataset = %d", rec.Code)
	}
	// Empty history: 200 with no versions (E-02).
	if rec := h.get("/v1/publications/ussp_list", h.token(usspID, auth.ScopeRead)); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"versions":[]`) {
		t.Errorf("empty = %d %s", rec.Code, rec.Body.String())
	}
}

// The attempts: the publisher reads its refusals with their problems,
// since an instant; another client is 403; accepted ones are not listed.
func TestListPublicationAttempts(t *testing.T) {
	h := newPubHarness(t, nil)
	d := zonesDoc(t)
	fprops(d, 0)["type"] = "USPACE"
	if rec := h.put("zones", jsonBytes(t, d)); rec.Code != 400 {
		t.Fatalf("refusal = %d", rec.Code)
	}
	if rec := h.put("zones", jsonBytes(t, zonesDoc(t))); rec.Code != 201 {
		t.Fatalf("accepted = %d", rec.Code)
	}
	authority := h.token(authorityID, auth.ScopePublishZones)
	rec := h.get("/v1/publications/zones/attempts", authority)
	var list gen.PublicationAttemptList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 || len(list.Attempts) != 1 {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
	a := list.Attempts[0]
	if a.Outcome != gen.Refused || a.Problems[0].Field != "features[0].properties.type" || a.BodySha256 == nil || a.Bytes == 0 || a.Truncated != nil {
		t.Errorf("attempt %+v", a)
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if rec := h.get("/v1/publications/zones/attempts?since="+future, authority); !strings.Contains(rec.Body.String(), `"attempts":[]`) {
		t.Errorf("since the future: %s", rec.Body.String())
	}
	// The publisher's sub without the dataset's publish scope: 403
	// (scope and sub are both required), beside the token with it above.
	rec = h.get("/v1/publications/zones/attempts", h.token(authorityID, auth.ScopeRead, auth.ScopePublishUSpace))
	if p := decodeProblem(t, rec); rec.Code != http.StatusForbidden || p.Type != ProblemTypeBase+auth.SlugForbidden || !hasProblem(p, "scope", auth.ScopePublishZones) {
		t.Errorf("authority without the zones scope = %d %s", rec.Code, rec.Body.String())
	}
	// The scope from another client: 403 not_a_publisher.
	rec = h.get("/v1/publications/zones/attempts", h.token(usspID, auth.ScopePublishZones))
	if p := decodeProblem(t, rec); rec.Code != http.StatusForbidden || p.Type != ProblemTypeBase+auth.SlugNotAPublisher {
		t.Errorf("the scope without the sub = %d %s", rec.Code, rec.Body.String())
	}
	// The ANSP reads restrictions' attempts with its own scope.
	if rec := h.get("/v1/publications/restrictions/attempts", h.token(anspID, auth.ScopePublishRestrictions)); rec.Code != http.StatusOK {
		t.Errorf("ansp on restrictions = %d %s", rec.Code, rec.Body.String())
	}
	// Another client, even with cis.read: 403. The ANSP on zones: 403.
	for _, tok := range []string{h.token(usspID, auth.ScopeRead), h.token(anspID, auth.ScopePublishRestrictions, auth.ScopeRead)} {
		if rec := h.get("/v1/publications/zones/attempts", tok); rec.Code != http.StatusForbidden {
			t.Errorf("another client = %d", rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/publications/zones/attempts?limit=900", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+authority)
	if rec := h.do(req); rec.Code != 400 {
		t.Errorf("limit 900 = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/publications/nothing/attempts", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+authority)
	if rec := h.do(req); rec.Code != 404 {
		t.Errorf("unknown dataset = %d", rec.Code)
	}
	// A truncated refusal reads back with its count.
	h.fake.attempts = append(h.fake.attempts, store.Attempt{Dataset: "zones", PublisherClientID: authorityID, Outcome: store.OutcomeRefused,
		ReceivedAt: time.Now(), Problems: []store.AttemptProblem{{Field: "$", Reason: "x"}}, Truncated: 7})
	list = gen.PublicationAttemptList{}
	_ = json.Unmarshal(h.get("/v1/publications/zones/attempts", authority).Body.Bytes(), &list)
	if list.Attempts[0].Truncated == nil || *list.Attempts[0].Truncated != 7 {
		t.Errorf("truncated read back %+v", list.Attempts[0])
	}
	if _, err := h.pubs.attempts(t.Context(), gen.ListPublicationAttemptsRequestObject{Dataset: "zones"}); err == nil {
		t.Error("no caller: no error")
	}
}
