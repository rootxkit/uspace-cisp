package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/jws"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// GET /v1/{dataset}/versions: the history, paged, the same body as the
// publications history.
func TestReadVersionList(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	if rec := h.put("zones", []byte(emptyCollection)); rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	rec := h.read(http.MethodGet, "/v1/zones/versions?limit=1")
	var list gen.PublicationVersionList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || rec.Code != 200 {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
	if len(list.Versions) != 1 || list.Versions[0].Version != 2 || list.NextBefore == nil || *list.NextBefore != 2 || list.Versions[0].Etag != `"zones:2"` {
		t.Errorf("page 1 %+v", list)
	}
	rec = h.read(http.MethodGet, "/v1/zones/versions?before=2")
	list = gen.PublicationVersionList{}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Versions) != 1 || list.Versions[0].Version != 1 || list.NextBefore != nil {
		t.Errorf("page 2 %+v", list)
	}
	for _, q := range []string{"limit=0", "limit=501", "before=0"} {
		req := h.readRaw(http.MethodGet, "/v1/zones/versions?"+q)
		if p := decodeProblem(t, req); req.Code != 400 || p.Type != ProblemTypeBase+SlugBadRequest {
			t.Errorf("%s = %d", q, req.Code)
		}
	}
	if rec := h.read(http.MethodGet, "/v1/restrictions/versions"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"versions":[]`) {
		t.Errorf("no versions = %d %s", rec.Code, rec.Body.String())
	}
}

// GET /v1/{dataset}/versions/{v}: the verbatim bytes with the content
// type received, the publisher's signature and kid, and the CISP's
// signature (made once and kept); 304, 404 beside 200.
func TestReadVersionBody(t *testing.T) {
	h := newPubHarness(t, nil)
	body := jsonBytes(t, readZones(t))
	req := h.putReq("zones", body, `"zones:0"`)
	req.Header.Set("Content-Type", "application/json")
	pubSig := req.Header.Get(jws.HeaderSignature)
	if rec := h.do(req); rec.Code != 201 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	rec := h.read(http.MethodGet, "/v1/zones/versions/1")
	hd := rec.Header()
	if rec.Code != 200 || !bytes.Equal(rec.Body.Bytes(), body) || hd.Get("Content-Type") != "application/json" {
		t.Fatalf("GET = %d %q equal %v", rec.Code, hd.Get("Content-Type"), bytes.Equal(rec.Body.Bytes(), body))
	}
	if hd.Get(HeaderPublisherSig) != pubSig || hd.Get(HeaderPublisherKID) != publisherKID || hd.Get("ETag") != `"zones:1"` || hd.Get("Last-Modified") == "" {
		t.Errorf("headers %v", hd)
	}
	verifyCISP(t, hd.Get(HeaderSignature), body)
	signed := h.fake.signed
	again := h.read(http.MethodGet, "/v1/zones/versions/1")
	if again.Header().Get(HeaderSignature) != hd.Get(HeaderSignature) || h.fake.signed != signed {
		t.Error("the version was signed again instead of served from the kept signature")
	}
	if nm := h.read(http.MethodGet, "/v1/zones/versions/1", "If-None-Match", `"zones:1"`); nm.Code != 304 {
		t.Errorf("If-None-Match = %d", nm.Code)
	}
	missing := h.read(http.MethodGet, "/v1/zones/versions/9")
	if p := decodeProblem(t, missing); missing.Code != 404 || !hasProblem(p, "version", "no version 9") {
		t.Errorf("missing = %d %s", missing.Code, missing.Body.String())
	}
	if zero := h.readRaw(http.MethodGet, "/v1/zones/versions/0"); zero.Code != 400 {
		t.Errorf("version 0 = %d", zero.Code)
	}
	// A CISP-made version (no publisher signature) still carries the
	// CISP's.
	h.fake.mu.Lock()
	p := h.fake.heads[publication.DatasetZones][1]
	p.PublisherSignature, p.SignatureKID = nil, nil
	h.fake.heads[publication.DatasetZones][1] = p
	h.fake.mu.Unlock()
	own := h.read(http.MethodGet, "/v1/zones/versions/1")
	if own.Header().Get(HeaderPublisherSig) != "" || own.Header().Get(HeaderSignature) == "" {
		t.Errorf("CISP-made version headers %v", own.Header())
	}
	// No signing key: never served unsigned.
	h.reads.Signer = nil
	unsigned := h.read(http.MethodGet, "/v1/zones/versions/1")
	if p := decodeProblem(t, unsigned); unsigned.Code != 503 || p.Type != ProblemTypeBase+SlugSigningUnavailable {
		t.Errorf("no signer = %d %s", unsigned.Code, unsigned.Body.String())
	}
}

// T7: a stored body that no longer matches its hash is 500 integrity and
// an error log line, never the bytes; the snapshot read is unaffected.
func TestReadVersionIntegrity(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	h.fake.mu.Lock()
	p := h.fake.heads[publication.DatasetZones][1]
	p.Body = append([]byte{}, p.Body...)
	p.Body[10] ^= 0x20
	h.fake.heads[publication.DatasetZones][1] = p
	h.fake.mu.Unlock()
	rec := h.read(http.MethodGet, "/v1/zones/versions/1")
	if p := decodeProblem(t, rec); rec.Code != 500 || p.Type != ProblemTypeBase+SlugIntegrity {
		t.Fatalf("corrupt = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(h.logs.String(), "publication body integrity check failed") || !strings.Contains(h.logs.String(), `"version":1`) {
		t.Errorf("no error line: %s", h.logs.String())
	}
	if h.counter(readsComponent, CounterIntegrityFailed) != 1 {
		t.Error("integrity_failed not counted")
	}
	if snap := h.read(http.MethodGet, "/v1/zones"); snap.Code != 200 {
		t.Errorf("snapshot after corruption = %d", snap.Code)
	}
}

// E-10: the per-version signatures are bounded; past the bound the
// least recently served goes and is counted.
func TestSignatureCacheBound(t *testing.T) {
	h := newPubHarness(t, nil)
	h.reads.SignatureCacheEntries = 2
	h.publishReadZones()
	for range 2 {
		if rec := h.put("zones", []byte(emptyCollection)); rec.Code != 201 {
			if rec = h.put("zones", jsonBytes(t, readZones(t))); rec.Code != 201 {
				t.Fatal(rec.Code)
			}
		}
	}
	for _, v := range []string{"1", "2", "3", "1"} {
		if rec := h.read(http.MethodGet, "/v1/zones/versions/"+v); rec.Code != 200 {
			t.Fatalf("version %s = %d", v, rec.Code)
		}
	}
	if n := h.reads.sigs.len(); n != 2 {
		t.Errorf("holds %d signatures, bound 2", n)
	}
	if got := h.counter(readsComponent, CounterSignatureEvicted); got != 2 {
		t.Errorf("evicted %d, want 2 (1 for 3, then 2 for 1 again)", got)
	}
	// Within the bound nothing goes.
	c := newSignatureCache(3, obs.NewStatus("t", nil, time.Now()).Component("c").Counter("e", ""))
	c.put("a", "1")
	c.put("a", "2")
	if sig, ok := c.get("a"); !ok || sig != "2" || c.len() != 1 {
		t.Errorf("replace: %q %v %d", sig, ok, c.len())
	}
	if _, ok := c.get("b"); ok {
		t.Error("an absent key was found")
	}
}

// GET /v1/changes: cursor order, the dataset filter, limit and next,
// the cis/change/v1 body with pull_url and bbox; bad parameters 400.
func TestReadChanges(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	if rec := h.put("ussp_list", usspListBody(t)); rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	if rec := h.put("zones", []byte(emptyCollection)); rec.Code != 201 {
		t.Fatal(rec.Code)
	}
	type change struct {
		Schema     string    `json:"schema"`
		MsgID      string    `json:"msg_id"`
		Producer   string    `json:"producer"`
		Dataset    string    `json:"dataset"`
		ETag       string    `json:"etag"`
		Reason     string    `json:"reason"`
		PullURL    string    `json:"pull_url"`
		Version    int64     `json:"version"`
		FeatureIDs []string  `json:"feature_ids"`
		RemovedIDs []string  `json:"removed_ids"`
		BBox       []float64 `json:"bbox"`
	}
	type list struct {
		Changes []change `json:"changes"`
		Next    int64    `json:"next"`
	}
	get := func(q string) list {
		rec := h.read(http.MethodGet, "/v1/changes"+q)
		if rec.Code != 200 {
			t.Fatalf("%s = %d %s", q, rec.Code, rec.Body.String())
		}
		var out list
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	all := get("")
	if len(all.Changes) != 3 || all.Next != 3 {
		t.Fatalf("all %+v", all)
	}
	first := all.Changes[0]
	if first.Schema != "cis/change/v1" || first.MsgID != "1" || first.Producer != "uspace-cisp" || first.Dataset != "zones" ||
		first.ETag != `"zones:1"` || first.Reason != "publication" || first.PullURL != "https://uspace-cisp.example.test/v1/zones?since_version=0" ||
		strings.Join(first.FeatureIDs, ",") != "TSC001,TSP001,TSR001" || len(first.BBox) != 4 {
		t.Errorf("first change %+v", first)
	}
	if last := all.Changes[2]; strings.Join(last.RemovedIDs, ",") != "TSC001,TSP001,TSR001" || last.Version != 2 {
		t.Errorf("removal %+v", last)
	}
	if zones := get("?dataset=zones"); len(zones.Changes) != 2 || zones.Next != 3 {
		t.Errorf("zones %+v", zones)
	}
	if page := get("?since=1&limit=1"); len(page.Changes) != 1 || page.Changes[0].MsgID != "2" || page.Next != 2 {
		t.Errorf("page %+v", page)
	}
	if none := get("?since=3"); len(none.Changes) != 0 || none.Next != 3 {
		t.Errorf("past the end %+v", none)
	}
	for _, q := range []string{"?limit=0", "?limit=501", "?since=-1"} {
		rec := h.readRaw(http.MethodGet, "/v1/changes"+q)
		if rec.Code != 400 {
			t.Errorf("%s = %d", q, rec.Code)
		}
	}
	rec := h.readRaw(http.MethodGet, "/v1/changes?dataset=nosuch")
	if p := decodeProblem(t, rec); rec.Code != 400 || !hasProblem(p, "dataset", "not a dataset") {
		t.Errorf("unknown dataset = %d %s", rec.Code, rec.Body.String())
	}
}

// GET /v1/status: the datasets from the cache, the publishers (heard
// recently: not stale; silent past stale_after_s: stale since; configured
// and never heard: stale), the degraded components and the mTLS mode.
// With the store down the publishers are not guessed.
func TestReadStatus(t *testing.T) {
	h := newPubHarness(t, nil)
	h.publishReadZones()
	now := time.Now().UTC()
	old := now.Add(-5 * time.Minute)
	h.fake.mu.Lock()
	h.fake.beats[authorityID] = store.Heartbeat{ClientID: authorityID, Kind: "authority", ReceivedAt: now.Add(-10 * time.Second)}
	h.fake.publishers = []store.Publisher{{ClientID: "ansp-legacy", Kind: "ansp", LastHeartbeatAt: &old, LastPublicationAt: &old, StaleAfterS: 120, Enabled: true}}
	h.fake.mu.Unlock()
	h.status.Component("nats").SetDegraded("disconnected")
	h.status.Component("signing").SetDegraded("not configured") // not a status component

	rec := h.read(http.MethodGet, "/v1/status")
	var st struct {
		Datasets []struct {
			Dataset        string     `json:"dataset"`
			CurrentVersion int64      `json:"current_version"`
			ETag           string     `json:"etag"`
			UpdatedAt      *time.Time `json:"updated_at"`
		} `json:"datasets"`
		Publishers []struct {
			ClientID   string     `json:"client_id"`
			Kind       string     `json:"kind"`
			Stale      bool       `json:"stale"`
			StaleSince *time.Time `json:"stale_since"`
			Last       *time.Time `json:"last_heartbeat_at"`
		} `json:"publishers"`
		Degraded []struct {
			Component string `json:"component"`
		} `json:"degraded"`
		MTLSMode string `json:"mtls_mode"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != 200 {
		t.Fatalf("= %d %s", rec.Code, rec.Body.String())
	}
	if len(st.Datasets) != 4 || st.Datasets[0].Dataset != "zones" || st.Datasets[0].CurrentVersion != 1 || st.Datasets[0].ETag != `"zones:1"` || st.Datasets[0].UpdatedAt == nil {
		t.Errorf("datasets %+v", st.Datasets)
	}
	pubs := map[string]int{}
	for i, p := range st.Publishers {
		pubs[p.ClientID] = i
	}
	if len(st.Publishers) != 3 {
		t.Fatalf("publishers %+v", st.Publishers)
	}
	if a := st.Publishers[pubs[authorityID]]; a.Stale || a.Last == nil || a.StaleSince != nil {
		t.Errorf("authority heard 10 s ago %+v", a)
	}
	if l := st.Publishers[pubs["ansp-legacy"]]; !l.Stale || l.StaleSince == nil || l.StaleSince.Sub(old.Add(120*time.Second)).Abs() > time.Millisecond {
		t.Errorf("silent publisher %+v", l)
	}
	if n := st.Publishers[pubs[anspID]]; !n.Stale || n.Last != nil || n.StaleSince != nil {
		t.Errorf("never heard %+v", n)
	}
	if len(st.Degraded) != 1 || st.Degraded[0].Component != "nats" || st.MTLSMode != "required" {
		t.Errorf("degraded %+v mode %q", st.Degraded, st.MTLSMode)
	}

	h.fake.mu.Lock()
	h.fake.down = true
	h.fake.mu.Unlock()
	_ = h.cache.Refresh(t.Context())
	down := h.read(http.MethodGet, "/v1/status")
	st.Publishers, st.Degraded = nil, nil
	if err := json.Unmarshal(down.Body.Bytes(), &st); err != nil || down.Code != 200 {
		t.Fatalf("down = %d %s", down.Code, down.Body.String())
	}
	names := []string{}
	for _, d := range st.Degraded {
		names = append(names, d.Component)
	}
	if len(st.Publishers) != 0 || strings.Join(names, ",") != "database,nats" || len(st.Datasets) != 4 {
		t.Errorf("down: publishers %+v degraded %v datasets %d", st.Publishers, names, len(st.Datasets))
	}
	t.Logf("status with the store down: %s", strings.TrimSpace(down.Body.String()))
}

func TestPublisherStatusRule(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { x := now.Add(-d); return &x }
	cases := []struct {
		name  string
		row   store.Publisher
		stale bool
	}{
		{"just heard", store.Publisher{LastHeartbeatAt: at(0), StaleAfterS: 60}, false},
		{"at the bound", store.Publisher{LastHeartbeatAt: at(60 * time.Second), StaleAfterS: 60}, false},
		{"past the bound", store.Publisher{LastHeartbeatAt: at(61 * time.Second), StaleAfterS: 60}, true},
		{"no bound in the row: 60 s", store.Publisher{LastHeartbeatAt: at(61 * time.Second)}, true},
		{"never heard", store.Publisher{StaleAfterS: 60}, true},
	}
	for _, c := range cases {
		p := publisherStatus(c.row, now)
		if p.Stale != c.stale || (p.Stale && c.row.LastHeartbeatAt != nil && (p.StaleSince == nil || !p.StaleSince.Equal(c.row.LastHeartbeatAt.Add(60*time.Second)))) {
			t.Errorf("%s: %+v", c.name, p)
		}
	}
}

// GET /v1/changes bounds what each record lists: a change of 5 000
// zones is a summary (empty lists, ids_truncated, the counts, pull_url)
// that the spec describes; the small change beside it is listed whole
// with no summary members (Q49, N2).
func TestReadChangesSummarisesALargeChange(t *testing.T) {
	h := newPubHarness(t, nil)
	ids := make([]string, 5000)
	for i := range ids {
		ids[i] = fmt.Sprintf("Z%05d", i)
	}
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	h.fake.mu.Lock()
	h.fake.changes = append(h.fake.changes,
		publication.Change{ID: 1, Dataset: publication.DatasetZones, Version: 1, FeatureIDs: ids, RemovedIDs: []string{}, Reason: publication.ReasonPublication, At: at},
		publication.Change{ID: 2, Dataset: publication.DatasetZones, Version: 2, FeatureIDs: []string{"Z00001"}, RemovedIDs: []string{"Z00001"}, Reason: publication.ReasonPublication, At: at})
	h.fake.mu.Unlock()
	rec := h.read(http.MethodGet, "/v1/changes")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Changes []map[string]any `json:"changes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Changes) != 2 {
		t.Fatalf("%d changes", len(out.Changes))
	}
	big, small := out.Changes[0], out.Changes[1]
	if big["ids_truncated"] != true || big["feature_count"] != float64(5000) || big["removed_count"] != float64(0) ||
		len(big["feature_ids"].([]any)) != 0 || len(big["removed_ids"].([]any)) != 0 ||
		big["pull_url"] != "https://uspace-cisp.example.test/v1/zones?since_version=0" {
		t.Errorf("large change %v", big)
	}
	if _, ok := small["ids_truncated"]; ok || len(small["feature_ids"].([]any)) != 1 || len(small["removed_ids"].([]any)) != 1 {
		t.Errorf("small change %v", small)
	}
	if n := rec.Body.Len(); n > 4096 {
		t.Errorf("the feed answered %d bytes for two changes", n)
	}
}
