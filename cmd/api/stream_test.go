package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/httpapi"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

type fakeCache struct {
	versions map[publication.Dataset]int64
	updated  map[publication.Dataset]time.Time
}

func (f fakeCache) Current(context.Context, publication.Dataset) (store.Snapshot, error) {
	return store.Snapshot{}, errors.New("unused")
}
func (f fakeCache) CurrentVersion(context.Context, publication.Dataset) (int64, error) { return 0, nil }
func (f fakeCache) Stale() (time.Time, bool)                                           { return time.Time{}, false }
func (f fakeCache) Refreshed() time.Time                                               { return time.Time{} }
func (f fakeCache) Versions() (map[publication.Dataset]int64, map[publication.Dataset]time.Time) {
	return f.versions, f.updated
}

var _ httpapi.SnapshotReader = fakeCache{}

// E-02 read field by field: the healthy parts (versions, ages, the
// newest change's age, fresh publishers, the bus connected, nothing
// degraded), then the degraded ones (the database and the bus with
// their since-times, a stale publisher), from memory only.
func TestStreamStatusParts(t *testing.T) {
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	st := obs.NewStatus("api", nil, now)
	hb := now.Add(-10 * time.Second)
	reads := 0
	busNow := bus.State{Kind: bus.StateConnected, Since: now.Add(-time.Hour)}
	src := &streamStatus{
		status: st, policy: "cfg-x", now: func() time.Time { return now },
		cache: fakeCache{
			versions: map[publication.Dataset]int64{publication.DatasetZones: 7, publication.DatasetRestrictions: 3},
			updated:  map[publication.Dataset]time.Time{publication.DatasetZones: now.Add(-100 * time.Second), publication.DatasetRestrictions: now.Add(-4 * time.Second)},
		},
		configured: []httpapi.ConfiguredPublisher{{ClientID: "authority-01", Kind: "authority"}, {ClientID: "ansp-01", Kind: "ansp"}},
		read: func(context.Context) ([]store.Publisher, error) {
			reads++
			return []store.Publisher{
				{ClientID: "authority-01", Kind: "authority", LastHeartbeatAt: &hb, StaleAfterS: 60},
				{ClientID: "ansp-01", Kind: "ansp", LastHeartbeatAt: &hb, StaleAfterS: 60},
			}, nil
		},
		busState: func() bus.State { return busNow },
	}
	src.refresh(context.Background())
	p := src.Parts(now)
	if len(p.Degraded) != 0 || p.NATS != bus.StateConnected || p.PolicyVersion != "cfg-x" || p.StaleAfterS != 60 {
		t.Errorf("healthy parts %+v", p)
	}
	if p.Datasets["zones"].Version != "7" || p.Datasets["zones"].AgeS != 100 || p.Datasets["restrictions"].AgeS != 4 || *p.CISAgeS != 4 {
		t.Errorf("datasets %+v cis_age_s %v", p.Datasets, *p.CISAgeS)
	}
	if len(p.Publishers) != 2 || p.Publishers[0].Stale || *p.Publishers[0].HeartbeatAgeS != 10 {
		t.Errorf("publishers %+v", p.Publishers)
	}
	src.probe(context.Background())
	if g := st.Component("publishers").Gauge("publisher_stale", "").Value(); g != 0 {
		t.Errorf("publisher_stale = %v", g)
	}

	lost := now.Add(-30 * time.Second)
	busNow = bus.State{Kind: bus.StateReconnecting, Since: lost}
	st.Component("database").SetDegraded("unreachable")
	later := now.Add(2 * time.Minute)
	p = src.Parts(later)
	if strings.Join(p.Degraded, ",") != "database,nats,publisher_stale" || !p.DegradedSince["nats"].Equal(lost) ||
		p.NATS != bus.StateReconnecting || !p.NATSSince.Equal(lost) {
		t.Errorf("degraded parts %+v", p)
	}
	if !p.DegradedSince["publisher_stale"].Equal(hb.Add(time.Minute)) {
		t.Errorf("publisher stale since %s", p.DegradedSince["publisher_stale"])
	}
	now = later
	src.probe(context.Background())
	if g := st.Component("publishers").Gauge("publisher_stale", "").Value(); g != 2 {
		t.Errorf("publisher_stale = %v", g)
	}

	// No database, no bus: the parts say so and never read anything.
	bare := &streamStatus{status: obs.NewStatus("api", nil, now), now: time.Now,
		configured: []httpapi.ConfiguredPublisher{{ClientID: "ansp-01", Kind: "ansp"}}}
	bare.refresh(context.Background())
	p = bare.Parts(now)
	if p.NATS != natsNotConfigured || p.Datasets != nil || len(p.Publishers) != 1 || !p.Publishers[0].Stale || p.Publishers[0].HeartbeatAgeS != nil {
		t.Errorf("bare parts %+v", p)
	}
	bare.probe(context.Background())
}

func TestPolicyVersionFollowsTheConfiguration(t *testing.T) {
	env := []string{"CISP_TOKEN_ISSUER=https://a.example/", "CISP_TOKEN_JWKS_URL=https://a.example/jwks", "CISP_AUDIENCES=cisp", "CISP_ANSP_MTLS_SUBJECT=CN=a"}
	a, err := config.LoadAPI(env)
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.LoadAPI(append(env, "CISP_STREAM_MAX_CLIENTS=10"))
	if err != nil {
		t.Fatal(err)
	}
	va, vb := policyVersion(a), policyVersion(b)
	if va == vb || !strings.HasPrefix(va, "cfg-") || len(va) != 16 || va != policyVersion(a) {
		t.Errorf("policy versions %q %q", va, vb)
	}
}
