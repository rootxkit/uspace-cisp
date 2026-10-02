//go:build integration

package store

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// The reads WP-4 serves, on PostgreSQL: the current features (all and
// by box), the delta between two versions with its two refusals, a
// stored version, the change feed and the publishers.
func TestReadsFromTheStore(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	ds := publication.DatasetRestrictions
	fc, body := base(t, "R")
	first, err := s.PublishTx(ctx, input(ds, fc, body), NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	fewer := *fc
	fewer.Features = fc.Features[:len(fc.Features)-1]
	body2, err := ed318.Export(&fewer)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.PublishTx(ctx, input(ds, &fewer, body2), NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}

	cur, err := s.ReadCurrent(ctx, ds, nil)
	if err != nil || cur.Version != second.Version || len(cur.Features) != len(fewer.Features) || cur.ReceivedAt.IsZero() || cur.Publisher != "authority-01" {
		t.Fatalf("current %+v %v", cur, err)
	}
	for _, f := range cur.Features {
		if row, err := f.Row(); err != nil || row.ID != f.ID || !bytes.Equal(row.SHA256[:], f.SHA256) {
			t.Errorf("row of %s: %v", f.ID, err)
		}
	}
	none, err := s.ReadCurrent(ctx, ds, &BBox{MinLon: 0, MinLat: 0, MaxLon: 1, MaxLat: 1})
	if err != nil || len(none.Features) != 0 || none.Version != second.Version {
		t.Errorf("box away from every zone: %+v %v", none, err)
	}
	all, err := s.ReadCurrent(ctx, ds, &BBox{MinLon: 44, MinLat: 41, MaxLon: 46, MaxLat: 42})
	if err != nil || len(all.Features) != len(fewer.Features) {
		t.Errorf("box over Tbilisi: %d features %v", len(all.Features), err)
	}

	d, err := s.ReadDelta(ctx, ds, first.Version, 1000)
	if err != nil || d.From != first.Version || d.To != second.Version || len(d.FromFeatures) != len(fc.Features) || len(d.ToFeatures) != len(fewer.Features) {
		t.Fatalf("delta %d -> %d: %v", d.From, d.To, err)
	}
	from := rows(t, d.FromFeatures)
	to := rows(t, d.ToFeatures)
	delta := publication.Delta(from, to, d.From, d.To)
	if len(delta.Removed) != 1 || delta.Removed[0] != fc.Features[len(fc.Features)-1].Properties.Identifier || len(delta.Added)+len(delta.Changed) != 0 {
		t.Errorf("delta %+v", delta)
	}
	if same, err := s.ReadDelta(ctx, ds, second.Version, 1000); err != nil || len(same.FromFeatures)+len(same.ToFeatures) != 0 {
		t.Errorf("delta from current: %+v %v", same, err)
	}
	if _, err := s.ReadDelta(ctx, ds, second.Version+1, 1000); !errors.Is(err, ErrVersionAhead) {
		t.Errorf("ahead: %v", err)
	}
	var gone *DeltaUnavailableError
	if _, err := s.ReadDelta(ctx, ds, 0, 1); !errors.As(err, &gone) || gone.Current != second.Version || !strings.Contains(err.Error(), "more than 1 versions behind") {
		t.Errorf("too old: %v", err)
	}
	if _, err := s.ReadCurrent(ctx, "nosuch", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown dataset: %v", err)
	}
	if _, err := s.ReadDelta(ctx, "nosuch", 0, 1); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown dataset delta: %v", err)
	}

	p, err := s.Publication(ctx, ds, first.Version)
	if err != nil || !bytes.Equal(p.Body, body) || p.PublisherSignature == nil || p.ContentType != "application/json" {
		t.Errorf("publication %v", err)
	}
	if _, err := s.Publication(ctx, ds, 1<<40); !errors.Is(err, ErrNotFound) {
		t.Errorf("no such version: %v", err)
	}

	changes, err := s.Changes(ctx, first.Change.ID-1, &ds, 2)
	if err != nil || len(changes) != 2 || changes[0].ID != first.Change.ID || changes[0].BBox == nil || changes[1].Version != second.Version {
		t.Fatalf("changes %+v %v", changes, err)
	}
	if every, err := s.Changes(ctx, first.Change.ID-1, nil, 1); err != nil || len(every) != 1 {
		t.Errorf("changes of every dataset: %+v %v", every, err)
	}
	if _, err := s.Publishers(ctx); err != nil {
		t.Errorf("publishers: %v", err)
	}
	snap, err := s.Snapshot(ctx, ds, second.Version)
	if err != nil || snap.ReceivedAt.IsZero() || snap.Publisher != "authority-01" {
		t.Errorf("snapshot head %+v %v", snap, err)
	}
}

func rows(t *testing.T, fs []StoredFeature) []publication.FeatureRow {
	t.Helper()
	out := make([]publication.FeatureRow, 0, len(fs))
	for _, f := range fs {
		r, err := f.Row()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}
