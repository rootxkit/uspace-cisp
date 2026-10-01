package publication

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/vectors"
)

// acceptedCollections are the collections of ed318_roundtrip.json that
// ed318.Parse accepts, by case name.
func acceptedCollections(t *testing.T) map[string]*ed318.FeatureCollection {
	t.Helper()
	f := vectors.Load(t, "ed318_roundtrip.json")
	out := map[string]*ed318.FeatureCollection{}
	for _, c := range f.Cases {
		var in struct {
			Document json.RawMessage `json:"document"`
		}
		if err := json.Unmarshal(c.Input, &in); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if len(in.Document) == 0 {
			continue
		}
		fc, probs := ed318.Parse(in.Document, ed318.Limits{})
		if probs != nil {
			continue
		}
		out[c.Name] = fc
	}
	if len(out) < 5 {
		t.Fatalf("only %d accepted collections in the vectors", len(out))
	}
	return out
}

func baseCollection(t *testing.T) *ed318.FeatureCollection {
	t.Helper()
	fc, ok := acceptedCollections(t)["accept-authority-collection"]
	if !ok {
		t.Fatal("no accept-authority-collection case")
	}
	return fc
}

func rowByID(t *testing.T, rows []FeatureRow, id string) FeatureRow {
	t.Helper()
	for i := range rows {
		if rows[i].ID == id {
			return rows[i]
		}
	}
	t.Fatalf("no row %q", id)
	return FeatureRow{}
}

func TestRowsFromEveryAcceptedVectorCollection(t *testing.T) {
	for name, fc := range acceptedCollections(t) {
		t.Run(name, func(t *testing.T) {
			rows, err := Rows(fc)
			if err != nil {
				t.Fatalf("Rows: %v", err)
			}
			if len(rows) != len(fc.Features) {
				t.Fatalf("%d rows for %d features", len(rows), len(fc.Features))
			}
			for i, r := range rows {
				if r.ID != fc.Features[i].Properties.Identifier {
					t.Errorf("row %d id %q, feature %q", i, r.ID, fc.Features[i].Properties.Identifier)
				}
				if r.SHA256 != sha256.Sum256(r.Canonical) {
					t.Errorf("%s: hash is not of Canonical", r.ID)
				}
				if len(r.Geom) == 0 {
					t.Errorf("%s: no geometry part", r.ID)
				}
				// The canonical feature is the published feature by value.
				fe, err := ed318.Export(&ed318.FeatureCollection{Features: []ed318.Feature{fc.Features[i]}})
				if err != nil {
					t.Fatal(err)
				}
				var doc struct{ Features []any }
				if err := json.Unmarshal(fe, &doc); err != nil {
					t.Fatal(err)
				}
				var got any
				if err := json.Unmarshal(r.Canonical, &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, doc.Features[0]) {
					t.Errorf("%s: canonical feature differs from the published one by value", r.ID)
				}
			}
		})
	}
}

func TestRowsOfTheBaseCollection(t *testing.T) {
	rows, err := Rows(baseCollection(t))
	if err != nil {
		t.Fatal(err)
	}

	// A circle keeps its centre and radius; nothing is approximated in Go.
	circle := rowByID(t, rows, "TSD001")
	if len(circle.Geom) != 1 || !circle.Geom[0].Circle() || *circle.Geom[0].RadiusM != 1500 {
		t.Fatalf("TSD001 geometry %+v, want one circle of 1500 m", circle.Geom)
	}
	if c := *circle.Geom[0].Center; c.LatDeg != 41.7151 || c.LonDeg != 44.8271 {
		t.Errorf("TSD001 centre %+v", c)
	}
	if circle.Centroid != (core.LatLon{}) {
		t.Errorf("Rows computed a centroid %+v; the store does that in SQL", circle.Centroid)
	}
	// Feet converted by core; the references kept.
	if circle.UpperM == nil || *circle.UpperM != 2500*core.FeetToMetres || circle.UpperRef != core.VerticalRef("AMSL") {
		t.Errorf("TSD001 upper %v %s, want %v AMSL", circle.UpperM, circle.UpperRef, 2500*core.FeetToMetres)
	}
	if circle.LowerM == nil || *circle.LowerM != 0 || circle.LowerRef != core.VerticalRef("AGL") {
		t.Errorf("TSD001 lower %v %s", circle.LowerM, circle.LowerRef)
	}
	// Daylight events and the outer bounds of applicability.
	if !circle.HasEvents {
		t.Error("TSD001 uses BMCT/EECT but HasEvents is false")
	}
	wantFrom := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	wantTo := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	if circle.ApplicableFrom == nil || !circle.ApplicableFrom.Equal(wantFrom) || circle.ApplicableTo == nil || !circle.ApplicableTo.Equal(wantTo) {
		t.Errorf("TSD001 applicability %v..%v", circle.ApplicableFrom, circle.ApplicableTo)
	}

	// A clock-time schedule: bounded, no events (E-01 twin of the above).
	sched := rowByID(t, rows, "TSR001")
	if sched.HasEvents {
		t.Error("TSR001 has clock times only but HasEvents is true")
	}
	if sched.ApplicableFrom == nil || sched.ApplicableTo == nil {
		t.Error("TSR001 has start and end dates but the bounds are nil")
	}
	if len(sched.Geom[0].Rings) != 2 {
		t.Errorf("TSR001 has a hole; got %d rings", len(sched.Geom[0].Rings))
	}

	// No limitedApplicability: unbounded.
	always := rowByID(t, rows, "TSU001")
	if always.ApplicableFrom != nil || always.ApplicableTo != nil || always.HasEvents {
		t.Errorf("TSU001 applies always; got %v..%v events=%v", always.ApplicableFrom, always.ApplicableTo, always.HasEvents)
	}
	if always.HasLayers || always.PartIDs != nil {
		t.Error("TSU001 is one polygon, not layers")
	}

	// A GeometryCollection is one row with its parts and their identifiers.
	layered := rowByID(t, rows, "TSC001")
	if !layered.HasLayers || len(layered.Geom) != 2 {
		t.Fatalf("TSC001 layers=%v parts=%d, want one row with 2 parts", layered.HasLayers, len(layered.Geom))
	}
	if want := []string{"TSC001/L0", "TSC001/L1"}; !reflect.DeepEqual(layered.PartIDs, want) {
		t.Errorf("TSC001 part ids %v, want %v", layered.PartIDs, want)
	}

	// No limits given: the surface and unlimited, references kept.
	open := rowByID(t, rows, "TSN001")
	if open.LowerM != nil || open.UpperM != nil {
		t.Errorf("TSN001 has no limit values; got %v %v", open.LowerM, open.UpperM)
	}
}

func f64(v float64) *float64 { return &v }
func str(s string) *string   { return &s }

func layer(lower, upper *float64, lref, uref string) *ed318.Layer {
	return &ed318.Layer{Lower: lower, Upper: upper, LowerReference: core.VerticalRef(lref), UpperReference: core.VerticalRef(uref)}
}

func TestLayersBoundsShareAReferenceOrAreOpen(t *testing.T) {
	cases := []struct {
		name               string
		layers             []*ed318.Layer
		wantLower, wantUp  *float64
		wantLRef, wantURef string
	}{
		{"same references: lowest lower, highest upper",
			[]*ed318.Layer{layer(f64(10), f64(50), "AGL", "AGL"), layer(f64(50), f64(120), "AGL", "AGL")},
			f64(10), f64(120), "AGL", "AGL"},
		{"different references: no single bound",
			[]*ed318.Layer{layer(f64(10), f64(50), "AGL", "AGL"), layer(f64(500), f64(900), "AMSL", "AMSL")},
			nil, nil, "", ""},
		{"one layer from the surface",
			[]*ed318.Layer{layer(nil, f64(50), "AGL", "AGL"), layer(f64(50), f64(120), "AGL", "AGL")},
			nil, f64(120), "AGL", "AGL"},
		{"no layer at all",
			[]*ed318.Layer{nil},
			nil, nil, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lo, lref := bound(c.layers, true)
			up, uref := bound(c.layers, false)
			if !reflect.DeepEqual(lo, c.wantLower) || !reflect.DeepEqual(up, c.wantUp) || string(lref) != c.wantLRef || string(uref) != c.wantURef {
				t.Errorf("got %v %s / %v %s", lo, lref, up, uref)
			}
		})
	}
}

func TestRowsRefusals(t *testing.T) {
	base := baseCollection(t)

	t.Run("nil collection", func(t *testing.T) {
		if _, err := Rows(nil); !isField(err, "$") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("repeated identifier refused, distinct accepted", func(t *testing.T) {
		fc := *base
		fc.Features = append([]ed318.Feature{}, base.Features...)
		dup := fc.Features[0]
		fc.Features = append(fc.Features, dup)
		_, err := Rows(&fc)
		if !isField(err, "features[5].properties.identifier") || !strings.Contains(err.Error(), "TSU001") {
			t.Fatalf("got %v", err)
		}
		dup.Properties.Identifier = "TSU002"
		fc.Features[5] = dup
		if _, err := Rows(&fc); err != nil {
			t.Fatalf("distinct identifiers refused: %v", err)
		}
	})

	t.Run("identifier equal to a layer identifier refused, a free one accepted", func(t *testing.T) {
		fc := *base
		fc.Features = append([]ed318.Feature{}, base.Features...)
		f := fc.Features[0]
		f.Properties.Identifier = "TSC001/L1"
		fc.Features = append(fc.Features, f)
		_, err := Rows(&fc)
		if !isField(err, "features[5].properties.identifier") {
			t.Fatalf("got %v", err)
		}
		f.Properties.Identifier = "TSC001/L2"
		fc.Features[5] = f
		if _, err := Rows(&fc); err != nil {
			t.Fatalf("an identifier no layer makes was refused: %v", err)
		}
	})

	t.Run("a layer identifier equal to an earlier identifier refused", func(t *testing.T) {
		fc := *base
		f := base.Features[0]
		f.Properties.Identifier = "TSC001/L0"
		fc.Features = append([]ed318.Feature{f}, base.Features...)
		_, err := Rows(&fc)
		if !isField(err, "features[4].geometry.geometries[0]") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("over MaxFeaturesPerPublication refused, at it accepted", func(t *testing.T) {
		one := base.Features[0]
		fc := &ed318.FeatureCollection{Type: "FeatureCollection", Features: make([]ed318.Feature, MaxFeaturesPerPublication+1)}
		for i := range fc.Features {
			fc.Features[i] = one
			fc.Features[i].Properties.Identifier = "Z" + strconv.Itoa(i)
		}
		_, err := Rows(fc)
		if !isField(err, "features") || !strings.Contains(err.Error(), "50001") {
			t.Fatalf("got %v", err)
		}
		fc.Features = fc.Features[:MaxFeaturesPerPublication]
		rows, err := Rows(fc)
		if err != nil || len(rows) != MaxFeaturesPerPublication {
			t.Fatalf("at the bound: %d rows, %v", len(rows), err)
		}
	})
}

func isField(err error, field string) bool {
	var fe *core.FieldError
	return errors.As(err, &fe) && fe.Field == field
}

func TestCanonicalSortsKeysAndKeepsNumbers(t *testing.T) {
	got, err := Canonical([]byte(` {"b": 1.50, "a": {"z": "<&>", "y": [3, 1e2]}} `))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":{"y":[3,1e2],"z":"<&>"},"b":1.50}`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if _, err := Canonical([]byte(`{"a":`)); err == nil {
		t.Error("broken JSON accepted")
	}
}

func row(id string, content string) FeatureRow {
	c := []byte(`{"id":"` + id + `","v":"` + content + `"}`)
	return FeatureRow{ID: id, Canonical: c, SHA256: sha256.Sum256(c)}
}

func TestDiffPresenceBesideAbsence(t *testing.T) {
	prev := []FeatureRow{row("A", "1"), row("B", "1"), row("C", "1")}

	t.Run("nothing changed", func(t *testing.T) {
		d := DiffRows(prev, []FeatureRow{row("C", "1"), row("A", "1"), row("B", "1")})
		if !d.Empty() || len(d.Ops) != 3 || d.Ops["A"] != OpUnchanged {
			t.Fatalf("got %+v", d)
		}
	})
	t.Run("one added beside the unchanged", func(t *testing.T) {
		d := DiffRows(prev, append(append([]FeatureRow{}, prev...), row("D", "1")))
		if !reflect.DeepEqual(d.Added, []string{"D"}) || d.Changed != nil || d.Removed != nil || d.Ops["A"] != OpUnchanged || d.Ops["D"] != OpAdded {
			t.Fatalf("got %+v", d)
		}
	})
	t.Run("one changed beside the unchanged", func(t *testing.T) {
		d := DiffRows(prev, []FeatureRow{row("A", "1"), row("B", "2"), row("C", "1")})
		if !reflect.DeepEqual(d.Changed, []string{"B"}) || d.Added != nil || d.Removed != nil || d.Ops["B"] != OpChanged || d.Ops["C"] != OpUnchanged {
			t.Fatalf("got %+v", d)
		}
	})
	t.Run("one removed beside the unchanged", func(t *testing.T) {
		d := DiffRows(prev, []FeatureRow{row("A", "1"), row("C", "1")})
		if !reflect.DeepEqual(d.Removed, []string{"B"}) || d.Added != nil || d.Changed != nil || d.Ops["B"] != OpRemoved {
			t.Fatalf("got %+v", d)
		}
		if !reflect.DeepEqual(d.IDs(), []string{"B"}) {
			t.Errorf("IDs %v", d.IDs())
		}
	})
	t.Run("all three, sorted", func(t *testing.T) {
		d := DiffRows(prev, []FeatureRow{row("Z", "1"), row("C", "2"), row("Y", "1"), row("A", "2")})
		if !reflect.DeepEqual(d.Added, []string{"Y", "Z"}) || !reflect.DeepEqual(d.Changed, []string{"A", "C"}) || !reflect.DeepEqual(d.Removed, []string{"B"}) {
			t.Fatalf("got %+v", d)
		}
		if !reflect.DeepEqual(d.IDs(), []string{"A", "B", "C", "Y", "Z"}) {
			t.Errorf("IDs %v", d.IDs())
		}
	})
	t.Run("from empty, to empty", func(t *testing.T) {
		if d := DiffRows(nil, prev); len(d.Added) != 3 {
			t.Errorf("from empty: %+v", d)
		}
		if d := DiffRows(prev, nil); len(d.Removed) != 3 {
			t.Errorf("to empty: %+v", d)
		}
		if d := DiffRows(nil, nil); !d.Empty() {
			t.Errorf("empty to empty: %+v", d)
		}
	})
}

// Property: Apply(a, b, DiffRows(a, b)) == b, DiffRows(a, a) is empty, and
// the diff is the same whatever the input order.
func TestDiffApplyProperty(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261002, 1))
	randomSet := func() []FeatureRow {
		n := rng.IntN(40)
		seen := map[string]bool{}
		var out []FeatureRow
		for range n {
			id := "F" + strconv.Itoa(rng.IntN(60))
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, row(id, strconv.Itoa(rng.IntN(3))))
		}
		return out
	}
	for i := range 2000 {
		a, b := randomSet(), randomSet()
		d := DiffRows(a, b)
		got := Apply(a, b, d)
		want := append([]FeatureRow{}, b...)
		SortRows(want)
		if len(got) != len(want) {
			t.Fatalf("iteration %d: apply gave %d rows, want %d", i, len(got), len(want))
		}
		for k := range got {
			if got[k].ID != want[k].ID || got[k].SHA256 != want[k].SHA256 {
				t.Fatalf("iteration %d: row %d is %s, want %s", i, k, got[k].ID, want[k].ID)
			}
		}
		if s := DiffRows(a, a); !s.Empty() {
			t.Fatalf("iteration %d: diff(a, a) = %+v", i, s)
		}
		shuffled := append([]FeatureRow{}, b...)
		rng.Shuffle(len(shuffled), func(x, y int) { shuffled[x], shuffled[y] = shuffled[y], shuffled[x] })
		if d2 := DiffRows(a, shuffled); !reflect.DeepEqual(d2, d) {
			t.Fatalf("iteration %d: diff depends on input order", i)
		}
	}
}

func TestDelta(t *testing.T) {
	from := []FeatureRow{row("A", "1"), row("B", "1"), row("C", "1")}
	to := []FeatureRow{row("A", "1"), row("B", "2"), row("D", "1")}
	d := Delta(from, to, 3, 5)
	if d.FromVersion != 3 || d.ToVersion != 5 {
		t.Errorf("versions %d..%d", d.FromVersion, d.ToVersion)
	}
	if len(d.Added) != 1 || string(d.Added[0]) != string(row("D", "1").Canonical) {
		t.Errorf("added %s", d.Added)
	}
	if len(d.Changed) != 1 || string(d.Changed[0]) != string(row("B", "2").Canonical) {
		t.Errorf("changed %s", d.Changed)
	}
	if !reflect.DeepEqual(d.Removed, []string{"C"}) {
		t.Errorf("removed %v", d.Removed)
	}
	// The empty delta is empty lists, not nil (it is a JSON body).
	e := Delta(from, from, 3, 3)
	if e.Added == nil || e.Changed == nil || e.Removed == nil || len(e.Added)+len(e.Changed)+len(e.Removed) != 0 {
		t.Errorf("empty delta %+v", e)
	}
}

func TestChangeOf(t *testing.T) {
	rows, err := Rows(baseCollection(t))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 2, 10, 0, 0, 0, time.FixedZone("x", 4*3600))

	t.Run("a removed polygon makes its box", func(t *testing.T) {
		next := []FeatureRow{}
		for _, r := range rows {
			if r.ID != "TSR001" {
				next = append(next, r)
			}
		}
		d := DiffRows(rows, next)
		c := ChangeOf(DatasetZones, 7, d, append(append([]FeatureRow{}, rows...), next...), ReasonPublication, at)
		if c.Dataset != DatasetZones || c.Version != 7 || c.Reason != ReasonPublication || !c.At.Equal(at) || c.At.Location() != time.UTC {
			t.Errorf("header %+v", c)
		}
		if !reflect.DeepEqual(c.FeatureIDs, []string{"TSR001"}) || !reflect.DeepEqual(c.RemovedIDs, []string{"TSR001"}) {
			t.Errorf("ids %v removed %v", c.FeatureIDs, c.RemovedIDs)
		}
		if c.BBox == nil || c.BBox.MinLat != 41.7 || c.BBox.MaxLat != 41.72 || c.BBox.MinLon != 44.8 || c.BBox.MaxLon != 44.82 {
			t.Errorf("bbox %+v", c.BBox)
		}
	})
	t.Run("a circle's box covers its radius", func(t *testing.T) {
		c := ChangeOf(DatasetZones, 1, DiffRows(nil, rows[1:2]), rows[1:2], ReasonPublication, at)
		if c.BBox == nil || !(c.BBox.MinLat < 41.7151-0.013 && c.BBox.MaxLat > 41.7151+0.013) {
			t.Errorf("bbox %+v does not cover 1500 m around the centre", c.BBox)
		}
	})
	t.Run("nothing changed: no box", func(t *testing.T) {
		c := ChangeOf(DatasetZones, 7, DiffRows(rows, rows), rows, ReasonRepublished, at)
		if c.BBox != nil || len(c.FeatureIDs) != 0 || c.RemovedIDs == nil {
			t.Errorf("got %+v", c)
		}
	})
}

func TestSnapshotDeterministicAndParseable(t *testing.T) {
	fc := baseCollection(t)
	issued := time.Date(2026, 10, 2, 8, 30, 0, 250_000_000, time.FixedZone("x", 4*3600))
	a, err := Snapshot(DatasetZones, 12, issued, "authority-01", fc)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Snapshot(DatasetZones, 12, issued, "authority-01", fc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two runs gave different bytes")
	}
	if fc.Extra[MemberVersion] != nil || *fc.Metadata.Issued != (ed318.DateTime{Time: fc.Metadata.Issued.Time, Text: "2026-09-30T12:00:00.5Z"}) {
		t.Fatal("Snapshot modified its input")
	}

	back, probs := ed318.Parse(a, ed318.Limits{})
	if probs != nil {
		t.Fatalf("ed318.Parse refused the snapshot: %v", probs)
	}
	// Parse(Snapshot(fc)) is fc plus the cis_* members and the issued and
	// provider metadata.
	want := *fc
	meta := *fc.Metadata
	meta.Issued = &ed318.DateTime{Time: issued.UTC(), Text: "2026-10-02T04:30:00.25Z"}
	meta.Provider = []ed318.Text{{Text: str("authority-01"), Lang: ProviderLang}}
	want.Metadata = &meta
	want.Extra = map[string]json.RawMessage{
		MemberDataset:   json.RawMessage(`"zones"`),
		MemberVersion:   json.RawMessage(`12`),
		MemberUpdatedAt: json.RawMessage(`"2026-10-02T04:30:00.25Z"`),
	}
	for k, v := range fc.Extra {
		want.Extra[k] = v
	}
	wantBytes, err := ed318.Export(&want)
	if err != nil {
		t.Fatal(err)
	}
	gotBytes, err := ed318.Export(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Errorf("round trip differs:\n got %s\nwant %s", gotBytes, wantBytes)
	}
	if !bytes.Equal(gotBytes, a) {
		t.Error("Export(Parse(snapshot)) is not the snapshot")
	}

	// An empty provider keeps the published one (E-01 twin).
	kept, err := Snapshot(DatasetZones, 12, issued, "", fc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(kept, []byte(`"Test authority"`)) || bytes.Contains(kept, []byte(`authority-01`)) {
		t.Error("an empty provider did not keep the published provider")
	}
	// A different version gives different bytes.
	other, _ := Snapshot(DatasetZones, 13, issued, "authority-01", fc)
	if bytes.Equal(other, a) {
		t.Error("version 13 and 12 gave the same bytes")
	}
	// A collection without metadata gets one.
	bare := &ed318.FeatureCollection{Type: "FeatureCollection", Features: fc.Features}
	if s, err := Snapshot(DatasetRestrictions, 1, issued, "ansp-01", bare); err != nil || !bytes.Contains(s, []byte(`"issued":"2026-10-02T04:30:00.25Z"`)) {
		t.Errorf("bare collection: %v %s", err, s)
	}
	if _, err := Snapshot(DatasetZones, 1, issued, "", nil); !isField(err, "$") {
		t.Errorf("nil collection: %v", err)
	}
}

func TestETagAndDatasets(t *testing.T) {
	if got := ETag(DatasetZones, 12); got != `"zones:12"` {
		t.Errorf("ETag %s", got)
	}
	if got := ETag(DatasetUSpaceAirspace, 0); got != `"uspace_airspace:0"` {
		t.Errorf("ETag %s", got)
	}
	for _, d := range Datasets {
		if !d.Valid() {
			t.Errorf("%s not valid", d)
		}
	}
	if Dataset("geo_zones").Valid() {
		t.Error("an unknown dataset is valid")
	}
	if DatasetUSSPList.Kind() != KindUsspList || DatasetRestrictions.Kind() != KindED318 {
		t.Error("kinds")
	}
	if !ReasonRestrictionExpired.VersionReason() || ReasonSubscriptionTest.VersionReason() || Reason("x").VersionReason() {
		t.Error("version reasons")
	}
}
