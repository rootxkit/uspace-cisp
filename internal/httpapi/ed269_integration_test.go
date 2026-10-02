//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-cisp/internal/dataset"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// The ED-269 bridge on PostgreSQL (migration 0013): the mappable vector
// file is published, read back three ways (export, source, version), and
// its row holds the mapped ED-318 as body and the bytes sent as
// source_body with their hash and type; an ED-318 publication's row has
// none (E-01). A refusal is recorded and makes no version.
func TestED269BridgeOnPostgres(t *testing.T) {
	st, pool := pgStore(t)
	h := newPubHarness(t, st)
	ctx := context.Background()
	emptyZones(t, h)
	body := mappableED269(t)
	v := ed269RoundTrip(t, h, body)

	row, err := relational.New(pool).GetPublication(ctx, relational.GetPublicationParams{Dataset: "zones", Version: v})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if !bytes.Equal(row.SourceBody, body) || !bytes.Equal(row.SourceSha256, sum[:]) ||
		row.SourceContentType == nil || *row.SourceContentType != dataset.MediaTypeED269 {
		t.Fatalf("source columns: %d bytes, type %v", len(row.SourceBody), row.SourceContentType)
	}
	if row.ContentType != mediaGeoJSON || bytes.Equal(row.Body, body) || !strings.Contains(string(row.Body), `"FeatureCollection"`) {
		t.Errorf("body is not the mapped ED-318 (%s, %d bytes)", row.ContentType, len(row.Body))
	}

	// An ED-318 publication keeps no source.
	if rec := h.put("zones", jsonBytes(t, plainZones(t))); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body.String())
	}
	cur, err := st.CurrentVersion(ctx, publication.DatasetZones)
	if err != nil {
		t.Fatal(err)
	}
	row, err = relational.New(pool).GetPublication(ctx, relational.GetPublicationParams{Dataset: "zones", Version: cur})
	if err != nil {
		t.Fatal(err)
	}
	if row.SourceBody != nil || row.SourceSha256 != nil || row.SourceContentType != nil {
		t.Errorf("an ED-318 version has source columns")
	}

	// A refusal makes no version.
	rec := h.putED269(oneED269Zone(t, func(z doc) { z["restriction"] = "REQ_AUTHORIZATION" }), "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("refusal = %d %s", rec.Code, rec.Body.String())
	}
	if after, _ := st.CurrentVersion(ctx, publication.DatasetZones); after != cur {
		t.Errorf("a refused ED-269 publication made version %d", after)
	}

	// The database refuses a source without its hash or type: the
	// columns are all set or all null.
	_, err = pool.Exec(ctx, `INSERT INTO publications (id, dataset, version, publisher_client_id, received_at, body, body_sha256,
		content_type, feature_count, added, changed, removed, reason, source_body)
		VALUES ('ED269CHECK', 'zones', 999999, 'x', now(), '\x00', $1, 'application/geo+json', 0, 0, 0, 0, 'publication', '\x00')`, sum[:])
	if err == nil || !strings.Contains(err.Error(), "publications_source_all_or_none") {
		t.Errorf("a source without hash and type was stored: %v", err)
	}
}
