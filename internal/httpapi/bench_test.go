package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The read budgets of docs/PLAN.md section 9, on the fake store (the
// handler's own cost; the PostGIS prefilter is measured by the
// integration test TestReadBBoxBudgetOnPostgres).

// benchZones publishes 5 000 synthetic zones (a 71 x 71 grid around
// Tbilisi, 0.004 degrees apart) and returns the harness.
func benchZones(b *testing.B) *pubHarness {
	b.Helper()
	h := newPubHarness(b, nil)
	if rec := h.put("zones", syntheticZones(b, 5000, 20, 1)); rec.Code != 201 {
		b.Fatalf("PUT = %d", rec.Code)
	}
	return h
}

// bboxAbout50 covers about 50 of the grid's zones (7 x 7 cells and the
// edges of their neighbours).
const bboxAbout50 = "/v1/zones?bbox=44.6490,41.5990,44.6740,41.6240"

func benchRead(b *testing.B, h *pubHarness, method, target string) *httptest.ResponseRecorder {
	b.Helper()
	req := httptest.NewRequest(method, target, http.NoBody)
	req.Header.Set("Authorization", "Bearer "+h.reader())
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		b.Fatalf("%s %s = %d %s", method, target, rec.Code, rec.Body.String())
	}
	return rec
}

// BenchmarkGetZonesBBox: GET /v1/zones?bbox= over 5 000 features with
// about 50 hits. Budget: 100 ms p99 (ns/op under 50 ms).
func BenchmarkGetZonesBBox(b *testing.B) {
	h := benchZones(b)
	_, byID := collection(b, benchRead(b, h, http.MethodGet, bboxAbout50))
	b.ResetTimer()
	for b.Loop() {
		benchRead(b, h, http.MethodGet, bboxAbout50)
	}
	b.ReportMetric(float64(len(byID)), "hits")
}

// BenchmarkGetPublicZonesAt: an anonymous GET /public/v1/zones?at= with
// no box, the whole set judged at an instant. After the first read the
// version's features are parsed already (S3): the cost is the scan and
// the applicability loop.
func BenchmarkGetPublicZonesAt(b *testing.B) {
	h := benchZones(b)
	const target = "/public/v1/zones?at=2026-10-03T09:00:00Z"
	benchRead(b, h, http.MethodGet, target)
	b.ResetTimer()
	for b.Loop() {
		benchRead(b, h, http.MethodGet, target)
	}
}

// BenchmarkHeadDataset: HEAD /v1/zones from the snapshot cache (the
// subscribers' 60 s reconciliation). Budget: 5 ms p99.
func BenchmarkHeadDataset(b *testing.B) {
	h := benchZones(b)
	benchRead(b, h, http.MethodHead, "/v1/zones")
	b.ResetTimer()
	for b.Loop() {
		benchRead(b, h, http.MethodHead, "/v1/zones")
	}
}

// BenchmarkGetChanges: GET /v1/changes?since= after a webhook. Budget:
// 20 ms p99.
func BenchmarkGetChanges(b *testing.B) {
	h := newPubHarness(b, nil)
	for range 50 {
		if rec := h.put("zones", jsonBytes(b, readZones(b))); rec.Code != 201 {
			b.Fatal(rec.Code)
		}
		if rec := h.put("zones", []byte(emptyCollection)); rec.Code != 201 {
			b.Fatal(rec.Code)
		}
	}
	b.ResetTimer()
	for b.Loop() {
		benchRead(b, h, http.MethodGet, "/v1/changes?since=0&limit=100")
	}
}
