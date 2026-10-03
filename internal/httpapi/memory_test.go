package httpapi

import (
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The PUT hands PublishTx the rows the dataset rules built (acc.Rows),
// so they are built once per publication.
func TestPutPublicationReusesTheValidatedRows(t *testing.T) {
	h := newPubHarness(t, nil)
	if rec := h.put("zones", jsonBytes(t, zonesDoc(t))); rec.Code != http.StatusCreated || !h.fake.rowsGiven {
		t.Fatalf("= %d, rows given %v", rec.Code, h.fake.rowsGiven)
	}
	// The ussp_list has no rows to give (E-01 twin).
	if rec := h.put("ussp_list", usspListBody(t)); rec.Code != http.StatusCreated || h.fake.rowsGiven {
		t.Fatalf("ussp_list = %d, rows given %v", rec.Code, h.fake.rowsGiven)
	}
}

// BenchmarkPutPublicationPeakHeap records the peak heap of one PUT,
// from the signed body to the store (in memory): the signature check,
// ed318.Parse, the dataset rules with ToZones per zone, the rows and the
// D8 lookup. Two shapes bracket real zone sets: "texts" is 20-vertex
// polygons padded with message texts (the shape of the 32 MiB run that
// peaked near 400 MB), "vertices" is 200-vertex polygons with short
// texts. The figures chose the CISP_MAX_PUBLICATION_BYTES default
// (docs/PLAN.md section 15 Q46). Run with
//
//	go test -run XXX -bench PutPublicationPeakHeap -benchtime 1x ./internal/httpapi/
//
// peak-heap-MB is the largest HeapInuse sampled during the request,
// heap-before-MB the HeapInuse before it (the body and the harness).
func BenchmarkPutPublicationPeakHeap(b *testing.B) {
	shapes := []struct {
		name         string
		vertices     int
		bytesPerZone int
	}{
		{"texts", 20, 4000},
		{"vertices", 200, 5300},
	}
	for _, mb := range []int{4, 8, 12, 16, 24} {
		for _, sh := range shapes {
			b.Run(fmt.Sprintf("%s/%dMiB", sh.name, mb), func(b *testing.B) {
				size := mb<<20 - 64<<10
				n := max(1, size/sh.bytesPerZone)
				putPeakHeap(b, syntheticZones(b, n, sh.vertices, size))
			})
		}
	}
}

func putPeakHeap(b *testing.B, body []byte) {
	b.Helper()
	h := newPubHarness(b, nil)
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		h.fake = newFakeStore()
		h.pubs.Store = h.fake
		h.store = h.fake
		req := h.putReq("zones", body, `"zones:0"`)
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		before := ms.HeapInuse
		var peak atomic.Uint64
		peak.Store(before)
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			tick := time.NewTicker(2 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
					var m runtime.MemStats
					runtime.ReadMemStats(&m)
					if m.HeapInuse > peak.Load() {
						peak.Store(m.HeapInuse)
					}
				}
			}
		})
		b.StartTimer()
		rec := h.do(req)
		b.StopTimer()
		close(stop)
		wg.Wait()
		if rec.Code != http.StatusCreated {
			b.Fatalf("PUT = %d %s", rec.Code, rec.Body.String()[:min(rec.Body.Len(), 500)])
		}
		b.ReportMetric(float64(len(body))/(1<<20), "body-MB")
		b.ReportMetric(float64(before)/(1<<20), "heap-before-MB")
		b.ReportMetric(float64(peak.Load())/(1<<20), "peak-heap-MB")
	}
}
