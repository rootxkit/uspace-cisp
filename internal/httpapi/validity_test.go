package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// authorityPeriodOfValidity is a zones publication exactly as
// uspace-authority writes it since its period-of-validity fix
// (fix/WP-5-period-of-validity, internal/zonesvc withinValidity): the
// zone's valid_from and valid_to (2019/947 Art. 15(3)) as its one
// limitedApplicability TimePeriod. The dates are those of the staging
// demo zones (valid 2026-10-04 to 2027-10-04). An invented test zone
// near Tbilisi; no real restriction.
const authorityPeriodOfValidity = `{"type":"FeatureCollection","metadata":{"issued":"2026-10-05T12:00:00Z","provider":[{"text":"Test authority","lang":"en-GB"}]},"features":[{"type":"Feature","geometry":{"type":"Polygon","coordinates":[[[44.79,41.690000000000005],[44.809999999999995,41.690000000000005],[44.809999999999995,41.71],[44.79,41.71],[44.79,41.690000000000005]]],"layer":{"upper":120,"upperReference":"AMSL","lower":0,"lowerReference":"AGL","uom":"m"}},"properties":{"identifier":"TSV001","country":"GEO","name":[{"text":"Test zone TSV001","lang":"en-GB"}],"type":"PROHIBITED","variant":"COMMON","reason":["SENSITIVE"],"zoneAuthority":[{"name":[{"text":"Test authority","lang":"en-GB"}],"purpose":"AUTHORIZATION"}],"limitedApplicability":[{"startDateTime":"2026-10-04T00:00:00Z","endDateTime":"2027-10-04T00:00:00Z"}]}}]}`

// The instants either side of the period's end, and the 2028 read the
// defect was found with.
const (
	beforeEnd = "2027-10-03T23:59:00Z"
	atEnd     = "2027-10-04T00:00:00Z"
	afterEnd  = "2027-10-04T00:01:00Z"
	in2028    = "2028-01-15T08:00:00Z"
	beforeIt  = "2026-10-03T23:59:00Z"
)

// periodReads asserts, on h's zones, the public and authenticated reads
// of TSV001 around the end of its period of validity: applies_at
// annotates applies up to the end (both ends included) and
// not_applicable after it and before the start; at serves it inside and
// leaves it out outside. The stored feature keeps its period verbatim.
func periodReads(t *testing.T, h *pubHarness) {
	t.Helper()
	for _, base := range []string{"/public/v1/zones", "/v1/zones"} {
		for at, want := range map[string]string{beforeEnd: "applies", atEnd: "applies", afterEnd: "not_applicable", in2028: "not_applicable", beforeIt: "not_applicable"} {
			rec := h.read(http.MethodGet, base+"?bbox=44.35,41.5,45.35,41.95&applies_at="+url.QueryEscape(at))
			if _, byID := collection(t, rec); rec.Code != 200 || annotation(byID["TSV001"]) != want {
				t.Errorf("%s applies_at=%s: %d %v, want %s", base, at, rec.Code, annotation(byID["TSV001"]), want)
			}
		}
		for at, kept := range map[string]bool{beforeEnd: true, afterEnd: false, in2028: false, beforeIt: false} {
			rec := h.read(http.MethodGet, base+"?at="+url.QueryEscape(at))
			if _, byID := collection(t, rec); rec.Code != 200 || (byID["TSV001"] != nil) != kept {
				t.Errorf("%s at=%s: %d %v, want kept %v", base, at, rec.Code, ids(byID), kept)
			}
		}
	}
	plain := h.read(http.MethodGet, "/public/v1/zones")
	if !strings.Contains(plain.Body.String(), `"limitedApplicability":[{"startDateTime":"2026-10-04T00:00:00Z","endDateTime":"2027-10-04T00:00:00Z"}]`) {
		t.Errorf("the period is not served as published: %s", plain.Body.String())
	}
}

// A zone published with the period of validity the authority sends is
// served as applying before its end and as not applying after it
// (presence and absence of the same zone on one dataset).
func TestPeriodOfValidityIsHonouredByTheReads(t *testing.T) {
	h := newPubHarness(t, nil)
	if rec := h.put("zones", []byte(authorityPeriodOfValidity)); rec.Code != 201 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	periodReads(t, h)
}

// The same zone without limitedApplicability, as the authority sent it
// before its fix, applies at every instant: the CISP can only honour a
// period the publisher sends (the defect's other side, kept so that
// the presence test above is not passing for some other reason).
func TestZoneWithoutLimitedApplicabilityAppliesAlways(t *testing.T) {
	h := newPubHarness(t, nil)
	body := strings.Replace(authorityPeriodOfValidity, `,"limitedApplicability":[{"startDateTime":"2026-10-04T00:00:00Z","endDateTime":"2027-10-04T00:00:00Z"}]`, "", 1)
	if body == authorityPeriodOfValidity {
		t.Fatal("the fixture lost its limitedApplicability member")
	}
	if rec := h.put("zones", []byte(body)); rec.Code != 201 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	for _, at := range []string{beforeEnd, in2028} {
		rec := h.read(http.MethodGet, "/public/v1/zones?applies_at="+url.QueryEscape(at))
		if _, byID := collection(t, rec); annotation(byID["TSV001"]) != "applies" {
			t.Errorf("applies_at=%s: %v", at, annotation(byID["TSV001"]))
		}
	}
}
