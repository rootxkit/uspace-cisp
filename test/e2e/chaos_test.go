//go:build chaos

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/httpapi"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// window is a stretch of the run in which deliver could not work (the
// database stopped, deliver killed): a retry due inside it is late by
// design, and the subscriber-outage case says so.
type window struct {
	what       string
	from, upTo time.Time
}

var (
	outagesMu sync.Mutex
	outages   []window
)

func noteOutage(what string, from, upTo time.Time) {
	outagesMu.Lock()
	defer outagesMu.Unlock()
	outages = append(outages, window{what, from, upTo})
}

// TestChaos runs the cases in order on one stack. The subscriber outage
// spans the run: subscriber-b goes down first and comes back last, at
// least CHAOS_SUBSCRIBER_DOWN (30m) later, while the other faults run.
func TestChaos(t *testing.T) {
	s := chaosEnv(t)
	down := 30 * time.Minute
	if v := os.Getenv("CHAOS_SUBSCRIBER_DOWN"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			t.Fatalf("CHAOS_SUBSCRIBER_DOWN=%q: a duration of at least 1m", v)
		}
		down = d
	}
	s.subscribe(t, "subscriber-a", "zones")
	s.subscribe(t, "subscriber-slow", "zones")
	s.publish(t, "uspace_airspace", uspaceBodyN(t, 0))
	subB := s.subscribe(t, "subscriber-b", "uspace_airspace")

	var outage subscriberOutage
	ok := t.Run("subscriber down: the change it misses", func(t *testing.T) { outage = s.subscriberDown(t, subB) })
	t.Run("postgres stopped 60 s", s.postgresStopped)
	t.Run("nats stopped 60 s", s.natsStopped)
	// deliver first: the large publication and the api case publish
	// zone sets whose changes no core receiver accepts (Q49), and the
	// readers measure the publication against the small dataset before it.
	t.Run("deliver killed mid-batch", s.deliverKilled)
	t.Run("publication at the cap under 50 readers", s.largePublication)
	t.Run("api killed mid-publication", s.apiKilled)
	if ok {
		t.Run(fmt.Sprintf("subscriber down %s: the retry schedule", down), func(t *testing.T) { s.subscriberBack(t, outage, down) })
	}
}

// --- the subscriber outage -------------------------------------------

type subscriberOutage struct {
	subscription string
	change       change
	downAt       time.Time
}

func (s *chaosStack) subscriberDown(t *testing.T, subID string) subscriberOutage {
	_, cursor := s.changes(t, 0)
	s.compose(t, "stop", "-t", "5", "subscriber-b")
	downAt := time.Now()
	v := s.publish(t, "uspace_airspace", uspaceBodyN(t, 1))
	cs, _ := s.changes(t, cursor)
	var mine *change
	for i := range cs {
		if cs[i].Dataset == "uspace_airspace" && cs[i].Version == v {
			mine = &cs[i]
		}
	}
	if mine == nil {
		t.Fatalf("no change for uspace_airspace:%d in %+v", v, cs)
	}
	// The degraded observation: the first attempt failed.
	var d gen.Delivery
	eventually(t, 30*time.Second, "a failed attempt to subscriber-b", func() bool {
		d = s.deliveryOf(t, subID, mine.MsgID)
		return d.Attempts >= 1 && d.State != gen.Delivered
	})
	t.Logf("subscriber-b stopped at %s; change %s (uspace_airspace:%d): delivery %s %s after %d attempt(s), last error %q",
		downAt.UTC().Format(time.RFC3339), mine.MsgID, v, d.Id, d.State, d.Attempts, deref(d.LastError))
	return subscriberOutage{subscription: subID, change: *mine, downAt: downAt}
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

// deliveryOf is the subscription's delivery of the change with msg_id
// msgID, with its attempt log.
func (s *chaosStack) deliveryOf(t *testing.T, subID, msgID string) gen.Delivery {
	t.Helper()
	tok := s.token(t, labClient, "localhost", "cis.read")
	since := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	resp, raw := s.call(t, http.MethodGet, "/v1/subscriptions/"+subID+"/deliveries?since="+since, tok, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deliveries = %d %s", resp.StatusCode, raw)
	}
	var list gen.DeliveryList
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	for _, d := range list.Deliveries {
		if d.ChangeId != nil && strconv.FormatInt(*d.ChangeId, 10) == msgID {
			return d
		}
	}
	return gen.Delivery{}
}

func (s *chaosStack) subscriberBack(t *testing.T, o subscriberOutage, down time.Duration) {
	if wait := time.Until(o.downAt.Add(down)); wait > 0 {
		t.Logf("waiting %s more for the %s outage to elapse", wait.Round(time.Second), down)
		time.Sleep(wait) // the outage itself is the case: it is a duration, not a condition
	}
	upAt := time.Now()
	s.compose(t, "start", "subscriber-b")
	var d gen.Delivery
	eventually(t, 7*time.Minute, "the retry delivers the missed change to subscriber-b", func() bool {
		d = s.deliveryOf(t, o.subscription, o.change.MsgID)
		return d.State == gen.Delivered
	})
	held := false
	for deadline := time.Now().Add(30 * time.Second); !held && time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		for _, r := range s.received(t, "subscriber-b") {
			held = held || (r.ChangeID == o.change.MsgID && r.Verified)
		}
	}
	if !held {
		t.Errorf("delivery %s is delivered, but subscriber-b holds no verified notification of change %s: %+v",
			d.Id, o.change.MsgID, s.received(t, "subscriber-b"))
	}
	if d.Log == nil || len(*d.Log) < 2 {
		t.Fatalf("delivery %s has no attempt log: %+v", d.Id, d)
	}
	log := *d.Log
	sort.Slice(log, func(i, j int) bool { return log[i].Attempt < log[j].Attempt })
	retry := subscription.DefaultRetry
	// slack: the sender's poll (250 ms) and the dial; a retry due inside
	// an outage window is late by the window.
	const slack = 2 * time.Second
	var rows [][]string
	early, lateUnexplained := 0, 0
	for i := 1; i < len(log); i++ {
		prevEnd := log[i-1].At
		start := log[i].At.Add(-time.Duration(log[i].LatencyMs) * time.Millisecond)
		nominal := retry.Delay(log[i-1].Attempt)
		lo := time.Duration(float64(nominal) * (1 - subscription.Jitter))
		hi := time.Duration(float64(nominal)*(1+subscription.Jitter)) + slack
		gap := start.Sub(prevEnd)
		verdict := "within jitter"
		switch {
		case gap < lo-100*time.Millisecond:
			verdict = "EARLY"
			early++
		case gap > hi:
			if w, ok := overlapping(prevEnd.Add(lo), start); ok {
				verdict = "late: " + w
			} else {
				verdict = "LATE"
				lateUnexplained++
			}
		}
		rows = append(rows, []string{strconv.Itoa(log[i].Attempt), log[i].At.UTC().Format("15:04:05.000"),
			statusOf(log[i].StatusCode), nominal.String(),
			fmt.Sprintf("%s .. %s", lo.Round(time.Millisecond), hi.Round(time.Millisecond)), gap.Round(time.Millisecond).String(), verdict})
	}
	tab := table([]string{"attempt", "at (UTC)", "status", "NextAttempt delay", "allowed (±10 % + 2 s)", "observed", "verdict"}, rows)
	t.Logf("subscriber-b down %s, up at %s; delivery %s delivered after %d attempts\n%s", down,
		upAt.UTC().Format(time.RFC3339), d.Id, d.Attempts, tab)
	summary(t, fmt.Sprintf("### Chaos: subscriber down %s\n\nChange %s missed while subscriber-b was down; delivered %s after the restart in attempt %d. Each retry against `subscription.NextAttempt` (Delay doubling from 1 s to 300 s, ±10 %% jitter):\n\n%s",
		down, o.change.MsgID, time.Since(upAt).Round(time.Second), d.Attempts, tab))
	if early > 0 || lateUnexplained > 0 {
		t.Errorf("%d attempts early and %d late outside every outage window", early, lateUnexplained)
	}
	if deref(log[len(log)-1].StatusCode) != http.StatusNoContent {
		t.Errorf("the last attempt answered %d, want 204", deref(log[len(log)-1].StatusCode))
	}
}

func statusOf(code *int) string {
	if code == nil {
		return "no answer"
	}
	return strconv.Itoa(*code)
}

// overlapping names the outage window that covers [from, to], if any.
func overlapping(from, to time.Time) (string, bool) {
	outagesMu.Lock()
	defer outagesMu.Unlock()
	for _, w := range outages {
		if w.from.Before(to) && w.upTo.Add(5*time.Second).After(from) {
			return w.what, true
		}
	}
	return "", false
}

// --- PostgreSQL --------------------------------------------------------

func (s *chaosStack) postgresStopped(t *testing.T) {
	v0 := s.publish(t, "zones", zonesBody(t, 100))
	_, cursor := s.changes(t, 0)
	s.waitReceived(t, "subscriber-a", "zones", v0, 30*time.Second)
	var obs [][]string
	note := func(what, seen string) {
		t.Logf("%s: %s", what, seen)
		obs = append(obs, []string{time.Now().UTC().Format("15:04:05.000"), what, seen})
	}
	resp, _ := s.call(t, http.MethodGet, "/public/v1/zones", "", nil, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get(httpapi.HeaderStale) != "" {
		t.Fatalf("before: GET = %d stale %q", resp.StatusCode, resp.Header.Get(httpapi.HeaderStale))
	}
	note("before: GET /public/v1/zones", fmt.Sprintf("%d, ETag %s, no %s", resp.StatusCode, resp.Header.Get("ETag"), httpapi.HeaderStale))

	stopped := time.Now()
	s.compose(t, "stop", "-t", "10", "postgres")
	note("postgres stopped", s.state(t, "postgres"))
	var stale *http.Response
	eventually(t, 30*time.Second, "GET served stale", func() bool {
		r, _, err := s.do(t, nil, http.MethodGet, s.apiURL+"/public/v1/zones", "", nil, nil)
		if err == nil && r.StatusCode == http.StatusOK && r.Header.Get(httpapi.HeaderStale) == "true" {
			stale = r
			return true
		}
		return false
	})
	note("GET /public/v1/zones", fmt.Sprintf("%d, %s: %s, %s: %s, ETag %s", stale.StatusCode, httpapi.HeaderStale,
		stale.Header.Get(httpapi.HeaderStale), httpapi.HeaderAgeS, stale.Header.Get(httpapi.HeaderAgeS), stale.Header.Get("ETag")))
	head, _, err := s.do(t, nil, http.MethodHead, s.apiURL+"/public/v1/zones", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	note("HEAD /public/v1/zones", fmt.Sprintf("%d, %s: %s", head.StatusCode, httpapi.HeaderStale, head.Header.Get(httpapi.HeaderStale)))
	var put *http.Response
	var putRaw []byte
	eventually(t, 40*time.Second, "PUT refused 503", func() bool {
		r, raw, err := s.putAs(t, "zones", fmt.Sprintf(`"zones:%d"`, v0), zonesBody(t, 101))
		if err == nil && r.StatusCode == http.StatusServiceUnavailable {
			put, putRaw = r, raw
			return true
		}
		return false
	})
	var p gen.Problem
	_ = json.Unmarshal(putRaw, &p)
	note("PUT /v1/publications/zones", fmt.Sprintf("%d %s, Retry-After %s", put.StatusCode, p.Type, put.Header.Get("Retry-After")))
	if put.Header.Get("Retry-After") == "" {
		t.Error("the 503 has no Retry-After")
	}
	if wait := time.Until(stopped.Add(60 * time.Second)); wait > 0 {
		time.Sleep(wait) // the outage is 60 s long by the brief: a duration, not a condition
	}
	note("api and deliver during the outage", s.state(t, "api")+"; "+s.state(t, "deliver"))

	s.compose(t, "start", "postgres")
	restarted := time.Now()
	noteOutage("postgres stopped", stopped, restarted)
	eventually(t, 90*time.Second, "GET fresh again", func() bool {
		r, _, err := s.do(t, nil, http.MethodGet, s.apiURL+"/public/v1/zones", "", nil, nil)
		return err == nil && r.StatusCode == http.StatusOK && r.Header.Get(httpapi.HeaderStale) == ""
	})
	note("GET /public/v1/zones after restart", fmt.Sprintf("fresh %s after the start", time.Since(restarted).Round(time.Millisecond)))
	var v1 int64
	eventually(t, 60*time.Second, "PUT accepted again", func() bool {
		r, raw, err := s.putAs(t, "zones", fmt.Sprintf(`"zones:%d"`, v0), zonesBody(t, 102))
		if err != nil || r.StatusCode != http.StatusCreated {
			return false
		}
		var out struct {
			Version int64 `json:"version"`
		}
		_ = json.Unmarshal(raw, &out)
		v1 = out.Version
		return true
	})
	note("PUT after restart", fmt.Sprintf("201 zones:%d", v1))
	if v1 != v0+1 {
		t.Errorf("version after the outage = %d, want %d (the refused PUT must leave no version)", v1, v0+1)
	}
	cs, _ := s.changes(t, cursor)
	if len(cs) != 1 || cs[0].Version != v1 {
		t.Errorf("changes since the outage = %+v, want exactly zones:%d", cs, v1)
	}
	s.waitReceived(t, "subscriber-a", "zones", v1, 60*time.Second)
	note("subscriber-a", fmt.Sprintf("received zones:%d; no change lost (feed after the outage: %d change)", v1, len(cs)))
	for _, svc := range []string{"api", "deliver"} {
		if st := s.state(t, svc); !strings.HasPrefix(st, "running") || !strings.Contains(st, "restarts=0") {
			t.Errorf("%s after the outage: %s", svc, st)
		}
	}
	summary(t, "### Chaos: PostgreSQL stopped 60 s\n\n"+table([]string{"at (UTC)", "step", "observed"}, obs))
}

// waitReceived waits until sub holds a verified notification of the
// change of ds at version v.
func (s *chaosStack) waitReceived(t *testing.T, sub, ds string, v int64, within time.Duration) {
	t.Helper()
	var want string
	for since := int64(0); want == ""; {
		cs, next := s.changes(t, since)
		for _, c := range cs {
			if c.Dataset == ds && c.Version == v {
				want = c.MsgID
			}
		}
		if len(cs) == 0 || next <= since {
			break
		}
		since = next
	}
	if want == "" {
		t.Fatalf("no change for %s:%d", ds, v)
	}
	eventually(t, within, fmt.Sprintf("%s received %s:%d (change %s)", sub, ds, v, want), func() bool {
		for _, r := range s.received(t, sub) {
			if r.ChangeID == want && r.Verified {
				return true
			}
		}
		return false
	})
}

// --- NATS ---------------------------------------------------------------

func (s *chaosStack) natsStopped(t *testing.T) {
	var obs [][]string
	note := func(what, seen string) {
		t.Logf("%s: %s", what, seen)
		obs = append(obs, []string{time.Now().UTC().Format("15:04:05.000"), what, seen})
	}
	from := s.logCount(t, "deliver")
	apiFrom := s.logCount(t, "api")
	stopped := time.Now()
	s.compose(t, "stop", "-t", "5", "nats")
	s.waitLog(t, "deliver", from, 20*time.Second, "nats disconnected", func(m doc) bool { return m["msg"] == "nats disconnected" })
	note("nats stopped", "deliver: nats disconnected")
	_, cursor := s.changes(t, 0)
	v := s.publish(t, "zones", zonesBody(t, 200))
	cs, _ := s.changes(t, cursor)
	if len(cs) != 1 {
		t.Fatalf("%d changes, want 1", len(cs))
	}
	c := cs[0]
	note("PUT during the outage", fmt.Sprintf("accepted zones:%d (change %s)", v, c.MsgID))
	apiLines, _ := s.logs(t, "api")
	for _, m := range apiLines[min(apiFrom, len(apiLines)):] {
		if msg, _ := m["msg"].(string); strings.Contains(msg, "nats") || strings.Contains(msg, "bus") {
			note("api log", fmt.Sprintf("%s %v", msg, m["reason"]))
			break
		}
	}
	s.waitReceived(t, "subscriber-a", "zones", v, 40*time.Second)
	line := s.waitLog(t, "deliver", from, 20*time.Second, "deliveries_from_scan > 0", func(m doc) bool {
		d, _ := m["deliver"].(map[string]any)
		n, _ := d["deliveries_from_scan"].(float64)
		return m["msg"] == "status" && n > 0
	})
	d, _ := line["deliver"].(map[string]any)
	note("delivered by the scan", fmt.Sprintf("subscriber-a received change %s; deliver status: deliveries_from_scan %v, nats %v", c.MsgID, d["deliveries_from_scan"], line["nats"]))
	if wait := time.Until(stopped.Add(60 * time.Second)); wait > 0 {
		time.Sleep(wait) // the outage is 60 s long by the brief
	}
	s.compose(t, "start", "nats")
	reconnectFrom := s.logCount(t, "deliver")
	s.waitLog(t, "deliver", reconnectFrom-1, 60*time.Second, "nats reconnected", func(m doc) bool {
		msg, _ := m["msg"].(string)
		return strings.HasPrefix(msg, "nats ") && msg != "nats disconnected" && msg != "nats slow consumer"
	})
	note("nats started", fmt.Sprintf("deliver reconnected after %s down", time.Since(stopped).Round(time.Second)))
	// Everything the reconnect could bring (the publish the client
	// buffered while the broker was down) has been handled once deliver
	// reports nothing queued and nothing due.
	s.waitLog(t, "deliver", reconnectFrom, 60*time.Second, "nothing due and nothing in flight", func(m doc) bool {
		d, _ := m["deliver"].(map[string]any)
		sum, _ := d["summary"].(string)
		return m["msg"] == "status" && deliverIdle(sum)
	})
	var receipts int
	ids := map[string]bool{}
	for _, r := range s.received(t, "subscriber-a") {
		if r.ChangeID == c.MsgID {
			receipts++
			ids[r.DeliveryID] = true
		}
	}
	note("after the reconnect", fmt.Sprintf("subscriber-a holds %d notification(s) of change %s in %d delivery id(s)", receipts, c.MsgID, len(ids)))
	if receipts != 1 || len(ids) != 1 {
		t.Errorf("change %s reached subscriber-a %d times in %d deliveries, want once", c.MsgID, receipts, len(ids))
	}
	summary(t, "### Chaos: NATS stopped 60 s\n\n"+table([]string{"at (UTC)", "step", "observed"}, obs))
}

// --- api killed ---------------------------------------------------------

// signalReader is a request body that closes sent once read to the end.
type signalReader struct {
	r    io.Reader
	sent chan struct{}
	once sync.Once
}

func (b *signalReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if errors.Is(err, io.EOF) {
		b.once.Do(func() { close(b.sent) })
	}
	return n, err
}

func (s *chaosStack) apiKilled(t *testing.T) {
	var rows [][]string
	outcomes := map[string]int{}
	delays := []time.Duration{0, 500 * time.Millisecond, 1000 * time.Millisecond, 1500 * time.Millisecond,
		2000 * time.Millisecond, 2500 * time.Millisecond, 3000 * time.Millisecond, 4000 * time.Millisecond}
	for i, delay := range delays {
		etag := s.etag(t, "zones")
		body := bigZones(t, 1000+i, 200, 6<<20)
		sig := s.signAs(t, s.authKey, authorityKID, body)
		tok := s.authorityToken(t)
		send := func(ifMatch string, rd io.Reader) (*http.Response, []byte, error) {
			req, _ := http.NewRequest(http.MethodPut, s.apiURL+"/v1/publications/zones", rd)
			req.ContentLength = int64(len(body))
			req.Header.Set("Authorization", "Bearer "+tok)
			req.Header.Set("If-Match", ifMatch)
			req.Header.Set("X-JWS-Signature", sig)
			req.Header.Set("Content-Type", "application/geo+json")
			resp, err := s.client.Do(req)
			if err != nil {
				return nil, nil, err
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			return resp, raw, nil
		}
		sr := &signalReader{r: strings.NewReader(string(body)), sent: make(chan struct{})}
		type result struct {
			resp *http.Response
			err  error
		}
		done := make(chan result, 1)
		go func() {
			r, _, err := send(etag, sr)
			done <- result{r, err}
		}()
		select {
		case <-sr.sent:
		case <-time.After(60 * time.Second):
			t.Fatal("the body was not sent within 60 s")
		}
		time.Sleep(delay) // the kill's place in the request is the variable under test
		killedAt := time.Now()
		s.compose(t, "kill", "-s", "KILL", "api")
		first := <-done
		firstSeen := "connection error"
		if first.err == nil {
			firstSeen = strconv.Itoa(first.resp.StatusCode) + " (answered before the kill)"
		}
		s.compose(t, "start", "api")
		s.ready(t, s.apiURL+"/readyz", 60*time.Second)
		after := s.etag(t, "zones")
		// The client's retry with the same If-Match.
		resp, raw, err := send(etag, strings.NewReader(string(body)))
		if err != nil {
			t.Fatalf("retry: %v", err)
		}
		outcome := ""
		switch {
		case first.err == nil && first.resp.StatusCode == http.StatusCreated:
			outcome = "committed before the kill"
			if resp.StatusCode != http.StatusPreconditionFailed {
				t.Errorf("delay %s: retry after a 201 = %d %s", delay, resp.StatusCode, tail(string(raw), 3))
			}
		case after == etag && resp.StatusCode == http.StatusCreated:
			outcome = "not committed; the retry published it"
		case after != etag && resp.StatusCode == http.StatusPreconditionFailed && resp.Header.Get("ETag") == after:
			outcome = "committed; the retry got 412 with the new ETag"
		default:
			t.Errorf("delay %s: ETag %s -> %s, retry %d %s (ETag %s)", delay, etag, after, resp.StatusCode,
				tail(string(raw), 3), resp.Header.Get("ETag"))
			outcome = "UNEXPECTED"
		}
		outcomes[outcome]++
		// Never a second version of the same content, never a partial one.
		versions := s.versions(t, "zones")
		sum := sha256.Sum256(body)
		same := 0
		for _, pv := range versions {
			if pv.BodySha256 == hex.EncodeToString(sum[:]) {
				same++
			}
		}
		if same != 1 {
			t.Errorf("delay %s: %d versions hold this body, want 1", delay, same)
		}
		final := s.etag(t, "zones")
		finalV, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(final, `"zones:`), `"`), 10, 64)
		prevV, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(etag, `"zones:`), `"`), 10, 64)
		if finalV != prevV+1 {
			t.Errorf("delay %s: version %d -> %d, want exactly one new version", delay, prevV, finalV)
		}
		got := s.currentFeatureCount(t, "zones")
		if want := versions[finalV].FeatureCount; got != want {
			t.Errorf("delay %s: GET /v1/zones holds %d features, version %d says %d (partial version)", delay, got, finalV, want)
		}
		rows = append(rows, []string{delay.String(), killedAt.UTC().Format("15:04:05.000"), firstSeen, etag + " → " + after,
			fmt.Sprintf("%d", resp.StatusCode), outcome, fmt.Sprintf("zones:%d, %d features", finalV, got)})
		t.Logf("kill %s after the body: first %s; %s -> %s; retry %d: %s", delay, firstSeen, etag, after, resp.StatusCode, outcome)
	}
	summary(t, "### Chaos: api killed mid-publication\n\nA 6 MiB zone set PUT, the api SIGKILLed the given time after the last body byte, started again, and the client's retry sent with the same `If-Match`:\n\n"+
		table([]string{"kill after body", "killed at (UTC)", "first PUT", "ETag before → after restart", "retry", "outcome", "current"}, rows))
	t.Logf("outcomes: %v", outcomes)
}

// versions are the newest 500 versions of ds by number.
func (s *chaosStack) versions(t *testing.T, ds string) map[int64]gen.PublicationVersion {
	t.Helper()
	resp, raw := s.call(t, http.MethodGet, "/v1/"+ds+"/versions?limit=500", s.token(t, labClient, "localhost", "cis.read"), nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("versions = %d %s", resp.StatusCode, raw)
	}
	var list gen.PublicationVersionList
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	out := map[int64]gen.PublicationVersion{}
	for _, v := range list.Versions {
		out[v.Version] = v
	}
	return out
}

func (s *chaosStack) currentFeatureCount(t *testing.T, ds string) int {
	t.Helper()
	resp, raw := s.call(t, http.MethodGet, "/public/v1/"+ds, "", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", ds, resp.StatusCode)
	}
	var fc struct {
		Features []json.RawMessage `json:"features"`
	}
	if err := json.Unmarshal(raw, &fc); err != nil {
		t.Fatal(err)
	}
	return len(fc.Features)
}

// --- deliver killed -----------------------------------------------------

func (s *chaosStack) deliverKilled(t *testing.T) {
	const n = 12
	_, cursor := s.changes(t, 0)
	before := map[string]bool{}
	for _, r := range s.received(t, "subscriber-slow") {
		before[r.DeliveryID] = true
	}
	for i := range n {
		s.publish(t, "zones", zonesBody(t, 300+i))
	}
	cs, _ := s.changes(t, cursor)
	if len(cs) != n {
		t.Fatalf("%d changes, want %d", len(cs), n)
	}
	// Mid-batch: deliver's status line counts deliveries in flight (the
	// slow subscriber holds each answer 1.5 s, under the 2 s timeout).
	from := s.logCount(t, "deliver")
	line := s.waitLog(t, "deliver", from, 15*time.Second, "deliveries in flight", func(m doc) bool {
		d, _ := m["deliver"].(map[string]any)
		sum, _ := d["summary"].(string)
		mm := inFlight.FindStringSubmatch(sum)
		return m["msg"] == "status" && mm != nil && mm[1] != "0"
	})
	d, _ := line["deliver"].(map[string]any)
	t.Logf("deliver before the kill: %v", d["summary"])
	killed := time.Now()
	s.compose(t, "kill", "-s", "KILL", "deliver")
	gotAtKill := 0
	for _, r := range s.received(t, "subscriber-slow") {
		if !before[r.DeliveryID] {
			gotAtKill++
		}
	}
	// Two more changes while deliver is dead: the scan finds them.
	for i := range 2 {
		s.publish(t, "zones", zonesBody(t, 320+i))
	}
	s.compose(t, "start", "deliver")
	started := time.Now()
	noteOutage("deliver killed", killed, started.Add(35*time.Second)) // plus the 30 s lease of the rows it held
	all, _ := s.changes(t, cursor)
	want := map[string]bool{}
	for _, c := range all {
		want[c.MsgID] = true
	}
	perChange := map[string]map[string]int{}
	eventually(t, 3*time.Minute, fmt.Sprintf("all %d changes at subscriber-slow", len(want)), func() bool {
		perChange = map[string]map[string]int{}
		for _, r := range s.received(t, "subscriber-slow") {
			if want[r.ChangeID] && r.Verified {
				if perChange[r.ChangeID] == nil {
					perChange[r.ChangeID] = map[string]int{}
				}
				perChange[r.ChangeID][r.DeliveryID]++
			}
		}
		return len(perChange) == len(want)
	})
	// Let any lease still out expire and be sent, then count.
	from = s.logCount(t, "deliver")
	s.waitLog(t, "deliver", from, 90*time.Second, "nothing due and nothing in flight", func(m doc) bool {
		d, _ := m["deliver"].(map[string]any)
		sum, _ := d["summary"].(string)
		return m["msg"] == "status" && deliverIdle(sum)
	})
	var rows [][]string
	resent, multiID := 0, 0
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		receipts := 0
		for _, k := range perChange[id] {
			receipts += k
		}
		if len(perChange[id]) != 1 {
			multiID++
		}
		if receipts > 1 {
			resent++
		}
		rows = append(rows, []string{id, strconv.Itoa(len(perChange[id])), strconv.Itoa(receipts)})
	}
	t.Logf("deliver killed with %d of the batch received; %d changes, %d resent by the lease, %d with more than one delivery id", gotAtKill, len(ids), resent, multiID)
	summary(t, fmt.Sprintf("### Chaos: deliver killed mid-batch\n\n%d changes to subscriber-slow (1.5 s per answer); deliver SIGKILLed with %q in its last status line and %d notifications recorded at the subscriber, two more published while it was dead, then started. Per change, the delivery ids and the notifications the subscriber holds (a notification sent again by the 30 s lease carries the same delivery id, the receiver's idempotency key):\n\n%s",
		len(ids), d["summary"], gotAtKill, table([]string{"change", "delivery ids", "notifications"}, rows)))
	if multiID > 0 {
		t.Errorf("%d changes reached the subscriber under more than one delivery id", multiID)
	}
}

// --- a publication at the cap under 50 readers ---------------------------

var inFlight = regexp.MustCompile(`(\d+) in flight`)

var dueNow = regexp.MustCompile(`(\d+) due,`)

// deliverIdle reads deliver's status summary ("N queued, N due, oldest
// due N s, N in flight, broker S"): nothing due and nothing in flight.
// Queued rows may remain: subscriber-b's delivery waits for its next
// retry for the whole outage.
func deliverIdle(sum string) bool {
	d, f := dueNow.FindStringSubmatch(sum), inFlight.FindStringSubmatch(sum)
	return d != nil && f != nil && d[1] == "0" && f[1] == "0"
}

var gcLine = regexp.MustCompile(`gc \d+ @[0-9.]+s [0-9]+%: .* (\d+)->(\d+)->(\d+) MB`)

// readerPeriod is how often each public reader asks: 50 readers make
// 500 requests a second, fifty times section 9's public HEAD load.
const readerPeriod = 100 * time.Millisecond

func (s *chaosStack) largePublication(t *testing.T) {
	const readers = 50
	limit := int(httpapi.DefaultMaxPublicationBytes)
	body := bigZones(t, 5000, 200, limit-8<<10)
	_, rawBefore := s.logs(t, "api")
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var mu sync.Mutex
	// phase 0: before the PUT, 1: while it runs, 2: after it.
	var phase atomic.Int32
	heads := [3][]time.Duration{}
	gets := [3][]time.Duration{}
	var failures atomic.Int64
	failed := map[string]int{}
	for r := range readers {
		wg.Go(func() {
			tick := time.NewTicker(readerPeriod)
			defer tick.Stop()
			time.Sleep(time.Duration(r) * readerPeriod / readers) // spread the readers over the period
			for i := 0; ; i++ {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
				method := http.MethodHead
				if i%10 == 9 {
					method = http.MethodGet
				}
				req, _ := http.NewRequestWithContext(ctx, method, s.apiURL+"/public/v1/zones", http.NoBody)
				req.Header.Set("Accept-Encoding", "gzip")
				ph := phase.Load()
				start := time.Now()
				resp, err := s.client.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						failures.Add(1)
						mu.Lock()
						failed[err.Error()]++
						mu.Unlock()
					}
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				d := time.Since(start)
				mu.Lock()
				switch {
				case resp.StatusCode != http.StatusOK:
					failed[method+" "+strconv.Itoa(resp.StatusCode)]++
					failures.Add(1)
				case method == http.MethodHead:
					heads[ph] = append(heads[ph], d)
				default:
					gets[ph] = append(gets[ph], d)
				}
				mu.Unlock()
			}
		})
	}
	time.Sleep(5 * time.Second) // the baseline
	phase.Store(1)
	start := time.Now()
	v := s.publish(t, "zones", body)
	took := time.Since(start)
	phase.Store(2)
	eventually(t, 30*time.Second, "the readers see the new version", func() bool {
		return s.etag(t, "zones") == fmt.Sprintf(`"zones:%d"`, v)
	})
	time.Sleep(3 * time.Second)
	cancel()
	wg.Wait()
	_, rawAfter := s.logs(t, "api")
	peakMB := 0
	for _, l := range rawAfter[min(len(rawBefore), len(rawAfter)):] {
		if m := gcLine.FindStringSubmatch(l); m != nil {
			for _, g := range m[1:3] {
				if n, _ := strconv.Atoi(g); n > peakMB {
					peakMB = n
				}
			}
		}
	}
	// Server time of each HEAD while the PUT ran, from the api's access
	// log (section 9 budgets HEAD as server time; the client's figure
	// also holds the runner's scheduling of 50 readers, the test and
	// eleven containers on two CPUs).
	var serverHeads []time.Duration
	for _, l := range rawAfter[min(len(rawBefore), len(rawAfter)):] {
		var m struct {
			Msg        string    `json:"msg"`
			Time       time.Time `json:"time"`
			Route      string    `json:"route"`
			DurationMS int64     `json:"duration_ms"`
		}
		if json.Unmarshal([]byte(l), &m) != nil || m.Msg != "request" || m.Route != "HEAD /public/v1/{dataset}" {
			continue
		}
		if !m.Time.Before(start) && !m.Time.After(start.Add(took)) {
			serverHeads = append(serverHeads, time.Duration(m.DurationMS)*time.Millisecond)
		}
	}
	st := s.state(t, "api")
	mu.Lock()
	defer mu.Unlock()
	stats := func(ds []time.Duration) string {
		if len(ds) == 0 {
			return "none"
		}
		return fmt.Sprintf("%d: p50 %s, p99 %s, max %s", len(ds), percentile(ds, 0.5).Round(100*time.Microsecond),
			percentile(ds, 0.99).Round(100*time.Microsecond), percentile(ds, 1).Round(time.Millisecond))
	}
	names := []string{"before the PUT", "during the PUT", "after the PUT"}
	rows := [][]string{{"publication", fmt.Sprintf("%d bytes, 200-vertex polygons, zones:%d, accepted in %s", len(body), v, took.Round(time.Millisecond))}}
	for ph, n := range names {
		rows = append(rows, []string{"HEAD " + n + " (client)", stats(heads[ph])}, []string{"GET (gzip) " + n + " (client)", stats(gets[ph])})
		if ph == 1 {
			rows = append(rows, []string{"HEAD during the PUT (api server time, access log, 1 ms resolution)", stats(serverHeads)})
		}
	}
	rows = append(rows,
		[]string{"failed reads", fmt.Sprintf("%d %v", failures.Load(), failed)},
		[]string{"api heap peak (gctrace)", fmt.Sprintf("%d MB (GOMEMLIMIT 200MiB, container limit 256M, 1 CPU)", peakMB)},
		[]string{"api container", st})
	tab := table([]string{"measure", "observed"}, rows)
	t.Logf("\n%s", tab)
	summary(t, fmt.Sprintf("### Chaos: a publication at the cap under %d public readers\n\nCISP_MAX_PUBLICATION_BYTES at its default (%d); each reader asks every %s (HEAD, every tenth a full GET), %d requests a second in all; HEAD p99 budget 50 ms, asserted on the api's server time; the client's figure is printed beside it.\n\n%s",
		readers, limit, readerPeriod, readers*int(time.Second/readerPeriod), tab))
	if failures.Load() > 0 {
		t.Errorf("%d reads failed: %v", failures.Load(), failed)
	}
	if len(heads[1]) == 0 || len(serverHeads) == 0 {
		t.Fatalf("HEADs measured while the PUT ran: %d by the client, %d in the api's log", len(heads[1]), len(serverHeads))
	}
	if p99 := percentile(serverHeads, 0.99); p99 >= 50*time.Millisecond {
		t.Errorf("HEAD p99 server time during the PUT %s, over 50 ms", p99)
	}
	if !strings.HasPrefix(st, "running") || !strings.Contains(st, "oom=false") {
		t.Errorf("api after the publication: %s", st)
	}
	if peakMB == 0 {
		t.Error("no GC trace line read from the api's log: the peak is unmeasured")
	}
	s.largeChangeWebhook(t, v)
}

// largeChangeWebhook checks what became of the large publication's
// webhook to subscriber-a: the change is over the id bound, so the
// webhook is a summary under core's 8 KiB verifier bound and is
// delivered (docs/PLAN.md section 15 Q49).
func (s *chaosStack) largeChangeWebhook(t *testing.T, v int64) {
	t.Helper()
	var msgID string
	for since := int64(0); msgID == ""; {
		cs, next := s.changes(t, since)
		for _, c := range cs {
			if c.Dataset == "zones" && c.Version == v {
				msgID = c.MsgID
			}
		}
		if len(cs) == 0 || next <= since {
			break
		}
		since = next
	}
	var d gen.Delivery
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		d = s.deliveryOf(t, s.subscriptions["subscriber-a"], msgID)
		if d.Attempts >= 1 {
			break
		}
	}
	payload := 0
	if d.Log != nil && len(*d.Log) > 0 {
		payload = (*d.Log)[len(*d.Log)-1].PayloadBytes
	}
	line := fmt.Sprintf("change %s (zones:%d) to subscriber-a: delivery %s, %s after %d attempt(s), payload %d bytes, last status %d, last error %q",
		msgID, v, d.Id, d.State, d.Attempts, payload, deref(d.LastStatusCode), deref(d.LastError))
	t.Log(line)
	summary(t, "### Chaos: the webhook of the large change\n\n"+line+"\n")
	if d.State != gen.Delivered || payload == 0 || payload > 8192 {
		t.Errorf("the large change's webhook was not delivered under core's 8192-byte bound (Q49): %s", line)
	}
}
