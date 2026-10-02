//go:build integration

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/publication"
)

func countRows(t *testing.T, s *Store, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := s.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Republish (spec 01 section 2, Q13): a change record of the current
// version with reason republished, its audit row, the bus publish; no
// publications row and no new version. A version that is not the
// current one is refused, and so is no version (E-01 pairs).
func TestRepublishOnPostgres(t *testing.T) {
	ctx := context.Background()
	b, err := bus.Connect(ctx, bus.Config{URL: mustEnv(t, "CISP_TEST_NATS_URL"), Name: "uspace-cisp-test", PublicBaseURL: "https://uspace-cisp.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	got := make(chan bus.ChangeMessage, 16)
	sub, err := b.Subscribe(ctx, []string{bus.SubjectPrefix + string(publication.DatasetUSSPList)}, bus.Handler{
		Change: func(m bus.ChangeMessage, _ time.Time) { got <- m },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sub.Close)
	s := testStore(t, Options{Bus: b})
	publish := func() PublishResult {
		body := []byte(`{"schema":"cis/ussp_list/v1","issued":"2026-10-02T00:00:00Z","ussps":[],"n":"` + suffix(t) + `"}`)
		res, err := s.PublishTx(ctx, PublishInput{Dataset: publication.DatasetUSSPList, Body: body, ContentType: "application/json",
			PublisherClientID: "authority-01", Reason: publication.ReasonPublication}, NoopSigner{})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	old := publish()
	cur := publish()
	drain := func() {
		for {
			select {
			case <-got:
			case <-time.After(300 * time.Millisecond):
				return
			}
		}
	}
	drain()
	pubs := countRows(t, s, `SELECT count(*) FROM publications WHERE dataset = 'ussp_list'`)
	events := countRows(t, s, `SELECT count(*) FROM events WHERE event_type = 'console_republish'`)
	e := Event{ActorType: ActorAccount, ActorID: "acc-it", EventType: "console_republish", EntityType: "publication", EntityID: cur.PublicationID,
		Payload: map[string]any{"reason": "a subscriber lost its cache", "actor_role": "publisher_admin"}}
	ch, err := s.Republish(ctx, cur.PublicationID, e)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Reason != publication.ReasonRepublished || ch.Version != cur.Version || ch.ID == 0 || len(ch.FeatureIDs) != 0 || ch.BBox != nil {
		t.Errorf("change %+v", ch)
	}
	if n := countRows(t, s, `SELECT count(*) FROM publications WHERE dataset = 'ussp_list'`); n != pubs {
		t.Errorf("publications %d -> %d: a republication wrote a version", pubs, n)
	}
	if v := currentVersion(t, s, publication.DatasetUSSPList); v != cur.Version {
		t.Errorf("current version %d, want %d", v, cur.Version)
	}
	if n := countRows(t, s, `SELECT count(*) FROM changes WHERE id = $1 AND reason = 'republished' AND publication_id = $2`, ch.ID, cur.PublicationID); n != 1 {
		t.Errorf("changes row: %d", n)
	}
	if n := countRows(t, s, `SELECT count(*) FROM events WHERE event_type = 'console_republish'`); n != events+1 {
		t.Errorf("audit rows %d -> %d", events, n)
	}
	select {
	case m := <-got:
		if m.Reason != string(publication.ReasonRepublished) || m.Version != cur.Version {
			t.Errorf("bus message %+v", m)
		}
		t.Logf("bus: %s %s version %d reason %s", m.MsgID, m.Dataset, m.Version, m.Reason)
	case <-time.After(5 * time.Second):
		t.Fatal("the republished change did not reach the bus")
	}
	if _, err := s.Republish(ctx, old.PublicationID, e); !errors.Is(err, ErrNotCurrent) {
		t.Errorf("an old version: %v", err)
	}
	if _, err := s.Republish(ctx, "01NOPE", e); !errors.Is(err, ErrNotFound) {
		t.Errorf("no version: %v", err)
	}
	if n := countRows(t, s, `SELECT count(*) FROM events WHERE event_type = 'console_republish'`); n != events+1 {
		t.Errorf("a refused republication was audited (%d)", n-events)
	}
}

// The events partitions: created through the months asked for, each
// insert-only for cisp_api; a second run creates nothing (E-01).
func TestEnsureEventPartitionsOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	created, err := s.EnsureEventPartitions(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("created %v", created)
	now, _ := s.DatabaseNow(ctx)
	last := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 3, 0)
	name := "events_y" + last.Format("2006") + "m" + last.Format("01")
	if n := countRows(t, s, `SELECT count(*) FROM pg_class WHERE relname = $1`, name); n != 1 {
		t.Fatalf("%s missing", name)
	}
	var canUpdate bool
	if err := s.pool.QueryRow(ctx, `SELECT has_table_privilege(current_user, $1, 'UPDATE')`, name).Scan(&canUpdate); err != nil || canUpdate {
		t.Errorf("%s updatable by the api role (%v)", name, err)
	}
	again, err := s.EnsureEventPartitions(ctx, 3)
	if err != nil || len(again) != 0 {
		t.Errorf("second run: %v %v", again, err)
	}
	if _, err := s.EnsureEventPartitions(ctx, 121); err == nil {
		t.Error("121 months accepted")
	}
}

// The idle end on the database's clock (migration 0011): a session last
// seen 29 minutes ago is live and its last_seen_at moves to now; one
// last seen 31 minutes ago is over, and stays over; revoked, expired and
// unknown sessions are over too. Through auth.Activity two uses within a
// minute write once.
func TestTouchSessionOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	acc := "acc-idle-" + suffix(t)
	if _, err := s.pool.Exec(ctx, `INSERT INTO accounts (id, username, password_hash, role, status, created_at)
		VALUES ($1, lower($1), 'x', 'viewer', 'active', now())`, acc); err != nil {
		t.Fatal(err)
	}
	session := func(lastSeenAgo string, extra string) string {
		t.Helper()
		jti := "jti-" + suffix(t) + suffix(t)
		if _, err := s.pool.Exec(ctx, `INSERT INTO sessions (jti, account_id, issued_at, expires_at, last_seen_at)
			VALUES ($1, $2, now() - interval '1 hour', now() + interval '1 hour', now() - $3::interval)`, jti, acc, lastSeenAgo); err != nil {
			t.Fatal(err)
		}
		if extra != "" {
			if _, err := s.pool.Exec(ctx, `UPDATE sessions SET `+extra+` WHERE jti = $1`, jti); err != nil {
				t.Fatal(err)
			}
		}
		return jti
	}
	lastSeen := func(jti string) time.Time {
		t.Helper()
		sess, err := s.Session(ctx, jti)
		if err != nil {
			t.Fatal(err)
		}
		return sess.LastSeenAt
	}
	touch := func(jti string) bool {
		t.Helper()
		ok, err := s.TouchSession(ctx, jti, auth.SessionIdle)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	live := session("29 minutes", "")
	before := lastSeen(live)
	if !touch(live) {
		t.Fatal("a session used 29 minutes ago was refused")
	}
	if after := lastSeen(live); after.Sub(before) < 28*time.Minute {
		t.Errorf("last_seen_at moved from %s to %s, want about now", before, after)
	}
	idle := session("31 minutes", "")
	before = lastSeen(idle)
	for range 2 {
		if touch(idle) {
			t.Error("a session idle for 31 minutes was accepted")
		}
	}
	if !lastSeen(idle).Equal(before) {
		t.Error("an idle session's last_seen_at moved")
	}
	for name, jti := range map[string]string{
		"revoked": session("1 minute", "revoked_at = now()"),
		"expired": session("1 minute", "expires_at = now() - interval '1 second'"),
		"unknown": "jti-unknown-" + suffix(t),
	} {
		if touch(jti) {
			t.Errorf("%s session accepted", name)
		}
	}

	// The throttle: the first use writes; a second within the minute is
	// accepted from memory and does not write (last_seen_at is put back
	// by hand to see whether anything moves it).
	a, err := auth.NewActivity(auth.ActivityConfig{Source: s})
	if err != nil {
		t.Fatal(err)
	}
	used := session("10 minutes", "")
	if ok, err := a.Active(ctx, used); !ok || err != nil {
		t.Fatalf("first use: %v %v", ok, err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = now() - interval '10 minutes' WHERE jti = $1`, used); err != nil {
		t.Fatal(err)
	}
	marked := lastSeen(used)
	if ok, err := a.Active(ctx, used); !ok || err != nil {
		t.Fatalf("second use: %v %v", ok, err)
	}
	if !lastSeen(used).Equal(marked) {
		t.Error("a second use within the minute wrote last_seen_at")
	}
	t.Logf("live session touched; idle (31 min), revoked, expired and unknown refused; a second use within a minute not written")
}
