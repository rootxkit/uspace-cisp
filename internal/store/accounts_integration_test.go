//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-cisp/internal/publication"
)

// The console's rows on PostgreSQL (WP-8) at the store's boundary: the
// accounts with their unique username, the login's outcome committed
// with its refusal and rolled back with decide's error, the sessions and
// their revocation (fail closed for an unknown one), the account patch
// under the admin locks, the audit log read back and its chain
// recomputed, and the version heads with their feature changes.

func TestAccountsAndSessionsOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	tag := strings.ToLower(suffix(t) + suffix(t))
	actor := "acc-it-" + tag
	ev := func(typ, entity string) Event {
		return Event{TS: time.Now().UTC(), ActorType: ActorAccount, ActorID: actor, EventType: typ, EntityType: "account", EntityID: entity}
	}
	audited := func(typ string) int64 {
		return count(t, s.pool, `SELECT count(*) FROM events WHERE actor_id = $1 AND event_type = $2`, actor, typ)
	}

	dbNow, err := s.DatabaseNow(ctx)
	if err != nil || dbNow.Location() != time.UTC || time.Since(dbNow).Abs() > time.Minute {
		t.Fatalf("database clock %v %v", dbNow, err)
	}
	acc := Account{ID: "acc-a-" + tag, Username: "user-a-" + tag, PasswordHash: "$argon2id$x", Role: "admin", Status: "active", CreatedAt: dbNow.Truncate(time.Microsecond)}
	if err := s.CreateAccount(ctx, acc, ev("account_created", acc.ID)); err != nil {
		t.Fatal(err)
	}
	dup := acc
	dup.ID = "acc-b-" + tag
	if err := s.CreateAccount(ctx, dup, ev("account_created", dup.ID)); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("a taken username: %v", err)
	}
	if n := count(t, s.pool, `SELECT count(*) FROM events WHERE entity_id = $1`, dup.ID); n != 0 {
		t.Errorf("the refused account was audited (%d)", n)
	}
	got, err := s.Account(ctx, acc.ID)
	if err != nil || got.Username != acc.Username || got.Role != "admin" || got.FailedLogins != 0 || got.LastLoginAt != nil || !got.CreatedAt.Equal(acc.CreatedAt) {
		t.Errorf("account %+v %v", got, err)
	}
	if _, err := s.Account(ctx, "acc-none-"+tag); !errors.Is(err, ErrNotFound) {
		t.Errorf("no account: %v", err)
	}
	if list, err := s.Accounts(ctx, 1<<16); err != nil || !slices.ContainsFunc(list, func(a Account) bool { return a.ID == acc.ID }) {
		t.Errorf("accounts %v", err)
	}

	// The login: an unknown name reaches decide as nil and its refusal
	// is committed with its audit row; a wrong password commits the
	// counter with the refusal; decide's error writes nothing; the
	// success writes the session.
	refused := errors.New("refused")
	err = s.Login(ctx, "nobody-"+tag, func(a *Account, _ time.Time) (LoginOutcome, error) {
		if a != nil {
			t.Errorf("an unknown username found %+v", a)
		}
		return LoginOutcome{Events: []Event{ev("login_failed", "nobody")}, Refusal: refused}, nil
	})
	if !errors.Is(err, refused) || audited("login_failed") != 1 {
		t.Errorf("unknown username: %v, %d audit rows", err, audited("login_failed"))
	}
	lock := dbNow.Add(15 * time.Minute).Truncate(time.Microsecond)
	err = s.Login(ctx, acc.Username, func(a *Account, now time.Time) (LoginOutcome, error) {
		if a == nil || a.ID != acc.ID || now.Location() != time.UTC {
			t.Fatalf("login handed %+v at %v", a, now)
		}
		return LoginOutcome{Update: &AccountLoginUpdate{FailedLogins: a.FailedLogins + 1, LockedUntil: &lock, PasswordHash: a.PasswordHash},
			Events: []Event{ev("login_failed", a.ID)}, Refusal: refused}, nil
	})
	if !errors.Is(err, refused) {
		t.Errorf("wrong password: %v", err)
	}
	if got, _ := s.Account(ctx, acc.ID); got.FailedLogins != 1 || got.LockedUntil == nil || !got.LockedUntil.Equal(lock) {
		t.Errorf("the refusal's counter was not committed: %+v", got)
	}
	jti := "jti-a-" + tag
	broken := errors.New("decide failed")
	err = s.Login(ctx, acc.Username, func(*Account, time.Time) (LoginOutcome, error) {
		return LoginOutcome{Session: &NewSession{JTI: jti, AccountID: acc.ID, IssuedAt: dbNow, ExpiresAt: dbNow.Add(time.Hour)}}, broken
	})
	if !errors.Is(err, broken) {
		t.Errorf("decide's error: %v", err)
	}
	if _, err := s.Session(ctx, jti); !errors.Is(err, ErrNotFound) {
		t.Errorf("decide's error wrote a session: %v", err)
	}
	if revoked, err := s.SessionRevoked(ctx, jti); err != nil || !revoked {
		t.Errorf("an unknown session is not revoked: %v %v", revoked, err)
	}
	err = s.Login(ctx, acc.Username, func(a *Account, now time.Time) (LoginOutcome, error) {
		return LoginOutcome{Update: &AccountLoginUpdate{FailedLogins: 0, LastLoginAt: &now, PasswordHash: a.PasswordHash},
			Session: &NewSession{JTI: jti, AccountID: a.ID, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, Events: []Event{ev("login", a.ID)}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.Session(ctx, jti)
	if err != nil || sess.AccountID != acc.ID || sess.RevokedAt != nil || !sess.ExpiresAt.After(sess.IssuedAt) {
		t.Fatalf("session %+v %v", sess, err)
	}
	if got, _ := s.Account(ctx, acc.ID); got.FailedLogins != 0 || got.LastLoginAt == nil {
		t.Errorf("after the login %+v", got)
	}
	if revoked, err := s.SessionRevoked(ctx, jti); err != nil || revoked {
		t.Errorf("a live session is revoked: %v %v", revoked, err)
	}

	// Revocation: once, audited once.
	if ok, err := s.RevokeSession(ctx, jti, ev("session_revoked", jti)); err != nil || !ok {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	if ok, err := s.RevokeSession(ctx, jti, ev("session_revoked", jti)); err != nil || ok {
		t.Errorf("revoke again: %v %v", ok, err)
	}
	if n := audited("session_revoked"); n != 1 {
		t.Errorf("revocation audit rows %d", n)
	}
	if revoked, _ := s.SessionRevoked(ctx, jti); !revoked {
		t.Error("a revoked session is live")
	}
	if list, err := s.RevokedSessions(ctx, 1<<16); err != nil || !slices.Contains(list, jti) {
		t.Errorf("revoked sessions %v", err)
	}

	// The patch: decide sees the active admins under their locks; the
	// account's open sessions are revoked when asked; none, and decide's
	// refusal, write nothing.
	open := "jti-b-" + tag
	if _, err := s.pool.Exec(ctx, `INSERT INTO sessions (jti, account_id, issued_at, expires_at, last_seen_at) VALUES ($1, $2, now(), now() + interval '1 hour', now())`, open, acc.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.PatchAccount(ctx, acc.ID, func(Account, []string, time.Time) (AccountChange, error) {
		return AccountChange{}, refused
	}); !errors.Is(err, refused) {
		t.Errorf("decide's refusal: %v", err)
	}
	if _, _, err := s.PatchAccount(ctx, "acc-none-"+tag, func(Account, []string, time.Time) (AccountChange, error) {
		t.Error("decide ran for no account")
		return AccountChange{}, nil
	}); !errors.Is(err, ErrNotFound) {
		t.Errorf("no account: %v", err)
	}
	var admins []string
	out, revoked, err := s.PatchAccount(ctx, acc.ID, func(a Account, active []string, _ time.Time) (AccountChange, error) {
		admins = active
		return AccountChange{Role: "viewer", Status: "disabled", RevokeSessions: true, Event: ev("account_updated", a.ID)}, nil
	})
	if err != nil || out.Role != "viewer" || out.Status != "disabled" || !slices.Equal(revoked, []string{open}) {
		t.Errorf("patch %+v revoked %v: %v", out, revoked, err)
	}
	if !slices.Contains(admins, acc.ID) {
		t.Errorf("active admins %v without %s", admins, acc.ID)
	}
	if got, _ := s.Account(ctx, acc.ID); got.Role != "viewer" || got.Status != "disabled" {
		t.Errorf("patched account %+v", got)
	}
	if revoked, _ := s.SessionRevoked(ctx, open); !revoked {
		t.Error("the patch left a session open")
	}
	if n := audited("account_updated"); n != 1 {
		t.Errorf("patch audit rows %d", n)
	}

	// The audit log: filtered by actor and type, paged by id, by time;
	// the range handed in chain order with the hash before it, each
	// row's hash recomputed; a range with nothing in it; fn's error.
	rows, err := s.AuditEvents(ctx, AuditFilter{Actor: &actor, Limit: 100})
	if err != nil || len(rows) != 6 {
		t.Fatalf("this test's audit rows: %d %v", len(rows), err)
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].ID >= rows[i-1].ID {
			t.Errorf("not newest first: %d after %d", rows[i].ID, rows[i-1].ID)
		}
	}
	typ := "login_failed"
	if f, _ := s.AuditEvents(ctx, AuditFilter{Actor: &actor, EventType: &typ, Limit: 100}); len(f) != 2 {
		t.Errorf("by type: %d", len(f))
	}
	if p, _ := s.AuditEvents(ctx, AuditFilter{Actor: &actor, BeforeID: rows[1].ID, Limit: 100}); len(p) != 4 || p[0].ID != rows[2].ID {
		t.Errorf("the page before %d: %+v", rows[1].ID, p)
	}
	if f, _ := s.AuditEvents(ctx, AuditFilter{Actor: &actor, Since: time.Now().Add(time.Hour), Limit: 100}); len(f) != 0 {
		t.Errorf("since the future: %d", len(f))
	}
	oldest, newest := rows[len(rows)-1], rows[0]
	var seen []int64
	var mine int
	n, err := s.EventsInRange(ctx, oldest.TS, newest.TS.Add(time.Microsecond), func(prev []byte, r AuditRow) error {
		want, err := EventHash(prev, r.TS, r.ActorType, r.ActorID, r.EventType, r.EntityType, r.EntityID, r.Payload)
		if err != nil || !bytes.Equal(want, r.Hash) || !bytes.Equal(prev, r.PrevHash) {
			t.Errorf("row %d does not chain: %v", r.ID, err)
		}
		if r.ActorID == actor {
			mine++
		}
		seen = append(seen, r.ID)
		return nil
	})
	if err != nil || n != len(seen) || mine != 6 || !slices.IsSorted(seen) || seen[0] > oldest.ID {
		t.Errorf("range: %d rows, %d of this test's, %v", n, mine, err)
	}
	if n, err := s.EventsInRange(ctx, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour), func([]byte, AuditRow) error {
		t.Error("a row in an empty range")
		return nil
	}); err != nil || n != 0 {
		t.Errorf("empty range: %d %v", n, err)
	}
	if _, err := s.EventsInRange(ctx, oldest.TS, newest.TS.Add(time.Microsecond), func([]byte, AuditRow) error { return broken }); !errors.Is(err, broken) {
		t.Errorf("fn's error: %v", err)
	}
}

// withChange is the collection with the name of feature i rewritten: a
// changed feature of the same identifier.
func withChange(t *testing.T, fc *ed318.FeatureCollection, i int) *ed318.FeatureCollection {
	t.Helper()
	raw, err := ed318.Export(fc)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	props := doc["features"].([]any)[i].(map[string]any)["properties"].(map[string]any)
	props["name"] = []any{map[string]any{"lang": "en-GB", "text": "Renamed " + suffix(t)}}
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	out, probs := ed318.Parse(raw, ed318.Limits{})
	if probs != nil {
		t.Fatal(probs)
	}
	return out
}

// The console's version pages: a version's head with its counts, the
// one it superseded (none for a first version or a version that does
// not exist), and its feature changes with the previous form of a
// changed feature only when the previous version is named.
func TestPublicationHeadsOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	fc, body := base(t, "P")
	v1, err := s.PublishTx(ctx, input(publication.DatasetZones, fc, body), NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	next := withChange(t, fc, 0)
	next.Features = slices.Delete(next.Features, 1, 2)
	nextBody, err := ed318.Export(next)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := s.PublishTx(ctx, input(publication.DatasetZones, next, nextBody), NoopSigner{})
	if err != nil {
		t.Fatal(err)
	}
	changed, removed := fc.Features[0].Properties.Identifier, fc.Features[1].Properties.Identifier

	head, err := s.PublicationByID(ctx, v2.PublicationID)
	if err != nil || head.Version != v2.Version || head.Dataset != publication.DatasetZones || head.Changed != 1 || head.Removed != 1 ||
		head.Added != 0 || head.FeatureCount != len(next.Features) || head.SupersedesVersion == nil || *head.SupersedesVersion != v1.Version ||
		head.Reason != publication.ReasonPublication || !bytes.Equal(head.Body, nextBody) {
		t.Fatalf("head of v2 %+v %v", head, err)
	}
	prev, err := s.PreviousPublication(ctx, head)
	if err != nil || prev.ID != v1.PublicationID || prev.Version != v1.Version {
		t.Errorf("previous of v2 %+v %v", prev, err)
	}
	if _, err := s.PublicationByID(ctx, "01NOSUCHPUBLICATION000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no publication: %v", err)
	}
	if _, err := s.PreviousPublication(ctx, PublicationHead{Dataset: publication.DatasetZones}); !errors.Is(err, ErrNotFound) {
		t.Errorf("a first version's previous: %v", err)
	}
	beyond := v2.Version + 1_000_000
	if _, err := s.PreviousPublication(ctx, PublicationHead{Dataset: publication.DatasetZones, SupersedesVersion: &beyond}); !errors.Is(err, ErrNotFound) {
		t.Errorf("a version that does not exist: %v", err)
	}

	fcs, err := s.FeatureChanges(ctx, v2.PublicationID, v1.PublicationID, 100)
	if err != nil {
		t.Fatal(err)
	}
	ops := map[string]FeatureChange{}
	for _, c := range fcs {
		ops[c.FeatureID] = c
	}
	if len(fcs) != 2 || ops[changed].Op != "changed" || ops[removed].Op != "removed" || len(ops[changed].Feature) == 0 ||
		len(ops[changed].Previous) == 0 || bytes.Equal(ops[changed].Feature, ops[changed].Previous) || ops[removed].Previous != nil {
		t.Errorf("feature changes %+v", fcs)
	}
	if !strings.Contains(string(ops[changed].Feature), "Renamed") || strings.Contains(string(ops[changed].Previous), "Renamed") {
		t.Error("the changed feature and its previous form are not the two versions'")
	}
	if fcs, _ := s.FeatureChanges(ctx, v2.PublicationID, "", 100); len(fcs) != 2 || fcs[0].Previous != nil || fcs[1].Previous != nil {
		t.Errorf("without the previous version %+v", fcs)
	}
	if fcs, _ := s.FeatureChanges(ctx, v2.PublicationID, v1.PublicationID, 1); len(fcs) != 1 {
		t.Errorf("limit 1: %d", len(fcs))
	}
}
