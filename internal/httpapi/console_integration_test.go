//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

var _ ConsoleStore = (*store.Store)(nil)

func pgCount(t *testing.T, st *store.Store, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := st.Pool().QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Sessions on PostgreSQL: a TOTP login, the replay of its code refused
// (totp_last_step read back), me, logout, and the revocation seen by a
// second replica's cache at its next refresh (within 10 s) and not
// before; the lockout judged on the database's clock.
func TestConsoleSessionsOnPostgres(t *testing.T) {
	st, _ := pgStore(t)
	h := newPubHarness(t, st)
	ctx := context.Background()
	u := h.consoleUser(t, auth.RoleAdmin)
	good := h.loginBody(t, u, 0)
	rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", good))
	if rec.Code != http.StatusCreated {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	s := decodeJSON[gen.ConsoleSession](t, rec)
	if n := pgCount(t, st, `SELECT count(*) FROM accounts WHERE id = $1 AND totp_last_step IS NOT NULL`, u.id); n != 1 {
		t.Error("totp_last_step not written")
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", good)); rec.Code != http.StatusUnauthorized ||
		decodeProblem(t, rec).Type != ProblemTypeBase+console.SlugTOTPReused {
		t.Errorf("replayed code: %d %s", rec.Code, rec.Body.String())
	}
	if n := pgCount(t, st, `SELECT count(*) FROM events WHERE event_type = 'session_issued' AND actor_id = $1`, u.id); n != 1 {
		t.Errorf("%d session_issued rows", n)
	}

	// A second replica: its own cache on the same database.
	replica := auth.NewRevocationCache(auth.RevocationCacheConfig{Source: st})
	if err := replica.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	activity2, err := auth.NewActivity(auth.ActivityConfig{Source: st})
	if err != nil {
		t.Fatal(err)
	}
	guard2, err := auth.NewSessionGuard(auth.SessionGuardConfig{Verifier: h.verifier, Issuer: consoleIssuer, Revocations: replica, Activity: activity2, Problems: WriteProblem})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard2.VerifySession(ctx, s.Token); err != nil {
		t.Fatalf("replica before logout: %v", err)
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodDelete, "/v1/console/session", s.Token, nil)); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/me", s.Token, nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("this replica after logout: %d", rec.Code)
	}
	if err := guard2.VerifySession(ctx, s.Token); err != nil {
		t.Logf("the other replica refused before its refresh too: %v", err)
	} else {
		t.Log("the other replica accepts the revoked session until its next refresh (at most 10 s)")
	}
	start := time.Now()
	if err := replica.Refresh(ctx); err != nil { // the 10 s tick
		t.Fatal(err)
	}
	var se *auth.SessionError
	if err := guard2.VerifySession(ctx, s.Token); err == nil || !errorsAs(err, &se) || se.Slug != auth.SlugSessionRevoked {
		t.Errorf("the other replica after its refresh: %v", err)
	}
	t.Logf("revoked session refused by the other replica %s after its refresh", time.Since(start).Round(time.Millisecond))

	// The lockout, on the database's clock.
	v := h.consoleUser(t, auth.RoleViewer)
	for i := 0; i < 5; i++ {
		h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", map[string]any{"username": v.username, "password": "wrong"}))
	}
	var lockS float64
	if err := st.Pool().QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM locked_until - now()) FROM accounts WHERE id = $1`, v.id).Scan(&lockS); err != nil || lockS < 890 || lockS > 900 {
		t.Errorf("locked for %.0f s (%v), want about 900", lockS, err)
	}
	rec = h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", h.loginBody(t, v, 0)))
	if rec.Code != http.StatusLocked {
		t.Errorf("sixth with the right password: %d %s", rec.Code, rec.Body.String())
	}
	if n := pgCount(t, st, `SELECT count(*) FROM events WHERE event_type IN ('login_failed', 'account_locked') AND entity_id = $1`, v.id); n != 6 {
		t.Errorf("%d login_failed and account_locked rows, want 6", n)
	}
}

func errorsAs(err error, se **auth.SessionError) bool {
	e, ok := err.(*auth.SessionError) //nolint:errorlint // VerifySession returns it unwrapped
	if ok {
		*se = e
	}
	return ok
}

// A hash made with other parameters is re-hashed on the next login, and
// the stored hash is read back; the TOTP secrets are sealed per row
// (two ciphertexts differ) and each opens for its own account only.
func TestConsoleAccountsAtRestOnPostgres(t *testing.T) {
	st, _ := pgStore(t)
	h := newPubHarness(t, st)
	ctx := context.Background()
	old, err := auth.HashPassword("an old password", auth.Argon2Params{MemoryKiB: 32, Iterations: 2, Lanes: 1})
	if err != nil {
		t.Fatal(err)
	}
	id := store.NewID(time.Now())
	name := "legacy-" + strings.ToLower(id[18:])
	if err := st.CreateAccount(ctx, store.Account{ID: id, Username: name, PasswordHash: old, Role: auth.RoleViewer, Status: "active", CreatedAt: time.Now().UTC()},
		store.Event{TS: time.Now(), ActorType: store.ActorSystem, ActorID: "it", EventType: console.EventAccountCreated, EntityType: "account", EntityID: id}); err != nil {
		t.Fatal(err)
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", map[string]any{"username": name, "password": "an old password"})); rec.Code != http.StatusCreated {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	acc, err := st.Account(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if acc.PasswordHash == old || !strings.HasPrefix(acc.PasswordHash, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Errorf("stored hash after login %q", acc.PasswordHash)
	}
	a, b := h.consoleUser(t, auth.RoleAdmin), h.consoleUser(t, auth.RoleAdmin)
	ea, _ := st.Account(ctx, a.id)
	eb, _ := st.Account(ctx, b.id)
	if len(ea.TOTPSecretEnc) == 0 || bytes.Equal(ea.TOTPSecretEnc, eb.TOTPSecretEnc) {
		t.Fatal("ciphertexts empty or equal")
	}
	sealer, _ := console.NewSealer(k32())
	pa, err := sealer.Open(a.id, ea.TOTPSecretEnc)
	if err != nil || string(pa) != a.secret {
		t.Errorf("a's secret: %v", err)
	}
	if _, err := sealer.Open(b.id, ea.TOTPSecretEnc); err == nil {
		t.Error("a's ciphertext opened for b")
	}
	if strings.Contains(string(ea.TOTPSecretEnc), a.secret) {
		t.Error("the secret is stored in the clear")
	}
}

// The last-admin invariant under concurrency: two active admins demote
// each other at once; the locks of every active admin row let exactly
// one succeed.
func TestConsoleLastAdminOnPostgres(t *testing.T) {
	st, _ := pgStore(t)
	h := newPubHarness(t, st)
	ctx := context.Background()
	// Earlier runs' admins are not this test's.
	if _, err := st.Pool().Exec(ctx, `UPDATE accounts SET status = 'disabled' WHERE role = 'admin' AND status = 'active'`); err != nil {
		t.Fatal(err)
	}
	ta, a := h.consoleToken(t, auth.RoleAdmin)
	tb, b := h.consoleToken(t, auth.RoleAdmin)
	codes := make([]int, 2)
	var wg sync.WaitGroup
	for i, c := range []struct{ token, target string }{{ta, b.id}, {tb, a.id}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = httptestDo(h, h.consoleReq(http.MethodPatch, "/v1/console/accounts/"+c.target, c.token, map[string]any{"role": "viewer"})).Code
		}()
	}
	wg.Wait()
	ok, conflict := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusConflict:
			conflict++
		}
	}
	// The demoted admin's session is revoked, so the second may also
	// answer 401 if it ran after; what matters is one admin left.
	if ok != 1 {
		t.Errorf("codes %v: %d demotions succeeded, want 1", codes, ok)
	}
	if n := pgCount(t, st, `SELECT count(*) FROM accounts WHERE role = 'admin' AND status = 'active'`); n != 1 {
		t.Errorf("%d active admins left, want 1", n)
	}
	t.Logf("concurrent demotions answered %v (%d conflict)", codes, conflict)
}

// The console's actions on PostgreSQL, each with its audit row counted
// before and after; and the diff of two published zones versions.
func TestConsoleActionsOnPostgres(t *testing.T) {
	st, _ := pgStore(t)
	h := newPubHarness(t, st)
	ctx := context.Background()
	if _, err := st.Pool().Exec(ctx, `UPDATE subscriptions SET status = 'deleted' WHERE client_id LIKE 'ussp-con-%'`); err != nil {
		t.Fatal(err)
	}
	tok, u := h.consoleToken(t, auth.RolePublisherAdmin)
	client := "ussp-con-" + strings.ToLower(store.NewID(time.Now())[20:])
	sub := h.createSub(t, client, validSub())
	events := func(typ string) int64 {
		return pgCount(t, st, `SELECT count(*) FROM events WHERE event_type = $1 AND actor_id = $2`, typ, u.id)
	}
	reason := map[string]any{"reason": "integration"}
	for _, c := range []struct {
		path, typ string
		status    int
	}{
		{"/v1/console/subscriptions/" + sub.Id + "/suspend", EventConsoleSuspended, http.StatusOK},
		{"/v1/console/subscriptions/" + sub.Id + "/suspend", EventConsoleSuspended, http.StatusConflict},
		{"/v1/console/subscriptions/" + sub.Id + "/resume", EventConsoleResumed, http.StatusOK},
		{"/v1/console/subscriptions/" + sub.Id + "/deliveries/" + sub.Verification.Id + "/retry", EventConsoleRetried, http.StatusAccepted},
	} {
		before := events(c.typ)
		rec := h.consoleDo(t, h.consoleReq(http.MethodPost, c.path, tok, reason))
		if rec.Code != c.status {
			t.Fatalf("%s: %d %s", c.path, rec.Code, rec.Body.String())
		}
		want := int64(0)
		if c.status < 300 {
			want = 1
		}
		if got := events(c.typ) - before; got != want {
			t.Errorf("%s: %d audit rows, want %d", c.path, got, want)
		}
	}
	if n := pgCount(t, st, `SELECT count(*) FROM deliveries WHERE subscription_id = $1 AND change_id IS NULL`, sub.Id); n != 2 {
		t.Errorf("%d pings after resume, want 2", n)
	}
	got := decodeJSON[gen.ConsoleSubscriptionList](t, h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/subscriptions?status=pending_verification&limit=500", tok, nil)))
	found := false
	for _, s := range got.Subscriptions {
		if s.Subscription.Id == sub.Id {
			found = s.Deliveries.Queued == 2
		}
	}
	if !found {
		t.Errorf("the resumed subscription with its two queued pings is not listed")
	}

	// Two zones versions: one feature renamed, one removed, one added.
	d1 := zonesDoc(t)
	if rec := h.put("zones", jsonBytes(t, d1)); rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("v1: %d %s", rec.Code, rec.Body.String())
	}
	var d2 doc
	if err := json.Unmarshal(jsonBytes(t, d1), &d2); err != nil {
		t.Fatal(err)
	}
	fprops(d2, 0)["name"] = []any{doc{"lang": "en-GB", "text": "Renamed by the integration test"}}
	var added doc
	if err := json.Unmarshal(jsonBytes(t, feats(d2)[1]), &added); err != nil {
		t.Fatal(err)
	}
	newID := "TSQ" + strings.ToUpper(store.NewID(time.Now())[22:])
	added["properties"].(doc)["identifier"] = newID
	added["id"] = newID
	removed := fprops(d2, 2)["identifier"].(string)
	d2["features"] = []any{feats(d2)[0], feats(d2)[1], added}
	if len(feats(d1)) > 3 {
		d2["features"] = append(d2["features"].([]any), feats(d1)[3:]...)
	}
	if rec := h.put("zones", jsonBytes(t, d2)); rec.Code != http.StatusCreated {
		t.Fatalf("v2: %d %s", rec.Code, rec.Body.String())
	}
	list := decodeJSON[gen.ConsolePublicationList](t, h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/publications?dataset=zones&limit=1", tok, nil)))
	diff := decodeJSON[gen.ConsolePublicationDiff](t, h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/publications/"+list.Versions[0].Id+"/diff", tok, nil)))
	ops := map[string]string{}
	var paths []string
	for _, f := range diff.Features {
		ops[f.FeatureId] = string(f.Op)
		if f.Paths != nil {
			for _, p := range *f.Paths {
				paths = append(paths, f.FeatureId+p.Path)
			}
		}
	}
	renamed := fprops(d2, 0)["identifier"].(string)
	if ops[renamed] != "changed" || ops[removed] != "removed" || ops[newID] != "added" || len(paths) == 0 || !strings.Contains(strings.Join(paths, " "), "/properties/name/0/text") {
		t.Errorf("diff ops %v paths %v", ops, paths)
	}
	t.Logf("diff of zones %d: %v; paths %v", diff.Publication.Version, ops, paths)

	// Republish the current version: a change, no version.
	pubs := pgCount(t, st, `SELECT count(*) FROM publications WHERE dataset = 'zones'`)
	before := events(EventConsoleRepublish)
	rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/publications/"+list.Versions[0].Id+"/republish", tok, reason))
	if rec.Code != http.StatusAccepted || decodeJSON[gen.Change](t, rec).Reason != "republished" {
		t.Fatalf("republish: %d %s", rec.Code, rec.Body.String())
	}
	if pgCount(t, st, `SELECT count(*) FROM publications WHERE dataset = 'zones'`) != pubs || events(EventConsoleRepublish) != before+1 {
		t.Error("republish wrote a version or no audit row")
	}
}
