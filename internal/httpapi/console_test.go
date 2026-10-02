package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/rootxkit/uspace-cisp/internal/auth"
	"github.com/rootxkit/uspace-cisp/internal/console"
	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// seedConsole puts two zones versions with a diff, a USSP list pair, a
// subscription with a delivery and audit rows into the fakes.
func seedConsole(t *testing.T, h *pubHarness) {
	t.Helper()
	f, c := h.fake, h.cfake
	now := time.Now().UTC().Truncate(time.Second)
	one := int64(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	for v := int64(1); v <= 2; v++ {
		f.versions = append(f.versions, store.Version{ID: fmt.Sprintf("PUB-%d", v), Dataset: publication.DatasetZones, Version: v,
			PublisherClientID: authorityID, ReceivedAt: now, FeatureCount: 2, Reason: publication.ReasonPublication})
	}
	c.pubs["PUB-1"] = store.PublicationHead{ID: "PUB-1", Dataset: publication.DatasetZones, Version: 1, PublisherClientID: authorityID, ReceivedAt: now, FeatureCount: 2, Added: 2, Reason: publication.ReasonPublication}
	c.pubs["PUB-2"] = store.PublicationHead{ID: "PUB-2", Dataset: publication.DatasetZones, Version: 2, PublisherClientID: authorityID, ReceivedAt: now,
		FeatureCount: 2, Added: 1, Changed: 1, Removed: 1, SupersedesVersion: &one, Reason: publication.ReasonPublication}
	c.current[publication.DatasetZones] = "PUB-2"
	c.changes["PUB-2"] = []store.FeatureChange{
		{FeatureID: "Z1", Op: "changed", Feature: json.RawMessage(`{"identifier":"Z1","name":"B","lower":{"m":30}}`), Previous: json.RawMessage(`{"identifier":"Z1","name":"A","lower":{"m":30}}`)},
		{FeatureID: "Z2", Op: "removed", Feature: json.RawMessage(`{"identifier":"Z2"}`)},
		{FeatureID: "Z3", Op: "added", Feature: json.RawMessage(`{"identifier":"Z3"}`)},
	}
	c.pubs["PUB-U1"] = store.PublicationHead{ID: "PUB-U1", Dataset: publication.DatasetUSSPList, Version: 1, ReceivedAt: now, Body: []byte(`{"ussps":[{"ussp_id":"A","status":"operating"}]}`), Reason: publication.ReasonPublication}
	c.pubs["PUB-U2"] = store.PublicationHead{ID: "PUB-U2", Dataset: publication.DatasetUSSPList, Version: 2, ReceivedAt: now, SupersedesVersion: &one,
		Body: []byte(`{"ussps":[{"ussp_id":"A","status":"suspended"}]}`), Reason: publication.ReasonPublication}
	f.sb().rows["SUB-1"] = &store.SubscriptionRecord{Subscription: subscription.Subscription{
		ID: "SUB-1", ClientID: "ussp-geo1-01", CallbackURL: "https://ussp.example.ge/v1/cis/notifications",
		Datasets: []publication.Dataset{publication.DatasetZones}, Status: subscription.Active,
	}, CreatedAt: now}
	f.sb().deliveries["DEL-1"] = &store.DeliveryRecord{ID: "DEL-1", SubscriptionID: "SUB-1", Reason: publication.ReasonPublication, State: store.DeliveryDelivered, Attempts: 1, CreatedAt: now}
	for i := int64(1); i <= 3; i++ {
		c.audit = append(c.audit, store.AuditRow{ID: i, TS: now, ActorType: "account", ActorID: "acc-" + fmt.Sprint(i%2), EventType: "console_republish",
			EntityType: "publication", EntityID: "PUB-2", Payload: json.RawMessage(`{"reason":"r"}`), Hash: []byte{byte(i)}, PrevHash: []byte{byte(i - 1)}})
	}
}

func setSubStatus(h *pubHarness, id string, st subscription.Status) {
	h.fake.mu.Lock()
	defer h.fake.mu.Unlock()
	h.fake.sb().rows[id].Status = st
}

// consoleOp is one console operation of api/openapi.yaml with its
// x-role.
type consoleOp struct {
	method, path, role string
}

func consoleOps(t *testing.T) []consoleOp {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var out []consoleOp
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if len(op.Tags) != 1 || op.Tags[0] != "console" {
				continue
			}
			role, _ := op.Extensions["x-role"].(string)
			out = append(out, consoleOp{method: method, path: path, role: role})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path+out[i].method < out[j].path+out[j].method })
	return out
}

// Every console operation of the spec carries x-role, its description
// names the role, and ConsoleRoles (what the router enforces) says the
// same; every one is under /v1/console/ with security consoleSession
// (the login has none).
func TestConsoleRolesMatchTheSpec(t *testing.T) {
	ops := consoleOps(t)
	if len(ops) != len(ConsoleRoles)+1 {
		t.Fatalf("%d console operations in the spec, %d roles in the code (+ the login)", len(ops), len(ConsoleRoles))
	}
	for _, op := range ops {
		pattern := op.method + " " + op.path
		if !strings.HasPrefix(op.path, "/v1/console/") {
			t.Errorf("%s: a console operation outside /v1/console/", pattern)
		}
		if pattern == ConsoleLoginRoute {
			if op.role != "none" {
				t.Errorf("login x-role %q", op.role)
			}
			continue
		}
		if ConsoleRoles[pattern] != op.role {
			t.Errorf("%s: spec x-role %q, code %q", pattern, op.role, ConsoleRoles[pattern])
		}
	}
}

// Hard rule 2: no console handler reaches the publication transaction.
// The console's handler file and package must not name it at all.
func TestConsoleHasNoPathToContent(t *testing.T) {
	files := []string{"console.go"}
	pkg, err := filepath.Glob(filepath.Join("..", "console", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, pkg...)
	forbidden := regexp.MustCompile(`PublishTx|ApplyRestriction|RebuildCurrent|InsertPublication|InsertSnapshot|DeleteCurrentFeatures`)
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := forbidden.Find(src); m != nil {
			t.Errorf("%s names %s: the console has no write path to content", f, m)
		}
		checked++
	}
	if checked < 4 {
		t.Fatalf("only %d files checked", checked)
	}
	// The check catches what it is for (E-01).
	if forbidden.FindString("s.Store.PublishTx(ctx, in, signer)") == "" {
		t.Error("the pattern does not catch a call")
	}
}

type matrixCaller struct {
	name  string
	token func() string
	rank  int // -1 none, -2 machine
}

// The role matrix (docs/WORKPACKAGES/WP-8.md): every console operation of
// the spec × every caller kind. No token: 401. An ecosystem machine token
// (a USSP's cis.read): 403. A role below the operation's: 403. The role
// and above: the operation's success. The login answers 201 to anyone
// with the right credentials. Every exchange conforms to the spec.
func TestConsoleRoleMatrix(t *testing.T) {
	h := newPubHarness(t, nil)
	seedConsole(t, h)
	tokens := map[string]string{}
	for _, r := range auth.Roles {
		tokens[r], _ = h.consoleToken(t, r)
	}
	machine := h.token("ussp-geo1-01", auth.ScopeRead, auth.ScopePublishZones)
	callers := []matrixCaller{
		{"no token", func() string { return "" }, -1},
		{"machine cis.read", func() string { return machine }, -2},
	}
	for i, r := range auth.Roles {
		callers = append(callers, matrixCaller{r, func() string { return tokens[r] }, i})
	}
	target, _ := h.consoleToken(t, auth.RoleViewer)
	_ = target
	victim := h.consoleUser(t, auth.RoleViewer)
	var lines []string
	for _, op := range consoleOps(t) {
		pattern := op.method + " " + op.path
		need, _ := auth.RoleRank(op.role)
		row := fmt.Sprintf("%-68s %-16s", pattern, op.role)
		for _, c := range callers {
			path := strings.NewReplacer("{id}", idFor(op.path, victim.id), "{delivery_id}", "DEL-1").Replace(op.path)
			if op.path == "/v1/console/publications" {
				path += "?dataset=zones"
			}
			var body any
			switch {
			case pattern == ConsoleLoginRoute:
				body = h.loginBody(t, h.consoleUser(t, auth.RoleViewer), 0)
			case pattern == "POST /v1/console/accounts":
				body = map[string]any{"username": fmt.Sprintf("made-%d-%s", time.Now().UnixNano()%1e9, strings.ReplaceAll(c.name, " ", "-")), "role": "viewer"}
			case pattern == "PATCH /v1/console/accounts/{id}":
				body = map[string]any{"reset_mfa": false}
			case op.method == http.MethodPost:
				body = map[string]any{"reason": "the role matrix"}
			}
			if strings.HasSuffix(op.path, "/suspend") {
				setSubStatus(h, "SUB-1", subscription.Active)
			}
			if strings.HasSuffix(op.path, "/resume") {
				setSubStatus(h, "SUB-1", subscription.Suspended)
			}
			tok := c.token()
			if pattern == "DELETE /v1/console/session" && c.rank >= 0 {
				tok, _ = h.consoleToken(t, auth.Roles[c.rank])
			}
			rec := h.consoleDo(t, h.consoleReq(op.method, path, tok, body))
			var want string
			switch {
			case pattern == ConsoleLoginRoute:
				want = "2xx"
			case c.rank == -1:
				want = "401"
			case c.rank == -2 || c.rank < need:
				want = "403"
			default:
				want = "2xx"
			}
			got := fmt.Sprint(rec.Code)
			if rec.Code >= 200 && rec.Code < 300 {
				got = "2xx"
			}
			if got != want {
				t.Errorf("%s as %s: %d %s, want %s", pattern, c.name, rec.Code, rec.Body.String(), want)
			}
			row += fmt.Sprintf(" %s=%d", c.name, rec.Code)
		}
		lines = append(lines, row)
	}
	t.Logf("console role matrix (operation, x-role, status per caller):\n%s", strings.Join(lines, "\n"))
}

func idFor(path, accountID string) string {
	switch {
	case strings.HasPrefix(path, "/v1/console/accounts/"):
		return accountID
	case strings.HasPrefix(path, "/v1/console/publications/"):
		return "PUB-2"
	}
	return "SUB-1"
}

// A console session opens no content route: every operation of the
// publications and restrictions tags (and the machine reads) answers a
// console session of every role 403, admin included (Annex III B(5)).
func TestConsoleSessionOpensNoContentRoute(t *testing.T) {
	h := newPubHarness(t, nil)
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(filepath.Join("..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range auth.Roles {
		tok, _ := h.consoleToken(t, r)
		for path, item := range doc.Paths.Map() {
			for method, op := range item.Operations() {
				if len(op.Tags) != 1 || (op.Tags[0] != "publications" && op.Tags[0] != "restrictions") {
					continue
				}
				p := strings.NewReplacer("{dataset}", "zones", "{id}", "R1").Replace(path)
				req := h.consoleReq(method, p, tok, map[string]any{})
				rec := httptestDo(h, req)
				if rec.Code != http.StatusForbidden {
					t.Errorf("%s %s as console %s: %d %s", method, path, r, rec.Code, rec.Body.String())
				}
				lines = append(lines, fmt.Sprintf("%-6s %-44s %-16s %d", method, path, r, rec.Code))
			}
		}
	}
	sort.Strings(lines)
	t.Logf("content routes with a console session:\n%s", strings.Join(lines, "\n"))
	// The pair: the authority's machine token on the same route is not 403.
	rec := httptestDo(h, h.consoleReq(http.MethodGet, "/v1/publications/zones", h.authorityToken(), nil))
	if rec.Code != http.StatusOK {
		t.Errorf("the authority on its history: %d %s", rec.Code, rec.Body.String())
	}
}

func TestConsoleLogin(t *testing.T) {
	h := newPubHarness(t, nil)
	u := h.consoleUser(t, auth.RoleAdmin)
	// No TOTP: 401 mfa_required.
	body := map[string]any{"username": u.username, "password": u.password}
	rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", body))
	if rec.Code != http.StatusUnauthorized || decodeProblem(t, rec).Type != ProblemTypeBase+console.SlugMFARequired {
		t.Fatalf("no totp: %d %s", rec.Code, rec.Body.String())
	}
	good := h.loginBody(t, u, 0)
	rec = h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", good))
	if rec.Code != http.StatusCreated {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	s := decodeJSON[gen.ConsoleSession](t, rec)
	if s.Account.Role != "admin" || !s.Account.MfaEnrolled || s.Token == "" {
		t.Errorf("session %+v", s)
	}
	// The same code again: totp_reused.
	rec = h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", good))
	if rec.Code != http.StatusUnauthorized || decodeProblem(t, rec).Type != ProblemTypeBase+console.SlugTOTPReused {
		t.Errorf("reused: %d %s", rec.Code, rec.Body.String())
	}
	// Me with the token, then logout, then the token is refused at once.
	me := h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/me", s.Token, nil))
	if me.Code != http.StatusOK || decodeJSON[gen.ConsoleMe](t, me).Account.Username != u.username {
		t.Fatalf("me: %d %s", me.Code, me.Body.String())
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodDelete, "/v1/console/session", s.Token, nil)); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/me", s.Token, nil))
	if rec.Code != http.StatusUnauthorized || decodeProblem(t, rec).Type != ProblemTypeBase+auth.SlugSessionRevoked {
		t.Errorf("after logout: %d %s", rec.Code, rec.Body.String())
	}
	// Five wrong passwords lock; the sixth with the right one is 423.
	v := h.consoleUser(t, auth.RoleViewer)
	for i := 0; i < 5; i++ {
		rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", map[string]any{"username": v.username, "password": "wrong"}))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, rec.Code)
		}
	}
	rec = h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", h.loginBody(t, v, 0)))
	if rec.Code != http.StatusLocked || rec.Header().Get("Retry-After") != "900" {
		t.Errorf("locked: %d %q %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
	// Not JSON: 415.
	req := h.consoleReq(http.MethodPost, "/v1/console/session", "", body)
	req.Header.Set("Content-Type", "text/plain")
	if rec := httptestDo(h, req); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain: %d", rec.Code)
	}
	// Over the console cap: 413 (E-10).
	big := map[string]any{"username": "x", "password": strings.Repeat("p", MaxConsoleBodyBytes)}
	if rec := httptestDo(h, h.consoleReq(http.MethodPost, "/v1/console/session", "", big)); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("over the cap: %d", rec.Code)
	}
}

// The login limit: 20 attempts per address per 15 minutes; the 21st
// is 429 with Retry-After; another address is not limited (E-01, E-10).
func TestConsoleLoginRateLimit(t *testing.T) {
	h := newPubHarness(t, nil)
	body := map[string]any{"username": "nobody", "password": "x"}
	for i := 0; i < LoginBurst; i++ {
		if rec := httptestDo(h, h.consoleReq(http.MethodPost, "/v1/console/session", "", body)); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, rec.Code)
		}
	}
	rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/session", "", body))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("21st: %d %s", rec.Code, rec.Body.String())
	}
	other := h.consoleReq(http.MethodPost, "/v1/console/session", "", body)
	other.RemoteAddr = "198.51.100.7:1"
	if rec := httptestDo(h, other); rec.Code != http.StatusUnauthorized {
		t.Errorf("another address: %d", rec.Code)
	}
}

func TestConsoleAccountsAdmin(t *testing.T) {
	h := newPubHarness(t, nil)
	admin, au := h.consoleToken(t, auth.RoleAdmin)
	rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/accounts", admin, map[string]any{"username": "new.admin", "role": "admin"}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	created := decodeJSON[gen.ConsoleAccountCreated](t, rec)
	if created.TotpUri == nil || created.InitialPassword == "" || !created.Account.MfaRequired {
		t.Errorf("created %+v", created)
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/accounts", admin, map[string]any{"username": "new.admin", "role": "viewer"})); rec.Code != http.StatusConflict {
		t.Errorf("duplicate: %d", rec.Code)
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/accounts", admin, map[string]any{"username": "a b", "role": "viewer"})); rec.Code != http.StatusBadRequest {
		t.Errorf("bad username: %d", rec.Code)
	}
	list := decodeJSON[gen.ConsoleAccountList](t, h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/accounts", admin, nil)))
	if len(list.Accounts) != 2 {
		t.Errorf("listed %d", len(list.Accounts))
	}
	// Demote the other admin: allowed (two admins); then the last one
	// cannot demote itself.
	rec = h.consoleDo(t, h.consoleReq(http.MethodPatch, "/v1/console/accounts/"+created.Account.Id, admin, map[string]any{"role": "viewer", "reset_mfa": true}))
	p := decodeJSON[gen.ConsoleAccountPatched](t, rec)
	if rec.Code != http.StatusOK || p.Account.Role != "viewer" || p.TotpUri == nil {
		t.Fatalf("demote: %d %s", rec.Code, rec.Body.String())
	}
	rec = h.consoleDo(t, h.consoleReq(http.MethodPatch, "/v1/console/accounts/"+au.id, admin, map[string]any{"status": "disabled"}))
	if rec.Code != http.StatusConflict || decodeProblem(t, rec).Type != ProblemTypeBase+console.SlugLastAdmin {
		t.Errorf("last admin: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodPatch, "/v1/console/accounts/nobody", admin, map[string]any{"status": "disabled"})); rec.Code != http.StatusNotFound {
		t.Errorf("no account: %d", rec.Code)
	}
	// Disabling a logged-in viewer revokes its session at once.
	viewer, vu := h.consoleToken(t, auth.RoleViewer)
	rec = h.consoleDo(t, h.consoleReq(http.MethodPatch, "/v1/console/accounts/"+vu.id, admin, map[string]any{"status": "disabled"}))
	if p := decodeJSON[gen.ConsoleAccountPatched](t, rec); rec.Code != http.StatusOK || p.SessionsRevoked != 1 {
		t.Errorf("disable: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/status", viewer, nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("a disabled account's session: %d", rec.Code)
	}
	if n := countConsoleEvents(h, console.EventAccountCreated); n < 3 {
		t.Errorf("%d account_created rows", n)
	}
}

func countConsoleEvents(h *pubHarness, typ string) int {
	n := 0
	for _, e := range h.accounts.Events() {
		if e.EventType == typ {
			n++
		}
	}
	h.cfake.mu.Lock()
	defer h.cfake.mu.Unlock()
	for _, e := range h.cfake.events {
		if e.EventType == typ {
			n++
		}
	}
	for _, e := range h.fake.sb().events {
		if e.EventType == typ {
			n++
		}
	}
	return n
}

func TestConsoleReads(t *testing.T) {
	h := newPubHarness(t, nil)
	seedConsole(t, h)
	tok, _ := h.consoleToken(t, auth.RoleViewer)
	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		return h.consoleDo(t, h.consoleReq(http.MethodGet, path, tok, nil))
	}
	pl := decodeJSON[gen.ConsolePublicationList](t, get("/v1/console/publications?dataset=zones&limit=1"))
	if len(pl.Versions) != 1 || pl.Versions[0].Id != "PUB-2" || pl.NextBefore == nil || *pl.NextBefore != 2 {
		t.Errorf("versions %+v", pl)
	}
	if rec := httptestDo(h, h.consoleReq(http.MethodGet, "/v1/console/publications?dataset=zones&before=0", tok, nil)); rec.Code != http.StatusBadRequest {
		t.Errorf("before 0: %d", rec.Code)
	}
	// The diff: added, changed with its paths, removed.
	d := decodeJSON[gen.ConsolePublicationDiff](t, get("/v1/console/publications/PUB-2/diff"))
	if d.PreviousVersion == nil || *d.PreviousVersion != 1 || len(d.Features) != 3 || d.Truncated {
		t.Fatalf("diff %+v", d)
	}
	ch := d.Features[0]
	if ch.Op != "changed" || ch.Paths == nil || len(*ch.Paths) != 1 || (*ch.Paths)[0].Path != "/name" || d.Features[1].Op != "removed" || d.Features[2].Op != "added" {
		t.Errorf("features %+v", d.Features)
	}
	if d := decodeJSON[gen.ConsolePublicationDiff](t, get("/v1/console/publications/PUB-2/diff?limit=2")); !d.Truncated || len(d.Features) != 2 {
		t.Errorf("limit 2: %+v", d)
	}
	if d := decodeJSON[gen.ConsolePublicationDiff](t, get("/v1/console/publications/PUB-1/diff")); d.PreviousVersion != nil {
		t.Errorf("first version: %+v", d)
	}
	u := decodeJSON[gen.ConsolePublicationDiff](t, get("/v1/console/publications/PUB-U2/diff"))
	if u.BodyPaths == nil || len(*u.BodyPaths) != 1 || (*u.BodyPaths)[0].Path != "/ussps/0/status" {
		t.Errorf("ussp list diff %+v", u)
	}
	if rec := get("/v1/console/publications/NOPE/diff"); rec.Code != http.StatusNotFound {
		t.Errorf("no publication: %d", rec.Code)
	}
	if rec := httptestDo(h, h.consoleReq(http.MethodGet, "/v1/console/publications/PUB-2/diff?limit=6000", tok, nil)); rec.Code != http.StatusBadRequest {
		t.Errorf("limit past the bound: %d", rec.Code)
	}
	sl := decodeJSON[gen.ConsoleSubscriptionList](t, get("/v1/console/subscriptions"))
	if len(sl.Subscriptions) != 1 || sl.Subscriptions[0].Deliveries.Delivered != 1 || sl.Subscriptions[0].Subscription.ClientId != "ussp-geo1-01" {
		t.Errorf("subscriptions %+v", sl)
	}
	if sl := decodeJSON[gen.ConsoleSubscriptionList](t, get("/v1/console/subscriptions?status=suspended")); len(sl.Subscriptions) != 0 {
		t.Errorf("suspended %+v", sl)
	}
	dl := decodeJSON[gen.DeliveryList](t, get("/v1/console/subscriptions/SUB-1/deliveries"))
	if len(dl.Deliveries) != 1 {
		t.Errorf("deliveries %+v", dl)
	}
	if rec := get("/v1/console/subscriptions/NOPE/deliveries"); rec.Code != http.StatusNotFound {
		t.Errorf("no subscription: %d", rec.Code)
	}
	if rec := get("/v1/console/subscriptions/SUB-1/deliveries?since=yesterday"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad since: %d", rec.Code)
	}
	if rec := get("/v1/console/restrictions?state=active"); rec.Code != http.StatusOK {
		t.Errorf("restrictions: %d %s", rec.Code, rec.Body.String())
	}
	st := decodeJSON[gen.ConsoleStatus](t, get("/v1/console/status"))
	if st.Counters["console.console_logins"] < 1 || st.Counters["console_auth.session_accepted"] < 1 {
		t.Errorf("counters %v", st.Counters)
	}
}

func TestConsoleAudit(t *testing.T) {
	h := newPubHarness(t, nil)
	seedConsole(t, h)
	admin, _ := h.consoleToken(t, auth.RoleAdmin)
	rec := h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/audit?limit=2", admin, nil))
	l := decodeJSON[gen.ConsoleAuditList](t, rec)
	if len(l.Events) != 2 || l.Events[0].Id != 3 || l.NextBeforeId == nil || *l.NextBeforeId != 2 || l.Events[0].PrevHash == nil {
		t.Fatalf("audit %+v", l)
	}
	l = decodeJSON[gen.ConsoleAuditList](t, h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/audit?actor=acc-1&type=console_republish", admin, nil)))
	if len(l.Events) != 2 {
		t.Errorf("filtered %+v", l)
	}
	l = decodeJSON[gen.ConsoleAuditList](t, h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/audit?before_id=2&since=2020-01-01T00:00:00Z", admin, nil)))
	if len(l.Events) != 1 || l.Events[0].Id != 1 {
		t.Errorf("paged %+v", l)
	}
	for _, q := range []string{"since=nope", "before_id=0", "limit=501"} {
		if rec := httptestDo(h, h.consoleReq(http.MethodGet, "/v1/console/audit?"+q, admin, nil)); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
}

// Every action is audited with actor, role, target and reason: the
// count of rows before and after each (E-01: a refused action writes
// none).
func TestConsoleActionsAudited(t *testing.T) {
	h := newPubHarness(t, nil)
	seedConsole(t, h)
	tok, u := h.consoleToken(t, auth.RolePublisherAdmin)
	reason := map[string]any{"reason": "operator asked"}
	act := func(method, path string, body any, wantStatus int, typ string, wantRows int) {
		t.Helper()
		before := countConsoleEvents(h, typ)
		rec := h.consoleDo(t, h.consoleReq(method, path, tok, body))
		if rec.Code != wantStatus {
			t.Fatalf("%s %s = %d %s", method, path, rec.Code, rec.Body.String())
		}
		if after := countConsoleEvents(h, typ); after-before != wantRows {
			t.Errorf("%s %s: %d audit rows, want %d", method, path, after-before, wantRows)
		}
	}
	act(http.MethodPost, "/v1/console/subscriptions/SUB-1/suspend", reason, http.StatusOK, EventConsoleSuspended, 1)
	act(http.MethodPost, "/v1/console/subscriptions/SUB-1/suspend", reason, http.StatusConflict, EventConsoleSuspended, 0)
	act(http.MethodPost, "/v1/console/subscriptions/SUB-1/resume", reason, http.StatusOK, EventConsoleResumed, 1)
	act(http.MethodPost, "/v1/console/subscriptions/SUB-1/resume", reason, http.StatusConflict, EventConsoleResumed, 0)
	act(http.MethodPost, "/v1/console/subscriptions/SUB-1/deliveries/DEL-1/retry", reason, http.StatusAccepted, EventConsoleRetried, 1)
	act(http.MethodPost, "/v1/console/subscriptions/SUB-1/deliveries/NOPE/retry", reason, http.StatusNotFound, EventConsoleRetried, 0)
	act(http.MethodPost, "/v1/console/publications/PUB-2/republish", reason, http.StatusAccepted, EventConsoleRepublish, 1)
	act(http.MethodPost, "/v1/console/publications/PUB-1/republish", reason, http.StatusConflict, EventConsoleRepublish, 0)
	act(http.MethodPost, "/v1/console/publications/NOPE/republish", reason, http.StatusNotFound, EventConsoleRepublish, 0)
	act(http.MethodPost, "/v1/console/subscriptions/NOPE/suspend", reason, http.StatusNotFound, EventConsoleSuspended, 0)
	act(http.MethodPost, "/v1/console/subscriptions/NOPE/resume", reason, http.StatusNotFound, EventConsoleResumed, 0)
	// Requests the spec refuses: served without the conformance check.
	for _, bad := range []map[string]any{{"reason": ""}, {"reason": strings.Repeat("r", 501)}, {}} {
		before := countConsoleEvents(h, EventConsoleSuspended)
		if rec := httptestDo(h, h.consoleReq(http.MethodPost, "/v1/console/subscriptions/SUB-1/suspend", tok, bad)); rec.Code != http.StatusBadRequest {
			t.Errorf("reason %v: %d", bad, rec.Code)
		}
		if countConsoleEvents(h, EventConsoleSuspended) != before {
			t.Errorf("reason %v: an audit row was written", bad)
		}
	}
	h.cfake.mu.Lock()
	e := h.cfake.events[0]
	h.cfake.mu.Unlock()
	if e.ActorID != u.id || e.Payload["actor_role"] != auth.RolePublisherAdmin || e.Payload["reason"] != "operator asked" || e.EntityID != "SUB-1" {
		t.Errorf("audit row %+v", e)
	}
	// The republished change: the current version, reason republished.
	rec := h.consoleDo(t, h.consoleReq(http.MethodPost, "/v1/console/publications/PUB-2/republish", tok, reason))
	c := decodeJSON[gen.Change](t, rec)
	if c.Reason != "republished" || c.Version != 2 || len(c.FeatureIds) != 0 {
		t.Errorf("change %+v", c)
	}
}

// A store that does not answer: 503 database_unavailable with
// Retry-After on the reads and the actions.
func TestConsoleStoreDown(t *testing.T) {
	h := newPubHarness(t, nil)
	seedConsole(t, h)
	tok, _ := h.consoleToken(t, auth.RoleAdmin)
	h.fake.mu.Lock()
	h.fake.down = true
	h.fake.mu.Unlock()
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/v1/console/publications?dataset=zones"},
		{http.MethodGet, "/v1/console/publications/PUB-2/diff"},
		{http.MethodGet, "/v1/console/subscriptions"},
		{http.MethodGet, "/v1/console/audit"},
		{http.MethodPost, "/v1/console/publications/PUB-2/republish"},
		{http.MethodPost, "/v1/console/subscriptions/SUB-1/suspend"},
	} {
		var body any
		if r.method == http.MethodPost {
			body = map[string]any{"reason": "x"}
		}
		rec := h.consoleDo(t, h.consoleReq(r.method, r.path, tok, body))
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
			t.Errorf("%s %s: %d %s", r.method, r.path, rec.Code, rec.Body.String())
		}
	}
	// The pair: the database back, the same read answers.
	h.fake.mu.Lock()
	h.fake.down = false
	h.fake.mu.Unlock()
	if rec := h.consoleDo(t, h.consoleReq(http.MethodGet, "/v1/console/subscriptions", tok, nil)); rec.Code != http.StatusOK {
		t.Errorf("back: %d", rec.Code)
	}
}

// Without the console configured, every console operation answers 503
// console_unavailable (fail closed), the login included.
func TestConsoleOff(t *testing.T) {
	routes := openRoutes()
	for k, v := range ConsoleOffRoutes() {
		routes[k] = v
	}
	f := newFixture(t, &Server{}, Options{RouteMiddleware: routes})
	for _, op := range consoleOps(t) {
		path := strings.NewReplacer("{id}", "X", "{delivery_id}", "Y").Replace(op.path)
		rec := f.do(httptest.NewRequest(op.method, path, http.NoBody))
		if rec.Code != http.StatusServiceUnavailable || decodeProblem(t, rec).Type != ProblemTypeBase+SlugConsoleUnavailable {
			t.Errorf("%s %s: %d", op.method, op.path, rec.Code)
		}
	}
	// And a server without its console behind open routes says so too.
	f = newFixture(t, &Server{}, Options{})
	if rec := f.do(httptest.NewRequest(http.MethodGet, "/v1/console/status", http.NoBody)); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no console: %d", rec.Code)
	}
}
