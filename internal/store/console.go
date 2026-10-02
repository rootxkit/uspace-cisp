package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store/relational"
)

// The console errors (WP-8).
var (
	// ErrUsernameTaken is a create with a username another account holds.
	ErrUsernameTaken = errors.New("store: the username is taken")
	// ErrSubscriptionState is a console action the subscription's status
	// does not allow (suspend a suspended one, resume an active one).
	ErrSubscriptionState = errors.New("store: the subscription's status does not allow this")
	// ErrNotCurrent is a republication of a version that is not its
	// dataset's current one.
	ErrNotCurrent = errors.New("store: the publication is not its dataset's current version")
)

// Account is one console account.
type Account struct {
	ID            string
	Username      string
	PasswordHash  string
	Role          string
	TOTPSecretEnc []byte
	MFARequired   bool
	Status        string
	CreatedAt     time.Time
	LastLoginAt   *time.Time
	FailedLogins  int
	LockedUntil   *time.Time
	TOTPLastStep  *int64
}

func accountOf(a relational.Account) Account {
	return Account{
		ID: a.ID, Username: a.Username, PasswordHash: a.PasswordHash, Role: a.Role, TOTPSecretEnc: a.TotpSecretEnc,
		MFARequired: a.MfaRequired, Status: a.Status, CreatedAt: a.CreatedAt.UTC(), LastLoginAt: utcPtr(a.LastLoginAt),
		FailedLogins: int(a.FailedLogins), LockedUntil: utcPtr(a.LockedUntil), TOTPLastStep: a.TotpLastStep,
	}
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// DatabaseNow is the database's clock.
func (s *Store) DatabaseNow(ctx context.Context) (time.Time, error) {
	now, err := relational.New(s.pool).ConsoleNow(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("database clock: %w", err)
	}
	return now.UTC(), nil
}

// AccountLoginUpdate is what a login writes to the account row.
type AccountLoginUpdate struct {
	FailedLogins int
	LockedUntil  *time.Time
	LastLoginAt  *time.Time
	PasswordHash string
	TOTPLastStep *int64
}

// NewSession is a sessions row.
type NewSession struct {
	JTI       string
	AccountID string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// LoginOutcome is what a login decided: the row update, the session to
// insert, the audit rows, and the refusal returned after the commit
// (the failed-login counter must be committed with it).
type LoginOutcome struct {
	Update  *AccountLoginUpdate
	Session *NewSession
	Events  []Event
	Refusal error
}

// Login runs decide on the account named username, locked FOR UPDATE
// (nil when there is none), with the database's clock, and writes its
// outcome in the same transaction. An error from decide rolls back and
// is returned; a refusal is committed with its update and events and
// then returned.
func (s *Store) Login(ctx context.Context, username string, decide func(a *Account, now time.Time) (LoginOutcome, error)) error {
	var refusal error
	err := s.Tx(ctx, func(q *relational.Queries) error {
		now, err := q.ConsoleNow(ctx)
		if err != nil {
			return fmt.Errorf("database clock: %w", err)
		}
		var acc *Account
		row, err := q.GetAccountByUsernameForUpdate(ctx, username)
		switch {
		case err == nil:
			a := accountOf(row)
			acc = &a
		case !errors.Is(err, pgx.ErrNoRows):
			return fmt.Errorf("account: %w", err)
		}
		out, err := decide(acc, now.UTC())
		if err != nil {
			return err
		}
		if out.Update != nil && acc != nil {
			u := out.Update
			if err := q.UpdateAccountLogin(ctx, relational.UpdateAccountLoginParams{
				ID: acc.ID, FailedLogins: int32(min(max(u.FailedLogins, 0), 1<<30)), LockedUntil: u.LockedUntil,
				LastLoginAt: u.LastLoginAt, PasswordHash: u.PasswordHash, TotpLastStep: u.TOTPLastStep,
			}); err != nil {
				return fmt.Errorf("account login: %w", err)
			}
		}
		for _, e := range out.Events {
			if _, err := AppendEvent(ctx, q, e); err != nil {
				return err
			}
		}
		if out.Session != nil {
			ns := out.Session
			if err := q.InsertSession(ctx, relational.InsertSessionParams{
				Jti: ns.JTI, AccountID: ns.AccountID, IssuedAt: ns.IssuedAt, ExpiresAt: ns.ExpiresAt,
			}); err != nil {
				return fmt.Errorf("insert session: %w", err)
			}
		}
		refusal = out.Refusal
		return nil
	})
	if err != nil {
		return err
	}
	return refusal
}

// CreateAccount inserts an account with its audit row.
func (s *Store) CreateAccount(ctx context.Context, a Account, e Event) error {
	return s.Tx(ctx, func(q *relational.Queries) error {
		if _, err := AppendEvent(ctx, q, e); err != nil {
			return err
		}
		err := q.InsertAccount(ctx, relational.InsertAccountParams{
			ID: a.ID, Username: a.Username, PasswordHash: a.PasswordHash, Role: a.Role, TotpSecretEnc: a.TOTPSecretEnc,
			MfaRequired: a.MFARequired, Status: a.Status, CreatedAt: a.CreatedAt,
		})
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return ErrUsernameTaken
		}
		if err != nil {
			return fmt.Errorf("insert account: %w", err)
		}
		return nil
	})
}

// Accounts are the accounts by username, at most limit.
func (s *Store) Accounts(ctx context.Context, limit int) ([]Account, error) {
	rows, err := relational.New(s.pool).ListAccounts(ctx, int32(min(max(limit, 0), 1<<20)))
	if err != nil {
		return nil, fmt.Errorf("accounts: %w", err)
	}
	out := make([]Account, 0, len(rows))
	for i := range rows {
		out = append(out, accountOf(rows[i]))
	}
	return out, nil
}

// Account is one account, or ErrNotFound.
func (s *Store) Account(ctx context.Context, id string) (Account, error) {
	r, err := relational.New(s.pool).GetAccount(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if err != nil {
		return Account{}, fmt.Errorf("account: %w", err)
	}
	return accountOf(r), nil
}

// AccountChange is what PatchAccount writes: the row as it becomes,
// whether to revoke the account's open sessions, and the audit row.
type AccountChange struct {
	Role           string
	Status         string
	MFARequired    bool
	TOTPSecretEnc  []byte
	TOTPLastStep   *int64
	RevokeSessions bool
	Event          Event
}

// PatchAccount runs decide on the account, locked FOR UPDATE after every
// active admin row (the last-admin invariant is judged under those
// locks), with the database's clock, and writes its change, the audit
// row and, when asked, the revocation of the account's open sessions,
// in one transaction. It returns the account as written and the revoked
// jtis; ErrNotFound when there is no such account.
func (s *Store) PatchAccount(ctx context.Context, id string, decide func(a Account, activeAdmins []string, now time.Time) (AccountChange, error)) (Account, []string, error) {
	var out Account
	var revoked []string
	err := s.Tx(ctx, func(q *relational.Queries) error {
		now, err := q.ConsoleNow(ctx)
		if err != nil {
			return fmt.Errorf("database clock: %w", err)
		}
		admins, err := q.LockActiveAdmins(ctx)
		if err != nil {
			return fmt.Errorf("lock admins: %w", err)
		}
		row, err := q.GetAccountForUpdate(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("account: %w", err)
		}
		acc := accountOf(row)
		ch, err := decide(acc, admins, now.UTC())
		if err != nil {
			return err
		}
		if _, err := AppendEvent(ctx, q, ch.Event); err != nil {
			return err
		}
		if err := q.UpdateAccount(ctx, relational.UpdateAccountParams{
			ID: id, Role: ch.Role, Status: ch.Status, MfaRequired: ch.MFARequired,
			TotpSecretEnc: ch.TOTPSecretEnc, TotpLastStep: ch.TOTPLastStep,
		}); err != nil {
			return fmt.Errorf("update account: %w", err)
		}
		if ch.RevokeSessions {
			if revoked, err = q.RevokeAccountSessions(ctx, id); err != nil {
				return fmt.Errorf("revoke sessions: %w", err)
			}
		}
		acc.Role, acc.Status, acc.MFARequired, acc.TOTPSecretEnc, acc.TOTPLastStep = ch.Role, ch.Status, ch.MFARequired, ch.TOTPSecretEnc, ch.TOTPLastStep
		out = acc
		return nil
	})
	return out, revoked, err
}

// Session is one sessions row.
type Session struct {
	JTI       string
	AccountID string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	// LastSeenAt is the last recorded use (written at most once a
	// minute per replica, see TouchSession).
	LastSeenAt time.Time
}

// Session is the row of jti, or ErrNotFound.
func (s *Store) Session(ctx context.Context, jti string) (Session, error) {
	r, err := relational.New(s.pool).GetSession(ctx, jti)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("session: %w", err)
	}
	return Session{JTI: r.Jti, AccountID: r.AccountID, IssuedAt: r.IssuedAt.UTC(), ExpiresAt: r.ExpiresAt.UTC(), RevokedAt: utcPtr(r.RevokedAt), LastSeenAt: r.LastSeenAt.UTC()}, nil
}

// RevokeSession revokes jti with its audit row; false when it was
// already revoked (nothing written).
func (s *Store) RevokeSession(ctx context.Context, jti string, e Event) (bool, error) {
	var done bool
	err := s.Tx(ctx, func(q *relational.Queries) error {
		n, err := q.RevokeSession(ctx, jti)
		if err != nil {
			return fmt.Errorf("revoke session: %w", err)
		}
		if n == 0 {
			return nil
		}
		done = true
		_, err = AppendEvent(ctx, q, e)
		return err
	})
	return done, err
}

// RevokedSessions are the revoked sessions that have not expired yet
// (the database's clock), at most limit.
func (s *Store) RevokedSessions(ctx context.Context, limit int) ([]string, error) {
	jtis, err := relational.New(s.pool).ListRevokedSessions(ctx, int32(min(max(limit, 0), 1<<20)))
	if err != nil {
		return nil, fmt.Errorf("revoked sessions: %w", err)
	}
	return jtis, nil
}

// TouchSession implements auth.ActivitySource: it moves last_seen_at to
// now (the database's clock) when jti is live, that is not revoked, not
// expired and last seen within idle, and says whether it was. false is a
// session that is over: idle past the timeout, revoked, expired or
// unknown. An idle session is never moved again, so it ends for good.
func (s *Store) TouchSession(ctx context.Context, jti string, idle time.Duration) (bool, error) {
	n, err := relational.New(s.pool).TouchSession(ctx, relational.TouchSessionParams{Jti: jti, IdleS: idle.Seconds()})
	if err != nil {
		return false, fmt.Errorf("touch session: %w", err)
	}
	return n == 1, nil
}

// SessionRevoked says whether jti is revoked or expired; a jti with no
// row is revoked (fail closed).
func (s *Store) SessionRevoked(ctx context.Context, jti string) (bool, error) {
	revoked, err := relational.New(s.pool).SessionRevoked(ctx, jti)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("session: %w", err)
	}
	return revoked, nil
}

// AuditRow is one events row.
type AuditRow struct {
	ID         int64
	TS         time.Time
	ActorType  string
	ActorID    string
	EventType  string
	EntityType string
	EntityID   string
	Payload    json.RawMessage
	PrevHash   []byte
	Hash       []byte
}

func auditOf(e relational.Event) AuditRow {
	return AuditRow{
		ID: e.ID, TS: e.Ts.UTC(), ActorType: e.ActorType, ActorID: e.ActorID, EventType: e.EventType,
		EntityType: e.EntityType, EntityID: e.EntityID, Payload: e.Payload, PrevHash: e.PrevHash, Hash: e.Hash,
	}
}

// AuditFilter selects audit rows; nil members do not filter.
type AuditFilter struct {
	Since     time.Time
	Actor     *string
	EventType *string
	// BeforeID pages: rows with a lower id (0: from the newest).
	BeforeID int64
	Limit    int
}

// AuditEvents are the rows the filter selects, newest first.
func (s *Store) AuditEvents(ctx context.Context, f AuditFilter) ([]AuditRow, error) {
	before := f.BeforeID
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := relational.New(s.pool).ListAuditEvents(ctx, relational.ListAuditEventsParams{
		BeforeID: before, Since: f.Since, Actor: f.Actor, EventType: f.EventType, MaxRows: int32(min(max(f.Limit, 0), 1<<20)),
	})
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	out := make([]AuditRow, 0, len(rows))
	for i := range rows {
		out = append(out, auditOf(rows[i]))
	}
	return out, nil
}

// auditPage is how many rows one query of EventsInRange reads.
const auditPage = 1000

// EventsInRange hands fn the rows from the first one at or after from to
// the last one before to, in chain (id) order, with the hash of the row
// before the first (nil when the first is the chain's first). Every row
// between the two ids is handed, whatever its ts, because the chain is
// by id.
func (s *Store) EventsInRange(ctx context.Context, from, to time.Time, fn func(prev []byte, r AuditRow) error) (int, error) {
	q := relational.New(s.pool)
	b, err := q.EventIDBounds(ctx, relational.EventIDBoundsParams{FromTs: from, ToTs: to})
	if err != nil {
		return 0, fmt.Errorf("audit range: %w", err)
	}
	if b.FirstID == 0 {
		return 0, nil
	}
	prev, err := q.EventHashBefore(ctx, b.FirstID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("audit range: %w", err)
	}
	n := 0
	next := b.FirstID
	for {
		rows, err := q.ListEventsByID(ctx, relational.ListEventsByIDParams{FirstID: next, LastID: b.LastID, MaxRows: auditPage})
		if err != nil {
			return n, fmt.Errorf("audit rows: %w", err)
		}
		for i := range rows {
			if err := fn(prev, auditOf(rows[i])); err != nil {
				return n, err
			}
			prev = rows[i].Hash
			n++
		}
		if len(rows) < auditPage {
			return n, nil
		}
		next = rows[len(rows)-1].ID + 1
	}
}

// PublicationHead is a version without its features.
type PublicationHead struct {
	ID                string
	Dataset           publication.Dataset
	Version           int64
	PublisherClientID string
	ReceivedAt        time.Time
	Body              []byte
	FeatureCount      int
	Added             int
	Changed           int
	Removed           int
	SupersedesVersion *int64
	Reason            publication.Reason
}

// PublicationByID is one version by its id, or ErrNotFound.
func (s *Store) PublicationByID(ctx context.Context, id string) (PublicationHead, error) {
	r, err := relational.New(s.pool).GetPublicationByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicationHead{}, ErrNotFound
	}
	if err != nil {
		return PublicationHead{}, fmt.Errorf("publication: %w", err)
	}
	return PublicationHead{
		ID: r.ID, Dataset: publication.Dataset(r.Dataset), Version: r.Version, PublisherClientID: r.PublisherClientID,
		ReceivedAt: r.ReceivedAt.UTC(), Body: r.Body, FeatureCount: int(r.FeatureCount), Added: int(r.Added),
		Changed: int(r.Changed), Removed: int(r.Removed), SupersedesVersion: r.SupersedesVersion, Reason: publication.Reason(r.Reason),
	}, nil
}

// PreviousPublication is the version a publication superseded, or
// ErrNotFound for a first version.
func (s *Store) PreviousPublication(ctx context.Context, p PublicationHead) (PublicationHead, error) {
	if p.SupersedesVersion == nil || *p.SupersedesVersion < 1 {
		return PublicationHead{}, ErrNotFound
	}
	id, err := relational.New(s.pool).GetPublicationIDByVersion(ctx, relational.GetPublicationIDByVersionParams{Dataset: string(p.Dataset), Version: *p.SupersedesVersion})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicationHead{}, ErrNotFound
	}
	if err != nil {
		return PublicationHead{}, fmt.Errorf("previous publication: %w", err)
	}
	return s.PublicationByID(ctx, id)
}

// FeatureChange is one feature a version added, changed or removed:
// the feature as the version holds it and, for a changed one, as the
// previous version held it (a removed row carries the last feature).
type FeatureChange struct {
	FeatureID string
	Op        string
	Feature   json.RawMessage
	Previous  json.RawMessage
}

// FeatureChanges are the features publication pubID added, changed or
// removed against prevID (empty for a first version), by identifier, at
// most limit.
func (s *Store) FeatureChanges(ctx context.Context, pubID, prevID string, limit int) ([]FeatureChange, error) {
	q := relational.New(s.pool)
	rows, err := q.ListChangedFeatures(ctx, relational.ListChangedFeaturesParams{PublicationID: pubID, MaxRows: int32(min(max(limit, 0), 1<<20))})
	if err != nil {
		return nil, fmt.Errorf("changed features: %w", err)
	}
	out := make([]FeatureChange, 0, len(rows))
	var changed []string
	for _, r := range rows {
		out = append(out, FeatureChange{FeatureID: r.FeatureID, Op: r.Op, Feature: r.Feature})
		if r.Op == "changed" {
			changed = append(changed, r.FeatureID)
		}
	}
	if len(changed) == 0 || prevID == "" {
		return out, nil
	}
	prev, err := q.ListFeaturesByIDs(ctx, relational.ListFeaturesByIDsParams{PublicationID: prevID, Ids: changed})
	if err != nil {
		return nil, fmt.Errorf("previous features: %w", err)
	}
	byID := make(map[string]json.RawMessage, len(prev))
	for _, p := range prev {
		byID[p.FeatureID] = p.Feature
	}
	for i := range out {
		if out[i].Op == "changed" {
			out[i].Previous = byID[out[i].FeatureID]
		}
	}
	return out, nil
}

// SubscriptionFilter selects subscriptions for the console.
type SubscriptionFilter struct {
	Status         *string
	IncludeDeleted bool
	AfterID        string
	Limit          int
}

// AllSubscriptions are every client's subscriptions the filter selects,
// by id, with the number of their deliveries per state.
func (s *Store) AllSubscriptions(ctx context.Context, f SubscriptionFilter) ([]SubscriptionRecord, map[string]map[string]int64, error) {
	q := relational.New(s.pool)
	rows, err := q.ListAllSubscriptions(ctx, relational.ListAllSubscriptionsParams{
		AfterID: f.AfterID, IncludeDeleted: f.IncludeDeleted || f.Status != nil, Status: f.Status, MaxRows: int32(min(max(f.Limit, 0), 1<<20)),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("subscriptions: %w", err)
	}
	out := make([]SubscriptionRecord, 0, len(rows))
	ids := make([]string, 0, len(rows))
	for i := range rows {
		out = append(out, subscriptionOf(relational.GetSubscriptionRow(rows[i])))
		ids = append(ids, rows[i].ID)
	}
	sums := make(map[string]map[string]int64, len(rows))
	if len(ids) == 0 {
		return out, sums, nil
	}
	counts, err := q.DeliverySummaries(ctx, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("delivery summaries: %w", err)
	}
	for _, c := range counts {
		m := sums[c.SubscriptionID]
		if m == nil {
			m = map[string]int64{}
			sums[c.SubscriptionID] = m
		}
		m[c.State] = c.N
	}
	return out, sums, nil
}

// SuspendSubscriptionAudited suspends an active or pending subscription
// for the console: the audit row first, then the status, in one
// transaction. ErrNotFound for none or a deleted one,
// ErrSubscriptionState for a suspended one.
func (s *Store) SuspendSubscriptionAudited(ctx context.Context, id, reason string, e Event) error {
	return s.Tx(ctx, func(q *relational.Queries) error {
		st, err := q.GetSubscriptionStatusForUpdate(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) || st == "deleted" {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("subscription: %w", err)
		}
		if st == "suspended" {
			return ErrSubscriptionState
		}
		if _, err := AppendEvent(ctx, q, e); err != nil {
			return err
		}
		if err := q.ConsoleSuspendSubscription(ctx, relational.ConsoleSuspendSubscriptionParams{ID: id, Reason: &reason}); err != nil {
			return fmt.Errorf("suspend: %w", err)
		}
		return nil
	})
}

// ResumeSubscriptionAudited returns a suspended subscription to
// pending_verification with a new verification ping (pingID), the audit
// row first. ErrNotFound for none or a deleted one, ErrSubscriptionState
// for one that is not suspended.
func (s *Store) ResumeSubscriptionAudited(ctx context.Context, id, pingID string, e Event) error {
	return s.Tx(ctx, func(q *relational.Queries) error {
		st, err := q.GetSubscriptionStatusForUpdate(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) || st == "deleted" {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("subscription: %w", err)
		}
		if st != "suspended" {
			return ErrSubscriptionState
		}
		if _, err := AppendEvent(ctx, q, e); err != nil {
			return err
		}
		if err := q.ConsoleResumeSubscription(ctx, id); err != nil {
			return fmt.Errorf("resume: %w", err)
		}
		if err := q.InsertPingDelivery(ctx, relational.InsertPingDeliveryParams{ID: pingID, SubscriptionID: id, CreatedAt: e.TS}); err != nil {
			return fmt.Errorf("insert ping: %w", err)
		}
		return nil
	})
}

// Republish announces the current version of a dataset again (spec 01
// section 2, docs/PLAN.md section 15 Q13): under the dataset's lock, the
// audit row, then a changes row with reason republished, the version and
// publication of the current version, no feature ids and no box (the
// whole dataset), committed and published to the bus as every change is
// (D6). No publications, features, features_current or snapshots row is
// written. ErrNotFound when pubID is no version, ErrNotCurrent when it is
// not the current one.
func (s *Store) Republish(ctx context.Context, pubID string, e Event) (publication.Change, error) {
	var change publication.Change
	err := s.Tx(ctx, func(q *relational.Queries) error {
		p, err := q.GetPublicationByID(ctx, pubID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("publication: %w", err)
		}
		if err := q.LockDataset(ctx, p.Dataset); err != nil {
			return fmt.Errorf("lock %s: %w", p.Dataset, err)
		}
		d, err := q.GetDataset(ctx, p.Dataset)
		if err != nil {
			return fmt.Errorf("dataset %s: %w", p.Dataset, err)
		}
		if d.CurrentVersion != p.Version {
			return ErrNotCurrent
		}
		now, err := q.ConsoleNow(ctx)
		if err != nil {
			return fmt.Errorf("database clock: %w", err)
		}
		e.TS = now.UTC()
		if e.Payload == nil {
			e.Payload = map[string]any{}
		}
		e.Payload["dataset"], e.Payload["version"] = p.Dataset, p.Version
		if _, err := AppendEvent(ctx, q, e); err != nil {
			return err
		}
		change = publication.Change{
			Dataset: publication.Dataset(p.Dataset), Version: p.Version, FeatureIDs: []string{}, RemovedIDs: []string{},
			Reason: publication.ReasonRepublished, At: now.UTC().Truncate(time.Microsecond),
		}
		if change.ID, err = insertChange(ctx, q, change, &p.ID); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return publication.Change{}, err
	}
	s.publish(ctx, change)
	return change, nil
}

// EnsureEventPartitions creates the monthly partitions of events (UTC
// months) from the month holding the database's now through months
// ahead, each insert-only for cisp_api as 0006_events made the first two
// (spec 06 T7), and returns the ones it created. A partition that
// exists is left as it is. Run monthly (docs/RUNBOOKS/console.md).
func (s *Store) EnsureEventPartitions(ctx context.Context, months int) ([]string, error) {
	if months < 0 || months > 120 {
		return nil, fmt.Errorf("partitions: %d months is outside 0..120", months)
	}
	now, err := s.DatabaseNow(ctx)
	if err != nil {
		return nil, err
	}
	var created []string
	first := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i <= months; i++ {
		from := first.AddDate(0, i, 0)
		to := from.AddDate(0, 1, 0)
		name := fmt.Sprintf("events_y%04dm%02d", from.Year(), int(from.Month()))
		var exists bool
		if err := s.pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
			return created, fmt.Errorf("partition %s: %w", name, err)
		}
		if exists {
			continue
		}
		// The name and the bounds are made here from integers and a
		// time, never from input; one transaction per partition, so a
		// partition is never left without its revoke.
		ident := pgx.Identifier{name}.Sanitize() //nolint:misspell // pgx's method
		err := s.tx(ctx, func(tx pgx.Tx, _ *relational.Queries) error {
			for _, st := range []string{
				fmt.Sprintf(`CREATE TABLE %s PARTITION OF events FOR VALUES FROM ('%s') TO ('%s')`, ident, from.Format(time.RFC3339), to.Format(time.RFC3339)),
				fmt.Sprintf(`REVOKE UPDATE, DELETE, TRUNCATE ON %s FROM PUBLIC, cisp_api`, ident),
			} {
				if _, err := tx.Exec(ctx, st); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return created, fmt.Errorf("partition %s: %w", name, err)
		}
		created = append(created, name)
	}
	return created, nil
}
