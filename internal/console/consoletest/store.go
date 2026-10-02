// Package consoletest is an in-memory stand-in for the store's console
// accounts and sessions, with the same transactional contract as
// internal/store (a decision runs under the row's lock on the store's
// clock; a refusal is committed with its update and events). Only tests
// import it.
package consoletest

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/store"
)

// Store holds accounts, sessions and the audit rows written.
type Store struct {
	mu       sync.Mutex
	now      time.Time
	accounts map[string]store.Account
	sessions map[string]store.Session
	events   []store.Event
	// Fail, when set, is returned by every call (a database down).
	Fail error
}

// New is an empty store whose clock reads now.
func New(now time.Time) *Store {
	return &Store{now: now.UTC(), accounts: map[string]store.Account{}, sessions: map[string]store.Session{}}
}

// Advance moves the store's clock (the database's) by d.
func (s *Store) Advance(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = s.now.Add(d)
}

// Events are the audit rows written, oldest first.
func (s *Store) Events() []store.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.Event{}, s.events...)
}

// Append writes an audit row (for the fakes built on this one).
func (s *Store) Append(e store.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

// Put stores an account as it is.
func (s *Store) Put(a store.Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accounts[a.ID] = a
}

// Get is an account by id.
func (s *Store) Get(id string) (store.Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	return a, ok
}

// DatabaseNow implements console.Store.
func (s *Store) DatabaseNow(context.Context) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return time.Time{}, s.Fail
	}
	return s.now, nil
}

// Login implements console.Store.
func (s *Store) Login(_ context.Context, username string, decide func(a *store.Account, now time.Time) (store.LoginOutcome, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return s.Fail
	}
	var acc *store.Account
	for id := range s.accounts {
		if s.accounts[id].Username == username {
			c := s.accounts[id]
			acc = &c
		}
	}
	out, err := decide(acc, s.now)
	if err != nil {
		return err
	}
	if out.Update != nil && acc != nil {
		a := s.accounts[acc.ID]
		a.FailedLogins, a.LockedUntil, a.LastLoginAt = out.Update.FailedLogins, out.Update.LockedUntil, out.Update.LastLoginAt
		a.PasswordHash, a.TOTPLastStep = out.Update.PasswordHash, out.Update.TOTPLastStep
		s.accounts[acc.ID] = a
	}
	s.events = append(s.events, out.Events...)
	if out.Session != nil {
		ns := out.Session
		s.sessions[ns.JTI] = store.Session{JTI: ns.JTI, AccountID: ns.AccountID, IssuedAt: ns.IssuedAt, ExpiresAt: ns.ExpiresAt}
	}
	return out.Refusal
}

// CreateAccount implements console.Store.
func (s *Store) CreateAccount(_ context.Context, a store.Account, e store.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return s.Fail
	}
	for id := range s.accounts {
		if s.accounts[id].Username == a.Username {
			return store.ErrUsernameTaken
		}
	}
	s.accounts[a.ID] = a
	s.events = append(s.events, e)
	return nil
}

// Accounts implements console.Store.
func (s *Store) Accounts(_ context.Context, limit int) ([]store.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return nil, s.Fail
	}
	out := make([]store.Account, 0, len(s.accounts))
	for id := range s.accounts {
		out = append(out, s.accounts[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Account implements console.Store.
func (s *Store) Account(_ context.Context, id string) (store.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return store.Account{}, s.Fail
	}
	a, ok := s.accounts[id]
	if !ok {
		return store.Account{}, store.ErrNotFound
	}
	return a, nil
}

// PatchAccount implements console.Store.
func (s *Store) PatchAccount(_ context.Context, id string, decide func(a store.Account, activeAdmins []string, now time.Time) (store.AccountChange, error)) (store.Account, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return store.Account{}, nil, s.Fail
	}
	var admins []string
	for id := range s.accounts {
		if acc := s.accounts[id]; acc.Role == "admin" && acc.Status == "active" {
			admins = append(admins, id)
		}
	}
	sort.Strings(admins)
	a, ok := s.accounts[id]
	if !ok {
		return store.Account{}, nil, store.ErrNotFound
	}
	ch, err := decide(a, admins, s.now)
	if err != nil {
		return store.Account{}, nil, err
	}
	s.events = append(s.events, ch.Event)
	a.Role, a.Status, a.MFARequired, a.TOTPSecretEnc, a.TOTPLastStep = ch.Role, ch.Status, ch.MFARequired, ch.TOTPSecretEnc, ch.TOTPLastStep
	s.accounts[id] = a
	var revoked []string
	if ch.RevokeSessions {
		for j, sess := range s.sessions {
			if sess.AccountID == id && sess.RevokedAt == nil && sess.ExpiresAt.After(s.now) {
				t := s.now
				sess.RevokedAt = &t
				s.sessions[j] = sess
				revoked = append(revoked, j)
			}
		}
	}
	sort.Strings(revoked)
	return a, revoked, nil
}

// Session implements console.Store.
func (s *Store) Session(_ context.Context, jti string) (store.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return store.Session{}, s.Fail
	}
	sess, ok := s.sessions[jti]
	if !ok {
		return store.Session{}, store.ErrNotFound
	}
	return sess, nil
}

// RevokeSession implements console.Store.
func (s *Store) RevokeSession(_ context.Context, jti string, e store.Event) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return false, s.Fail
	}
	sess, ok := s.sessions[jti]
	if !ok || sess.RevokedAt != nil {
		return false, nil
	}
	t := s.now
	sess.RevokedAt = &t
	s.sessions[jti] = sess
	s.events = append(s.events, e)
	return true, nil
}

// RevokedSessions implements auth.RevocationSource.
func (s *Store) RevokedSessions(_ context.Context, limit int) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return nil, s.Fail
	}
	var out []string
	for j, sess := range s.sessions {
		if sess.RevokedAt != nil && sess.ExpiresAt.After(s.now) {
			out = append(out, j)
		}
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// SessionRevoked implements auth.RevocationSource: unknown is revoked.
func (s *Store) SessionRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail != nil {
		return false, s.Fail
	}
	sess, ok := s.sessions[jti]
	return !ok || sess.RevokedAt != nil || !sess.ExpiresAt.After(s.now), nil
}

// ErrDown is a database that does not answer.
var ErrDown = errors.New("consoletest: database down")
