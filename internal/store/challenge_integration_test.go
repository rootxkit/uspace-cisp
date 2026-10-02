//go:build integration

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// The two-step sign-in's challenges on PostgreSQL (migration 0012): a
// challenge opened under the account's lock, exchanged under the
// account's and the challenge's locks in the same order, attempts and
// use committed with a refusal, spent rows deleted when a new one opens.

func challengeHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func newChallengeAccount(t *testing.T, s *Store) Account {
	t.Helper()
	id := "acc-mfa-" + strings.ToLower(suffix(t)+suffix(t))
	if _, err := s.pool.Exec(context.Background(), `INSERT INTO accounts (id, username, password_hash, role, mfa_required, status, created_at)
		VALUES ($1, $1, 'x', 'admin', true, 'active', now())`, id); err != nil {
		t.Fatal(err)
	}
	return Account{ID: id, Username: id}
}

// open runs a password step that opens the challenge for token.
func open(t *testing.T, s *Store, acc Account, token string, ttl time.Duration) {
	t.Helper()
	err := s.Login(context.Background(), acc.Username, func(a *Account, now time.Time) (LoginOutcome, error) {
		if a == nil {
			t.Fatalf("no account %s", acc.Username)
		}
		return LoginOutcome{Challenge: &NewLoginChallenge{TokenHash: challengeHash(token), AccountID: a.ID, CreatedAt: now, ExpiresAt: now.Add(ttl)}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLoginChallengesOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	acc := newChallengeAccount(t, s)
	token := "tok-" + suffix(t) + suffix(t)
	open(t, s, acc, token, 5*time.Minute)
	if n := countRows(t, s, `SELECT count(*) FROM login_challenges WHERE token_hash = $1 AND account_id = $2 AND attempts = 0 AND used_at IS NULL`, challengeHash(token), acc.ID); n != 1 {
		t.Fatalf("challenge rows %d", n)
	}
	// Only the hash is stored.
	if n := countRows(t, s, `SELECT count(*) FROM login_challenges WHERE token_hash = $1`, token); n != 0 {
		t.Error("the token is stored")
	}

	// A refused code: the attempt is committed with the refusal.
	refused := errors.New("wrong code")
	err := s.ExchangeChallenge(ctx, challengeHash(token), func(ch *LoginChallenge, a *Account, now time.Time) (LoginOutcome, error) {
		if ch == nil || a == nil || ch.AccountID != acc.ID || a.ID != acc.ID || !ch.ExpiresAt.After(now) {
			t.Fatalf("exchange saw %+v %+v", ch, a)
		}
		return LoginOutcome{ChallengeAttempt: true, Refusal: refused, Update: &AccountLoginUpdate{FailedLogins: 1, PasswordHash: "x"}}, nil
	})
	if !errors.Is(err, refused) {
		t.Fatalf("refusal = %v", err)
	}
	if n := countRows(t, s, `SELECT count(*) FROM login_challenges WHERE token_hash = $1 AND attempts = 1`, challengeHash(token)); n != 1 {
		t.Error("the attempt was not committed with the refusal")
	}
	if n := countRows(t, s, `SELECT failed_logins FROM accounts WHERE id = $1`, acc.ID); n != 1 {
		t.Errorf("failed_logins %d", n)
	}

	// The accepted code: spent, and the session written.
	jti := "jti-mfa-" + suffix(t) + suffix(t)
	err = s.ExchangeChallenge(ctx, challengeHash(token), func(ch *LoginChallenge, a *Account, now time.Time) (LoginOutcome, error) {
		if ch.Attempts != 1 || ch.UsedAt != nil {
			t.Fatalf("challenge %+v", ch)
		}
		last := now
		return LoginOutcome{
			ChallengeUsed: true, Update: &AccountLoginUpdate{LastLoginAt: &last, PasswordHash: "x"},
			Session: &NewSession{JTI: jti, AccountID: a.ID, IssuedAt: now, ExpiresAt: now.Add(time.Hour)},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, `SELECT count(*) FROM login_challenges WHERE token_hash = $1 AND used_at IS NOT NULL`, challengeHash(token)); n != 1 {
		t.Error("the challenge was not spent")
	}
	if _, err := s.Session(ctx, jti); err != nil {
		t.Errorf("session: %v", err)
	}

	// An unknown challenge reaches decide as nil, nil; nothing is written.
	err = s.ExchangeChallenge(ctx, challengeHash("unknown-"+suffix(t)), func(ch *LoginChallenge, a *Account, _ time.Time) (LoginOutcome, error) {
		if ch != nil || a != nil {
			t.Fatalf("unknown challenge saw %+v %+v", ch, a)
		}
		return LoginOutcome{ChallengeAttempt: true, ChallengeUsed: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// An error from decide rolls back: no attempt counted.
	other := "tok-" + suffix(t) + suffix(t)
	open(t, s, acc, other, 5*time.Minute)
	boom := errors.New("decide failed")
	if err := s.ExchangeChallenge(ctx, challengeHash(other), func(*LoginChallenge, *Account, time.Time) (LoginOutcome, error) {
		return LoginOutcome{ChallengeAttempt: true}, boom
	}); !errors.Is(err, boom) {
		t.Fatalf("decide error = %v", err)
	}
	if n := countRows(t, s, `SELECT attempts FROM login_challenges WHERE token_hash = $1`, challengeHash(other)); n != 0 {
		t.Errorf("attempts %d after a rollback", n)
	}

	// The table refuses a token that is not a SHA-256 in hex.
	if _, err := s.pool.Exec(ctx, `INSERT INTO login_challenges (token_hash, account_id, created_at, expires_at) VALUES ('plain', $1, now(), now() + interval '1 minute')`, acc.ID); err == nil {
		t.Error("a non-hash token_hash was stored")
	}
}

// E-10: a new challenge deletes its account's spent (the used one above)
// and expired ones; a live one and another account's stay.
func TestLoginChallengesBoundedOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	acc, other := newChallengeAccount(t, s), newChallengeAccount(t, s)
	used, expired, live := "u-"+suffix(t), "e-"+suffix(t), "l-"+suffix(t)
	open(t, s, acc, used, 5*time.Minute)
	if err := s.ExchangeChallenge(ctx, challengeHash(used), func(*LoginChallenge, *Account, time.Time) (LoginOutcome, error) {
		return LoginOutcome{ChallengeUsed: true}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO login_challenges (token_hash, account_id, created_at, expires_at)
		VALUES ($1, $2, now() - interval '10 minutes', now() - interval '5 minutes')`, challengeHash(expired), acc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.pool.Exec(ctx, `INSERT INTO login_challenges (token_hash, account_id, created_at, expires_at)
		VALUES ($1, $2, now() - interval '10 minutes', now() - interval '5 minutes')`, challengeHash(expired+"-other"), other.ID); err != nil {
		t.Fatal(err)
	}
	open(t, s, acc, live, 5*time.Minute)
	open(t, s, acc, "n-"+suffix(t), 5*time.Minute)
	if n := countRows(t, s, `SELECT count(*) FROM login_challenges WHERE account_id = $1`, acc.ID); n != 2 {
		t.Errorf("%d challenges of the account, want the 2 live", n)
	}
	if n := countRows(t, s, `SELECT count(*) FROM login_challenges WHERE token_hash = $1`, challengeHash(live)); n != 1 {
		t.Error("a live challenge was deleted")
	}
	if n := countRows(t, s, `SELECT count(*) FROM login_challenges WHERE account_id = $1`, other.ID); n != 1 {
		t.Error("another account's challenge was deleted")
	}
}

// The lock order: the code step takes the account's lock before the
// challenge's, as the password step does (the account, then a delete of
// the account's spent challenges). Deterministically: a password step
// holds the account while a code step replaying a spent challenge, the
// very row that password step deletes, starts and waits; then the
// password step goes on. In this order the code step waits on the
// account and both commit. A code step that locked the challenge first
// would be waited on by the delete while it waits on the account: a
// deadlock, which PostgreSQL ends with 40P01 (checked by reversing the
// order once).
func TestLoginChallengesLockOrderOnPostgres(t *testing.T) {
	ctx := context.Background()
	s := testStore(t, Options{})
	acc := newChallengeAccount(t, s)
	spent := "s" + suffix(t) + suffix(t)
	open(t, s, acc, spent, 5*time.Minute)
	if err := s.ExchangeChallenge(ctx, challengeHash(spent), func(*LoginChallenge, *Account, time.Time) (LoginOutcome, error) {
		return LoginOutcome{ChallengeUsed: true}, nil
	}); err != nil {
		t.Fatal(err)
	}
	waiting := func() int64 {
		return countRows(t, s, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`)
	}
	exchanged := make(chan error, 1)
	err := s.Login(ctx, acc.Username, func(a *Account, now time.Time) (LoginOutcome, error) {
		go func() {
			exchanged <- s.ExchangeChallenge(ctx, challengeHash(spent), func(ch *LoginChallenge, _ *Account, _ time.Time) (LoginOutcome, error) {
				return LoginOutcome{ChallengeAttempt: ch != nil}, nil
			})
		}()
		deadline := time.Now().Add(10 * time.Second)
		for waiting() == 0 {
			if time.Now().After(deadline) {
				return LoginOutcome{}, errors.New("the code step never waited on a lock")
			}
			time.Sleep(10 * time.Millisecond)
		}
		return LoginOutcome{Challenge: &NewLoginChallenge{TokenHash: challengeHash("n" + spent), AccountID: a.ID, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}}, nil
	})
	if err != nil {
		t.Fatalf("password step: %v", err)
	}
	if err := <-exchanged; err != nil {
		t.Fatalf("code step: %v", err)
	}
	if n := countRows(t, s, `SELECT count(*) FROM login_challenges WHERE account_id = $1 AND used_at IS NOT NULL`, acc.ID); n != 0 {
		t.Errorf("%d spent challenges left after the password step", n)
	}
}
