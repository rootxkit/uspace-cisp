package auth

import (
	"context"
	"errors"
	"sync"
	"time"
)

// The idle end of a console session (the ecosystem's session contract,
// M20: at most 12 h, idle 30 min) and how often a use is written.
const (
	// SessionIdle ends a session unused for longer, for good.
	SessionIdle = 30 * time.Minute
	// SessionTouchEvery is the most often one replica writes a
	// session's last_seen_at: a use within it of the last write that
	// replica made is accepted without another write.
	SessionTouchEvery = time.Minute
)

// ActivitySource records a session's use in the sessions table.
type ActivitySource interface {
	// TouchSession moves jti's last_seen_at to now (the database's
	// clock) when the session is live: not revoked, not expired and last
	// seen within idle. false is a session that is over (idle, revoked,
	// expired or unknown).
	TouchSession(ctx context.Context, jti string, idle time.Duration) (bool, error)
}

// ActivityConfig configures an Activity.
type ActivityConfig struct {
	Source ActivitySource
	// Idle is the idle timeout (0: SessionIdle).
	Idle time.Duration
	// Every is the write throttle (0: SessionTouchEvery); it must be
	// shorter than Idle.
	Every time.Duration
	// MaxEntries bounds the sessions remembered as recently written
	// (E-10; 0: 10 000). Past it a use that is not remembered is written,
	// which costs a write and never accepts an idle session.
	MaxEntries int
	// Now is the clock of the throttle; nil is time.Now.
	Now func() time.Time
}

// Activity enforces the idle timeout and records each session's use,
// writing sessions.last_seen_at at most once per Every per session on
// this replica. A use within Every of a write this replica made is
// accepted from memory: the session was seen less than Every ago, which
// is shorter than Idle, so it cannot be idle. Any other use asks the
// database, which refuses a session idle past the timeout and moves
// last_seen_at for one that is not.
type Activity struct {
	cfg ActivityConfig

	mu      sync.Mutex
	touched map[string]time.Time // jti -> this replica's last write
}

// NewActivity returns the tracker; it refuses a config without a source
// or with a throttle not shorter than the idle timeout.
func NewActivity(cfg ActivityConfig) (*Activity, error) {
	if cfg.Source == nil {
		return nil, errors.New("session activity: a source is required")
	}
	if cfg.Idle <= 0 {
		cfg.Idle = SessionIdle
	}
	if cfg.Every <= 0 {
		cfg.Every = SessionTouchEvery
	}
	if cfg.Every >= cfg.Idle {
		return nil, errors.New("session activity: the write throttle must be shorter than the idle timeout")
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 10_000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Activity{cfg: cfg, touched: map[string]time.Time{}}, nil
}

// Idle is the idle timeout.
func (a *Activity) Idle() time.Duration { return a.cfg.Idle }

// Active records a use of jti and says whether the session is still
// live; false is a session idle past the timeout (or revoked, expired or
// unknown in the database). An error is a database that did not answer.
func (a *Activity) Active(ctx context.Context, jti string) (bool, error) {
	now := a.cfg.Now()
	a.mu.Lock()
	last, ok := a.touched[jti]
	a.mu.Unlock()
	if ok && now.Sub(last) < a.cfg.Every && !now.Before(last) {
		return true, nil
	}
	alive, err := a.cfg.Source.TouchSession(ctx, jti, a.cfg.Idle)
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil || !alive {
		delete(a.touched, jti)
		return false, err
	}
	a.remember(jti, now)
	return true, nil
}

// remember notes a write; at the bound it first forgets the writes older
// than Every, and when that frees nothing the use is not remembered.
// Called with mu held.
func (a *Activity) remember(jti string, now time.Time) {
	if _, ok := a.touched[jti]; !ok && len(a.touched) >= a.cfg.MaxEntries {
		for j, t := range a.touched {
			if now.Sub(t) >= a.cfg.Every || now.Before(t) {
				delete(a.touched, j)
			}
		}
		if len(a.touched) >= a.cfg.MaxEntries {
			return
		}
	}
	a.touched[jti] = now
}

// Len is the number of sessions remembered as recently written.
func (a *Activity) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.touched)
}
