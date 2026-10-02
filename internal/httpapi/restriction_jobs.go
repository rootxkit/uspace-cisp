package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/restriction"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// The restrictions' jobs (WP-5): the expiry at ends_at, the comparison of
// the ANSP's declared active_refs, and what the status reports of both.

// staleAfter is how old the expiry's last run may be.
func (rs *Restrictions) staleAfter() time.Duration {
	if rs.ExpiryStaleAfter <= 0 {
		return DefaultExpiryStaleAfter
	}
	return rs.ExpiryStaleAfter
}

// CompareRefs counts the differences between the active_refs the ANSP
// declared in a heartbeat and the restrictions the CISP holds as active:
// a declared ref not held as active (heartbeat_ref_unknown) and an active
// one not declared (heartbeat_ref_missing). It acts on neither: only the
// ANSP's POST and PATCH change a restriction. A store error is logged and
// counted, never answered.
func (rs *Restrictions) CompareRefs(ctx context.Context, declared []string) {
	active, err := rs.Store.ActiveRestrictionRefs(ctx)
	if err != nil {
		rs.logger().LogAttrs(ctx, slog.LevelWarn, "heartbeat refs not compared", slog.String("error", err.Error()))
		return
	}
	unknown, missing := diffRefs(declared, active)
	if len(unknown) > 0 {
		rs.counter(CounterHeartbeatRefUnknown).Add(uint64(len(unknown)))
	}
	if len(missing) > 0 {
		rs.counter(CounterHeartbeatRefMissing).Add(uint64(len(missing)))
	}
	if len(unknown)+len(missing) > 0 {
		rs.logger().LogAttrs(ctx, slog.LevelWarn, "ansp heartbeat disagrees with the active restrictions; nothing is changed",
			slog.Int("unknown", len(unknown)), slog.Int("missing", len(missing)))
	}
}

// diffRefs is declared minus active and active minus declared, sorted.
func diffRefs(declared, active []string) (unknown, missing []string) {
	in := func(list []string) map[string]bool {
		m := make(map[string]bool, len(list))
		for _, s := range list {
			m[s] = true
		}
		return m
	}
	d, a := in(declared), in(active)
	for s := range d {
		if !a[s] {
			unknown = append(unknown, s)
		}
	}
	for s := range a {
		if !d[s] {
			missing = append(missing, s)
		}
	}
	sort.Strings(unknown)
	sort.Strings(missing)
	return unknown, missing
}

// --- status ----------------------------------------------------------------

// RestrictionStatusReport is the restrictions block of GET /v1/status
// (the RestrictionStatus schema).
type RestrictionStatusReport struct {
	Active         int64        `json:"active"`
	Expiry         expiryStatus `json:"expiry"`
	ANSPStaleSince *staleSince  `json:"ansp_stale_since,omitempty"`
	RefUnknown     []string     `json:"heartbeat_ref_unknown,omitempty"`
	RefMissing     []string     `json:"heartbeat_ref_missing,omitempty"`
	staleANSP      bool
	expiryStale    bool
	expiryAge      time.Duration
}

type expiryStatus struct {
	LastRunAt    *time.Time `json:"last_run_at,omitempty"`
	LastInstance *string    `json:"last_instance,omitempty"`
	LastCount    *int       `json:"last_count,omitempty"`
	Stale        bool       `json:"stale"`
	StaleAfterS  int        `json:"stale_after_s"`
}

// Report reads the restrictions block of the status: the active count,
// the expiry's last run and whether it is stale, the ANSP's staleness,
// and the differences between its declared active_refs and the active
// heads (listed, never acted on).
func (rs *Restrictions) Report(ctx context.Context) (*RestrictionStatusReport, error) {
	now := rs.now()
	out := &RestrictionStatusReport{Expiry: expiryStatus{StaleAfterS: int(rs.staleAfter() / time.Second)}}
	n, err := rs.Store.CountActiveRestrictions(ctx)
	if err != nil {
		return nil, err
	}
	out.Active = n
	// The age of the last run is the database's (its clock wrote it);
	// before the first run, this process's uptime is the age.
	age := now.Sub(rs.Started)
	run, err := rs.Store.LastJobRun(ctx, JobRestrictionExpiry)
	switch {
	case err == nil:
		at, inst, count := run.RanAt.UTC(), run.Instance, run.Count
		out.Expiry.LastRunAt, out.Expiry.LastInstance, out.Expiry.LastCount = &at, &inst, &count
		age = run.Age
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}
	out.Expiry.Stale = age > rs.staleAfter()
	out.expiryStale = out.Expiry.Stale
	out.expiryAge = age
	pubs, err := rs.Store.PublishersRefs(ctx)
	if err != nil {
		return nil, err
	}
	var anspRow *store.PublisherRefs
	for i := range pubs {
		if pubs[i].ClientID == rs.ANSPClientID {
			anspRow = &pubs[i]
		}
	}
	stale, since := true, (*time.Time)(nil)
	if anspRow != nil {
		stale, since, _ = staleOf(*anspRow, now)
	}
	if stale {
		out.staleANSP = true
		out.ANSPStaleSince = &staleSince{at: since}
	}
	if anspRow != nil && anspRow.ActiveRefs != nil {
		active, err := rs.Store.ActiveRestrictionRefs(ctx)
		if err != nil {
			return nil, err
		}
		unknown, missing := diffRefs(anspRow.ActiveRefs, active)
		out.RefUnknown, out.RefMissing = capRefs(unknown), capRefs(missing)
	}
	return out, nil
}

func capRefs(refs []string) []string {
	if len(refs) > MaxListedRefs {
		return refs[:MaxListedRefs]
	}
	return refs
}

// Probe sets the status line's view of the restrictions before each
// line: the restrictions_active gauge, the expiry component degraded
// (error) while the last run is older than ExpiryStaleAfter, and the
// ansp component warned (warning, never error) while the ANSP is stale.
// A store it cannot read leaves the expiry degraded: whether it runs
// cannot be told.
func (rs *Restrictions) Probe(ctx context.Context) {
	st := rs.status()
	exp, ansp := st.Component(ExpiryComponent), st.Component(ANSPComponent)
	rep, err := rs.Report(ctx)
	if err != nil {
		exp.SetDegraded("the expiry's last run cannot be read: " + err.Error())
		return
	}
	st.Component(restrictionsComponent).Gauge(GaugeRestrictionsActive, "Active restrictions.").Set(float64(rep.Active))
	exp.Gauge(GaugeExpiryJobAgeS, "Seconds since the restriction expiry last ran (the database's clock).").Set(max(rep.expiryAge.Seconds(), 0))
	switch {
	case rep.expiryStale && rep.Expiry.LastRunAt == nil:
		exp.SetDegraded("the restriction expiry has not run since the start; active restrictions are not expired at their ends_at")
	case rep.expiryStale:
		exp.SetDegraded("the restriction expiry last ran at " + rep.Expiry.LastRunAt.Format(time.RFC3339) +
			", more than " + rs.staleAfter().String() + " ago; active restrictions are not expired at their ends_at")
	default:
		if exp.DegradedReason() != "" && rs.expiryFailures() == 0 {
			exp.SetHealthy()
		}
	}
	switch {
	case !rep.staleANSP:
		ansp.SetWarning("")
	case rep.ANSPStaleSince.at == nil:
		ansp.SetWarning(rs.ANSPClientID + " stale: never heard from; its active restrictions stay active until their ends_at")
	default:
		ansp.SetWarning(rs.ANSPClientID + " stale since " + rep.ANSPStaleSince.at.Format(time.RFC3339) +
			"; its active restrictions stay active until their ends_at")
	}
}

// --- the expiry --------------------------------------------------------------

// GaugeExpiryFailures is the restrictions the last expiry tick could
// not expire.
const GaugeExpiryFailures = "expiry_last_tick_failures"

// GaugeExpiryJobAgeS is the age of the expiry's last run, in seconds
// (before the first run, this process's uptime).
const GaugeExpiryJobAgeS = "restriction_expiry_job_age_s"

func (rs *Restrictions) failuresGauge() *obs.Gauge {
	return rs.status().Component(ExpiryComponent).Gauge(GaugeExpiryFailures, "Restrictions the last expiry tick could not expire.")
}

// expiryFailures is the failures of the last tick (0 when it had none).
func (rs *Restrictions) expiryFailures() float64 { return rs.failuresGauge().Value() }

// ExpireTick runs one expiry, as the leader when this replica gets the
// job's lock: every planned or active head whose ends_at is not after now is ended
// with ended_by expiry, each through its own version of the restrictions
// dataset (reason restriction_expired, no publisher signature, event
// actor system). Nothing else ends a restriction here. It returns how
// many expired and whether this replica ran the job.
func (rs *Restrictions) ExpireTick(ctx context.Context) (int, bool, error) {
	exp := rs.status().Component(ExpiryComponent)
	failures, expired := 0, 0
	// now is the database's clock: a replica whose clock runs late never
	// keeps a restriction past its ends_at, and one whose clock runs early
	// never ends one before it.
	ran, err := rs.Store.RunJob(ctx, JobRestrictionExpiry, rs.Instance, func(ctx context.Context, now time.Time) (int, error) {
		ids, err := rs.Store.ExpiredRestrictions(ctx, now, MaxExpiredPerTick)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, id := range ids {
			ok, err := rs.expire(ctx, id, now)
			if err != nil {
				failures++
				rs.status().Component(ExpiryComponent).Counter(CounterExpiryFailed, "Restrictions the expiry could not expire.").Inc()
				rs.logger().LogAttrs(ctx, slog.LevelError, "restriction not expired; it stays active and is retried next tick",
					slog.String("restriction_id", id), slog.String("error", err.Error()))
				continue
			}
			if ok {
				n++
			}
		}
		expired = n
		return n, nil
	})
	rs.failuresGauge().Set(float64(failures))
	switch {
	case err != nil:
		exp.SetDegraded("the restriction expiry failed: " + err.Error())
		return 0, false, err
	case !ran:
		exp.Counter(CounterExpiryNotLeader, "Expiry ticks another replica ran.").Inc()
		return 0, false, nil
	case failures > 0:
		exp.SetDegraded(strconv.Itoa(failures) + " restrictions past their ends_at could not be expired; they stay active and are retried")
	default:
		exp.SetHealthy()
	}
	exp.Counter(CounterExpiryTicks, "Expiry runs on this replica.").Inc()
	if n, err := rs.Store.CountActiveRestrictions(ctx); err == nil {
		rs.status().Component(restrictionsComponent).Gauge(GaugeRestrictionsActive, "Active restrictions.").Set(float64(n))
	}
	return expired, true, nil
}

// expire ends one head if it is still planned or active and past its ends_at under
// the lock (the ANSP may have extended or ended it meanwhile).
func (rs *Restrictions) expire(ctx context.Context, id string, now time.Time) (bool, error) {
	if rs.Signer == nil {
		return false, errors.New("no CISP signing key (CISP_SIGNING_KEY_FILE): an expiry cannot be published")
	}
	body, err := json.Marshal(map[string]string{"op": string(restriction.OpExpire), "restriction_id": id, "at": now.Format(time.RFC3339Nano)})
	if err != nil {
		return false, err
	}
	res, err := rs.Store.ApplyRestriction(ctx, store.RestrictionWrite{
		ID: id, Body: body, ContentType: mediaJSONRestriction, PublisherClientID: store.SystemPublisher,
		ReceivedAt: now, Actor: store.SystemActor,
		Decide: func(head *restriction.Head, current []store.StoredFeature) (store.RestrictionDecision, error) {
			if head == nil {
				return store.RestrictionDecision{}, store.ErrNotFound
			}
			next, ok := restriction.Expire(*head, now)
			if !ok {
				return store.RestrictionDecision{Head: *head}, nil // nothing to do
			}
			return decision(next, restriction.OpExpire, publication.ReasonRestrictionExpired, current, nil)
		},
	}, rs.Signer)
	if err != nil {
		return false, err
	}
	if res.Replay {
		return false, nil
	}
	rs.counter(CounterRestrictionsExpired).Inc()
	if rs.OnPublished != nil {
		rs.OnPublished()
	}
	rs.logger().LogAttrs(ctx, slog.LevelInfo, "restriction expired at its ends_at",
		slog.String("restriction_id", res.Head.ID), slog.String("ansp_ref", res.Head.AnspRef),
		slog.Time("ends_at", res.Head.EndsAt), slog.Int64("version", res.Version))
	return true, nil
}

// RunExpiry calls ExpireTick on every tick until ctx ends.
func (rs *Restrictions) RunExpiry(ctx context.Context, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			_, _, _ = rs.ExpireTick(ctx) // the outcome is the expiry component's state and counters
		}
	}
}
