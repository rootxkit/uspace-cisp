package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/config"
	"github.com/rootxkit/uspace-cisp/internal/httpapi"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/stream"
)

// The stream's degraded slugs (console/status/v1 degraded[]): the
// status components each one reads.
var degradedSlugs = map[string]string{
	"database":       "database",
	"snapshot_cache": "database",
	"nats":           "nats",
	"jwks":           "jwks",
}

// slugPublisherStale is the degraded slug of a silent publisher.
const slugPublisherStale = "publisher_stale"

// natsNotConfigured is the stream's nats value without CISP_NATS_URL.
const natsNotConfigured = "not_configured"

// streamStatus is the stream's status source and the status line's
// view of the datasets and the publishers. It answers from memory: the
// snapshot cache holds the versions, and the publishers table is read
// once per status period (refresh), never per client or per frame.
type streamStatus struct {
	status     *obs.Status
	cache      httpapi.SnapshotReader
	configured []httpapi.ConfiguredPublisher
	read       func(ctx context.Context) ([]store.Publisher, error)
	busState   func() bus.State
	policy     string
	now        func() time.Time

	mu      sync.Mutex
	rows    []store.Publisher
	readErr error
}

// policyVersion is a hash of the configuration as the start line prints
// it (secrets redacted): the CISP has no display thresholds of its own,
// so the version of its policy is the version of its configuration.
func policyVersion(cfg *config.API) string {
	red := cfg.Redacted()
	names := make([]string, 0, len(red))
	for n := range red {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n + "=" + red[n] + "\n"))
	}
	return "cfg-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// refresh reads the publishers table once, bounded; a failed read keeps
// the previous rows (the database component says it is down).
func (s *streamStatus) refresh(ctx context.Context) {
	if s.read == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows, err := s.read(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readErr = err
	if err == nil {
		s.rows = rows
	}
}

// run refreshes on every tick until ctx ends.
func (s *streamStatus) run(ctx context.Context, tick <-chan time.Time) {
	s.refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			s.refresh(ctx)
		}
	}
}

func (s *streamStatus) publishers(now time.Time) []httpapi.PublisherReading {
	s.mu.Lock()
	rows := s.rows
	s.mu.Unlock()
	return httpapi.ReadPublishers(s.configured, rows, now)
}

// Parts is the stream.StatusSource.
func (s *streamStatus) Parts(now time.Time) stream.Parts {
	now = now.UTC()
	p := stream.Parts{
		PolicyVersion: s.policy, StaleAfterS: httpapi.DefaultStaleAfter.Seconds(),
		Degraded: []string{}, DegradedSince: map[string]time.Time{},
	}
	for _, d := range s.status.Degradations() {
		slug, ok := degradedSlugs[d.Component]
		if !ok || (slug == "nats" && s.busState != nil) {
			// With a bus, its own state says (below): the component
			// follows it a callback later.
			continue
		}
		since := d.Since
		if since.IsZero() {
			since = now
		}
		if prev, seen := p.DegradedSince[slug]; !seen || since.Before(prev) {
			p.DegradedSince[slug] = since
		}
	}
	for _, r := range s.publishers(now) {
		ps := stream.PublisherStatus{ClientID: r.ClientID, Kind: r.Kind, StaleAfterS: r.StaleAfter.Seconds(), Stale: r.Stale}
		if r.LastHeartbeatAt != nil {
			at := stream.Timestamp(*r.LastHeartbeatAt)
			age := max(now.Sub(*r.LastHeartbeatAt).Seconds(), 0)
			ps.LastHeartbeatAt, ps.HeartbeatAgeS = &at, &age
		}
		if r.Stale {
			since := now
			if r.LastHeartbeatAt != nil {
				since = r.LastHeartbeatAt.Add(r.StaleAfter)
			}
			if prev, seen := p.DegradedSince[slugPublisherStale]; !seen || since.Before(prev) {
				p.DegradedSince[slugPublisherStale] = since
			}
		}
		p.Publishers = append(p.Publishers, ps)
	}

	if s.cache != nil {
		versions, updated := s.cache.Versions()
		p.Datasets = map[string]stream.DatasetStatus{}
		var newest *float64
		for _, ds := range publication.Datasets {
			v, ok := versions[ds]
			if !ok {
				continue
			}
			age := 0.0
			if u, ok := updated[ds]; ok {
				age = max(now.Sub(u).Seconds(), 0)
			}
			p.Datasets[string(ds)] = stream.DatasetStatus{Version: strconv.FormatInt(v, 10), AgeS: age}
			if newest == nil || age < *newest {
				a := age
				newest = &a
			}
		}
		p.CISAgeS = newest
	}

	if s.busState == nil {
		p.NATS = natsNotConfigured
	} else {
		st := s.busState()
		p.NATS, p.NATSSince = st.Kind, st.Since
		if st.Kind != bus.StateConnected {
			// The bus's own since: when the connection was lost, or
			// when the process started trying.
			p.DegradedSince["nats"] = st.Since
		}
	}
	for slug := range p.DegradedSince {
		p.Degraded = append(p.Degraded, slug)
	}
	sort.Strings(p.Degraded)
	return p
}

// probe sets the status line's view before every line: the
// publisher_stale gauge, and one-line summaries of the datasets and
// the publishers (the first line after start says what was found).
func (s *streamStatus) probe(context.Context) {
	now := s.now().UTC()
	stale := 0
	readings := s.publishers(now)
	pubs := make([]string, 0, len(readings))
	for _, r := range readings {
		hb := "never heard"
		if r.LastHeartbeatAt != nil {
			hb = "heartbeat " + strconv.FormatInt(int64(now.Sub(*r.LastHeartbeatAt)/time.Second), 10) + " s ago"
		}
		if r.Stale {
			stale++
			hb += ", stale"
		}
		pubs = append(pubs, r.ClientID+" "+hb)
	}
	comp := s.status.Component("publishers")
	comp.Gauge("publisher_stale", "Configured publishers whose last heartbeat is older than stale_after_s (or never heard).").Set(float64(stale))
	s.mu.Lock()
	readErr := s.readErr
	s.mu.Unlock()
	switch {
	case s.read == nil:
		comp.SetSummary("not read: no database")
	case readErr != nil:
		comp.SetSummary("not read: " + readErr.Error())
	default:
		comp.SetSummary(strings.Join(pubs, "; "))
	}
	if s.cache == nil {
		s.status.Component("datasets").SetSummary("no database")
		return
	}
	versions, _ := s.cache.Versions()
	var ds []string
	for _, d := range publication.Datasets {
		if v, ok := versions[d]; ok {
			ds = append(ds, string(d)+" "+strconv.FormatInt(v, 10))
		} else {
			ds = append(ds, string(d)+" none")
		}
	}
	s.status.Component("datasets").SetSummary(strings.Join(ds, ", "))
}

// startStream builds the hub and its upgrade handler, subscribes it to
// the bus (when there is one) and runs its status period until ctx
// ends; the hub then closes its clients (1001).
func startStream(ctx context.Context, cfg *config.API, status *obs.Status, logger *slog.Logger, changes *bus.Bus,
	src *streamStatus, sessions stream.SessionVerifier,
) (http.Handler, func(), error) {
	hub := stream.NewHub(stream.Config{
		MaxClients: int(cfg.StreamMaxClients), SendBuffer: int(cfg.StreamSendBufferFrames),
		StatusInterval: cfg.StreamStatusInterval, WriteTimeout: cfg.StreamWriteTimeout, LiveMaxAge: cfg.StreamLiveMaxAge,
		Source: src.Parts, Status: status, Logger: logger,
	})
	stop := func() {}
	if changes != nil {
		unreadable := status.Component("nats").Counter("bus_change_unreadable",
			"Bus messages on cis.v1.change.* that are not a cis/change/v1 record (dropped by the stream).")
		sub, err := changes.Subscribe(ctx, nil, bus.Handler{
			Change: hub.Publish,
			Resync: func(since time.Time) {
				logger.Info("stream: the bus is back; clients are told to resync", "resync_since", since.UTC().Format(time.RFC3339))
				hub.Resync(since)
			},
			Unreadable: func(err error) {
				unreadable.Inc()
				if ok, held := obs.Once("stream: unreadable bus message", time.Minute); ok {
					logger.Warn("stream: a bus message is not a cis/change/v1 record; dropped", "error", err.Error(), "also_dropped_since_last_line", held)
				}
			},
		})
		if err != nil {
			return nil, nil, err
		}
		stop = sub.Close
	}
	tick := time.NewTicker(cfg.StreamStatusInterval)
	refresh := time.NewTicker(cfg.StreamStatusInterval)
	go src.run(ctx, refresh.C)
	go hub.Run(ctx, tick.C)
	h := stream.NewHandler(hub, stream.HandlerConfig{
		AllowedOrigins: stream.AllowedOrigins(cfg.PublicBaseURL, cfg.StreamAllowedOrigins),
		Public:         cfg.StreamPublic, Sessions: sessions, Problems: httpapi.WriteProblem,
	})
	return h, func() {
		stop()
		tick.Stop()
		refresh.Stop()
		hub.Close()
	}, nil
}
