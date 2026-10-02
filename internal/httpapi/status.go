package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/httpapi/gen"
	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
)

// DefaultStaleAfter is a publisher's staleness when its row names none:
// three missed 15 s heartbeats (docs/PLAN.md section 15 Q3).
const DefaultStaleAfter = 60 * time.Second

// The degraded components GET /v1/status reports, by status component.
var statusComponents = map[string]string{"database": "database", "nats": "nats", "jwks": "jwks"}

// ConfiguredPublisher is a publisher the api is configured with
// (CISP_AUTHORITY_CLIENT_ID, CISP_ANSP_CLIENT_ID): listed in the status
// even before its first heartbeat.
type ConfiguredPublisher struct {
	ClientID string
	Kind     string
}

// StatusReport is what GET /v1/status is made of. Every field may be
// nil: the status is answered with what there is.
type StatusReport struct {
	// Cache gives the datasets' current versions (nil without a
	// database).
	Cache SnapshotReader
	// Publishers reads the publishers table (nil without a database).
	Publishers func(ctx context.Context) ([]store.Publisher, error)
	// Configured are the configured publishers.
	Configured []ConfiguredPublisher
	// Registry is the process status, whose degraded components are
	// reported.
	Registry *obs.Status
	// MTLSMode is CISP_MTLS_MODE.
	MTLSMode string
	// Restrictions reads the restrictions block (WP-5; nil without a
	// database).
	Restrictions func(ctx context.Context) (*RestrictionStatusReport, error)
	Logger       *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

type statusDataset struct {
	Dataset        string     `json:"dataset"`
	CurrentVersion int64      `json:"current_version"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	ETag           string     `json:"etag"`
}

type statusPublisher struct {
	ClientID          string     `json:"client_id"`
	Kind              string     `json:"kind"`
	LastHeartbeatAt   *time.Time `json:"last_heartbeat_at,omitempty"`
	LastPublicationAt *time.Time `json:"last_publication_at,omitempty"`
	StaleAfterS       int        `json:"stale_after_s"`
	Stale             bool       `json:"stale"`
	StaleSince        *time.Time `json:"stale_since,omitempty"`
}

type statusDegraded struct {
	Component string    `json:"component"`
	Since     time.Time `json:"since"`
	Reason    string    `json:"reason,omitempty"`
}

type statusBody struct {
	Now        time.Time         `json:"now"`
	Datasets   []statusDataset   `json:"datasets"`
	Publishers []statusPublisher `json:"publishers"`
	Degraded   []statusDegraded  `json:"degraded"`
	MTLSMode   string            `json:"mtls_mode,omitempty"`
	// Restrictions is absent when it cannot be read (database degraded).
	Restrictions *RestrictionStatusReport `json:"restrictions,omitempty"`
}

// VisitGetStatusResponse implements gen.GetStatusResponseObject.
func (b statusBody) VisitGetStatusResponse(w http.ResponseWriter) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", mediaJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(append(raw, '\n'))
	return err
}

// GetStatus is the service status (WP-4).
func (s *Server) GetStatus(ctx context.Context, _ gen.GetStatusRequestObject) (gen.GetStatusResponseObject, error) {
	rep := s.Status
	if rep == nil {
		rep = &StatusReport{}
	}
	return rep.build(ctx), nil
}

func (rep *StatusReport) now() time.Time {
	if rep.Now == nil {
		return time.Now().UTC()
	}
	return rep.Now().UTC()
}

func (rep *StatusReport) build(ctx context.Context) statusBody {
	now := rep.now()
	out := statusBody{Now: now, Datasets: []statusDataset{}, Publishers: []statusPublisher{}, Degraded: []statusDegraded{}, MTLSMode: rep.MTLSMode}
	degraded := map[string]statusDegraded{}
	if rep.Registry != nil {
		for _, d := range rep.Registry.Degradations() {
			name, ok := statusComponents[d.Component]
			if !ok {
				continue
			}
			since := d.Since
			if since.IsZero() {
				since = now
			}
			degraded[name] = statusDegraded{Component: name, Since: since.UTC(), Reason: d.Reason}
		}
	}

	if rep.Cache != nil {
		versions, updated := rep.Cache.Versions()
		for _, ds := range publication.Datasets {
			v, ok := versions[ds]
			if !ok {
				continue
			}
			item := statusDataset{Dataset: string(ds), CurrentVersion: v, ETag: publication.ETag(ds, v)}
			if u, ok := updated[ds]; ok {
				u = u.UTC()
				item.UpdatedAt = &u
			}
			out.Datasets = append(out.Datasets, item)
		}
		if since, stale := rep.Cache.Stale(); stale {
			if _, ok := degraded["database"]; !ok {
				degraded["database"] = statusDegraded{Component: "database", Since: since.UTC(), Reason: "the snapshot cache could not refresh"}
			}
		}
	}

	out.Publishers = rep.publishers(ctx, now, degraded)
	if rep.Restrictions != nil {
		rs, err := rep.Restrictions(ctx)
		if err != nil {
			if rep.Logger != nil {
				rep.Logger.LogAttrs(ctx, slog.LevelWarn, "status: restrictions not read", slog.String("error", err.Error()))
			}
			if _, ok := degraded["database"]; !ok {
				degraded["database"] = statusDegraded{Component: "database", Since: now, Reason: "the restrictions could not be read"}
			}
		} else {
			out.Restrictions = rs
		}
	}
	for _, d := range degraded {
		out.Degraded = append(out.Degraded, d)
	}
	sort.Slice(out.Degraded, func(i, j int) bool { return out.Degraded[i].Component < out.Degraded[j].Component })
	return out
}

// publishers merges the configured publishers with the table: a
// configured publisher never heard from is stale with no since.
func (rep *StatusReport) publishers(ctx context.Context, now time.Time, degraded map[string]statusDegraded) []statusPublisher {
	byID := map[string]statusPublisher{}
	for _, c := range rep.Configured {
		if c.ClientID == "" {
			continue
		}
		byID[c.ClientID] = statusPublisher{ClientID: c.ClientID, Kind: c.Kind, StaleAfterS: int(DefaultStaleAfter / time.Second), Stale: true}
	}
	if rep.Publishers != nil {
		rows, err := rep.Publishers(ctx)
		if err != nil {
			if rep.Logger != nil {
				rep.Logger.LogAttrs(ctx, slog.LevelWarn, "status: publishers not read", slog.String("error", err.Error()))
			}
			if _, ok := degraded["database"]; !ok {
				degraded["database"] = statusDegraded{Component: "database", Since: now, Reason: "the publishers could not be read"}
			}
			// What a publisher's staleness is cannot be told: none is listed.
			return []statusPublisher{}
		}
		for _, r := range rows {
			byID[r.ClientID] = publisherStatus(r, now)
		}
	}
	out := make([]statusPublisher, 0, len(byID))
	for _, p := range byID {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out
}

// publisherStatus is one publisher's staleness: stale when its last
// heartbeat is older than stale_after_s (WP-5 owns the rule; this is its
// reading for the status), since the instant that happened.
func publisherStatus(r store.Publisher, now time.Time) statusPublisher {
	after := time.Duration(r.StaleAfterS) * time.Second
	if after <= 0 {
		after = DefaultStaleAfter
	}
	p := statusPublisher{ClientID: r.ClientID, Kind: r.Kind, StaleAfterS: int(after / time.Second), Stale: true}
	if r.LastPublicationAt != nil {
		t := r.LastPublicationAt.UTC()
		p.LastPublicationAt = &t
	}
	if r.LastHeartbeatAt == nil {
		return p
	}
	last := r.LastHeartbeatAt.UTC()
	p.LastHeartbeatAt = &last
	if now.Sub(last) <= after {
		p.Stale = false
		return p
	}
	since := last.Add(after)
	p.StaleSince = &since
	return p
}

// PublisherReading is one publisher's heartbeat as GET /v1/status reads
// it, for the stream's status (which reads the table off the request
// path).
type PublisherReading struct {
	ClientID        string
	Kind            string
	LastHeartbeatAt *time.Time
	StaleAfter      time.Duration
	Stale           bool
}

// ReadPublishers merges the configured publishers with the table rows
// at now, by client id: a configured publisher never heard from is
// stale, with no heartbeat.
func ReadPublishers(configured []ConfiguredPublisher, rows []store.Publisher, now time.Time) []PublisherReading {
	byID := map[string]statusPublisher{}
	for _, c := range configured {
		if c.ClientID != "" {
			byID[c.ClientID] = statusPublisher{ClientID: c.ClientID, Kind: c.Kind, StaleAfterS: int(DefaultStaleAfter / time.Second), Stale: true}
		}
	}
	for _, r := range rows {
		byID[r.ClientID] = publisherStatus(r, now)
	}
	out := make([]PublisherReading, 0, len(byID))
	for _, p := range byID {
		out = append(out, PublisherReading{
			ClientID: p.ClientID, Kind: p.Kind, LastHeartbeatAt: p.LastHeartbeatAt,
			StaleAfter: time.Duration(p.StaleAfterS) * time.Second, Stale: p.Stale,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out
}
