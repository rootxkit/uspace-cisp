package deliver

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/obs"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// Defaults (docs/WORKPACKAGES/WP-6.md, docs/PLAN.md section 9).
const (
	DefaultTimeout     = 2 * time.Second
	DefaultMaxInFlight = 64
	// DefaultMaxPerSubscription bounds one subscription's attempts in
	// flight, so a slow subscriber holds at most this many of the
	// MaxInFlight slots.
	DefaultMaxPerSubscription = 8
	DefaultMaxResponseBytes   = 1 << 10
	DefaultPollInterval       = 250 * time.Millisecond
	DefaultScanInterval       = 10 * time.Second
	DefaultScanGrace          = 2 * time.Second
	DefaultScanSettle         = 30 * time.Second
	DefaultScanBatch          = 500
	DefaultLease              = 30 * time.Second
	DefaultDrainTimeout       = 5 * time.Second
	// DefaultIntakeTimeout bounds one message's matching and writes.
	DefaultIntakeTimeout = 5 * time.Second
	// MaxErrorChars bounds an attempt's error as stored.
	MaxErrorChars = 512
	// WatermarkName is the scan's deliver_state row.
	WatermarkName = "scan"
	// ProducerPrefix names the instance in a webhook's producer.
	ProducerPrefix = "cisp/deliver-"
	// MediaJOSE is a webhook's content type (RFC 7515 section 9.2.1).
	MediaJOSE = "application/jose"
)

// The headers of a webhook.
const (
	HeaderDeliveryID = "X-CIS-Delivery-Id"
	HeaderAttempt    = "X-CIS-Attempt"
)

// The component, counters and gauges deliver reports.
const (
	Component = "deliver"

	CounterIntakeDeliveries   = "deliveries_from_bus"
	CounterScanDeliveries     = "deliveries_from_scan"
	CounterScans              = "delivery_scans"
	CounterScanFailed         = "delivery_scan_failed"
	CounterBusPoison          = "bus_poison"
	CounterIntakeFailed       = "intake_failed"
	CounterDelivered          = "deliveries_delivered"
	CounterFailed             = "deliveries_failed"
	CounterExpired            = "deliveries_expired"
	CounterSSRFRefused        = "ssrf_refused"
	CounterSuspended          = "subscriptions_suspended_total"
	CounterVerified           = "subscriptions_verified"
	CounterLogWriteFailed     = "delivery_log_write_failed"
	CounterRecordFailed       = "delivery_record_failed"
	CounterSignFailed         = "delivery_sign_failed"
	CounterClaimFailed        = "delivery_claim_failed"
	CounterPayloadTooLarge    = "delivery_payload_too_large"
	GaugeQueued               = "deliveries_queued"
	GaugeDue                  = "deliveries_due"
	GaugeOldestDueS           = "deliveries_oldest_due_s"
	GaugeInFlight             = "deliveries_in_flight"
	GaugeSuspended            = "subscriptions_suspended"
	MetricFirstAttemptSeconds = "cisp_delivery_first_attempt_seconds"
	MetricResultTotal         = "cisp_delivery_result_total"
)

// Store is what deliver needs of the relational database (*store.Store).
type Store interface {
	ReceivingSubscriptions(ctx context.Context) ([]store.SubscriptionRecord, error)
	InsertChangeDeliveries(ctx context.Context, changeID int64, subscriptionIDs []string, now time.Time) (int64, error)
	Watermark(ctx context.Context, name string) (int64, error)
	AdvanceWatermark(ctx context.Context, name string, w int64, now time.Time) error
	ScanChanges(ctx context.Context, since int64, before time.Time, limit int) ([]publication.Change, error)
	ChangesByID(ctx context.Context, ids []int64) (map[int64]publication.Change, error)
	DatasetVersions(ctx context.Context) (map[publication.Dataset]int64, error)
	ClaimDeliveries(ctx context.Context, now, leaseUntil time.Time, limit, perSubscription int) ([]store.Claim, error)
	FinishDelivered(ctx context.Context, deliveryID, subscriptionID string, at time.Time, statusCode int) (store.Delivered, error)
	FinishFailed(ctx context.Context, f store.FailedAttempt) (store.Failed, error)
	SuspendSubscription(ctx context.Context, id, reason string) (bool, error)
	DeliveryQueue(ctx context.Context, now time.Time) (store.QueueStats, error)
}

// AttemptLog writes the delivery log (*store.DeliveryLog on the
// timeseries database).
type AttemptLog interface {
	Record(ctx context.Context, a store.DeliveryAttempt) error
}

// Signer signs a delivery (*jws.KeyRing: core's KeyRing.SignCompact).
type Signer interface {
	SignCompact(cl coreauth.CompactClaims, body json.RawMessage, now time.Time) (string, error)
}

// Config configures a Service. Zero durations and sizes take the
// defaults; Instance, IssuerURL and PublicBaseURL are required.
type Config struct {
	// Instance names this process in the producer and the delivery log
	// (1-64 of A-Z a-z 0-9 . _ -).
	Instance string
	// IssuerURL is the iss of every webhook (CISP_ISSUER_URL).
	IssuerURL string
	// PublicBaseURL prefixes every pull_url (CISP_PUBLIC_BASE_URL).
	PublicBaseURL string
	// Version is in the User-Agent (uspace-cisp/<version>).
	Version string
	// Policy is CISP_ALLOW_PRIVATE_CALLBACKS and
	// CISP_ALLOW_INSECURE_CALLBACKS: the dialer refuses a non-public
	// address unless AllowPrivate.
	Policy subscription.URLPolicy
	// Retry is the retry schedule (zero: subscription.DefaultRetry).
	Retry subscription.Retry

	Timeout     time.Duration
	MaxInFlight int
	// MaxPerSubscription bounds one subscription's attempts in flight
	// across every instance (at most MaxInFlight).
	MaxPerSubscription int
	MaxResponseBytes   int64
	// MaxTokenBytes bounds a signed webhook (CISP_WEBHOOK_MAX_TOKEN_BYTES,
	// default core's auth.DefaultMaxTokenBytes, the bound every receiver
	// on core's defaults verifies). A larger one is not sent: the
	// delivery expires as the payload's failure, never the subscriber's.
	MaxTokenBytes int
	PollInterval  time.Duration
	ScanInterval  time.Duration
	// ScanGrace is how old a change must be before the scan looks at it
	// (the bus has had its chance); ScanSettle how old before the
	// watermark passes it.
	ScanGrace, ScanSettle time.Duration
	ScanBatch             int
	Lease                 time.Duration
	DrainTimeout          time.Duration
	IntakeTimeout         time.Duration
	// RootCAs, when set, are the roots a callback's certificate is
	// checked against (tests; nil is the system pool).
	RootCAs *x509.CertPool
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

var instancePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func (c *Config) defaults() error {
	if !instancePattern.MatchString(c.Instance) {
		return fmt.Errorf("deliver: instance %q must be 1-64 of A-Z a-z 0-9 . _ -", c.Instance)
	}
	if c.IssuerURL == "" || c.PublicBaseURL == "" {
		return errors.New("deliver: the issuer URL and the public base URL are required")
	}
	if c.Version == "" {
		c.Version = "dev"
	}
	if c.Retry.Base <= 0 {
		c.Retry = subscription.DefaultRetry
	}
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	set(&c.Timeout, DefaultTimeout)
	set(&c.PollInterval, DefaultPollInterval)
	set(&c.ScanInterval, DefaultScanInterval)
	set(&c.ScanGrace, DefaultScanGrace)
	set(&c.ScanSettle, DefaultScanSettle)
	set(&c.Lease, DefaultLease)
	set(&c.DrainTimeout, DefaultDrainTimeout)
	set(&c.IntakeTimeout, DefaultIntakeTimeout)
	if c.MaxInFlight <= 0 {
		c.MaxInFlight = DefaultMaxInFlight
	}
	if c.MaxPerSubscription <= 0 {
		c.MaxPerSubscription = DefaultMaxPerSubscription
	}
	c.MaxPerSubscription = min(c.MaxPerSubscription, c.MaxInFlight)
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if c.MaxTokenBytes <= 0 {
		c.MaxTokenBytes = coreauth.DefaultMaxTokenBytes
	}
	if c.ScanBatch <= 0 {
		c.ScanBatch = DefaultScanBatch
	}
	if c.Lease <= c.Timeout {
		return fmt.Errorf("deliver: the lease %s must exceed the attempt timeout %s", c.Lease, c.Timeout)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return nil
}

// Service is deliver: intake, reconciliation scan and sender.
type Service struct {
	cfg    Config
	store  Store
	log    AttemptLog
	signer Signer
	client *http.Client
	logger *slog.Logger

	comp      *obs.Component
	busState  func() string
	spans     obs.Spans
	firstHist prometheus.Histogram
	results   *prometheus.CounterVec

	// sem bounds the attempts in flight (E-10); wake asks the sender to
	// claim now.
	sem      chan struct{}
	wake     chan struct{}
	inFlight atomic.Int64
	wg       sync.WaitGroup
}

// Options are what a Service writes to.
type Options struct {
	Status     *obs.Status
	Registerer prometheus.Registerer
	Logger     *slog.Logger
	// BusState says the broker's state for the status line; nil: "none".
	BusState func() string
	// Spans starts the delivery spans (claim, sign, post under one
	// delivery_attempt span per attempt); the zero value starts none.
	Spans obs.Spans
}

// New builds a Service. It refuses a Config without an instance, an
// issuer or a public base URL, and a lease no longer than the timeout.
func New(cfg Config, st Store, log AttemptLog, signer Signer, opts Options) (*Service, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	if st == nil || signer == nil {
		return nil, errors.New("deliver: a store and a signer are required")
	}
	if opts.Status == nil {
		opts.Status = obs.NewStatus("deliver", nil, time.Now())
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	if opts.BusState == nil {
		opts.BusState = func() string { return "none" }
	}
	s := &Service{
		cfg: cfg, store: st, log: log, signer: signer, logger: opts.Logger,
		comp: opts.Status.Component(Component), busState: opts.BusState, spans: opts.Spans,
		sem: make(chan struct{}, cfg.MaxInFlight), wake: make(chan struct{}, 1),
	}
	s.client = newClient(cfg)
	s.firstHist = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    MetricFirstAttemptSeconds,
		Help:    "Seconds from a change's commit (changes.at) to the end of its first delivery attempt.",
		Buckets: []float64{.05, .1, .25, .5, .75, 1, 1.5, 2, 3, 5, 10, 30},
	})
	s.results = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: MetricResultTotal,
		Help: "Delivery attempts by result: the HTTP status code, or timeout, redirect, ssrf_refused, payload_too_large, error.",
	}, []string{"code"})
	if opts.Registerer != nil {
		for _, c := range []prometheus.Collector{s.firstHist, s.results} {
			if err := opts.Registerer.Register(c); err != nil {
				var already prometheus.AlreadyRegisteredError
				if !errors.As(err, &already) {
					s.comp.SetDegraded("metric not registered: " + err.Error())
				}
			}
		}
	}
	// Every counter and gauge exists from the start, at zero, so the
	// healthy line names them (E-09).
	for _, name := range []string{CounterIntakeDeliveries, CounterScanDeliveries, CounterScans, CounterBusPoison, CounterDelivered,
		CounterFailed, CounterExpired, CounterSSRFRefused, CounterSuspended, CounterLogWriteFailed, CounterPayloadTooLarge} {
		s.counter(name)
	}
	for _, name := range []string{GaugeQueued, GaugeDue, GaugeOldestDueS, GaugeInFlight, GaugeSuspended} {
		s.gauge(name)
	}
	return s, nil
}

func (s *Service) counter(name string) *obs.Counter {
	return s.comp.Counter(name, "Webhook delivery ("+name+").")
}

func (s *Service) gauge(name string) *obs.Gauge {
	return s.comp.Gauge(name, "Webhook delivery ("+name+").")
}

func (s *Service) now() time.Time { return s.cfg.Now().UTC() }

// Wake asks the sender to claim now (after an intake or an api ping).
func (s *Service) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// InFlight is the attempts running now.
func (s *Service) InFlight() int64 { return s.inFlight.Load() }

// Probe reads the queue into the gauges and the status line's summary;
// a queue it cannot read degrades the component, and reading it again
// heals it.
func (s *Service) Probe(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	q, err := s.store.DeliveryQueue(ctx, s.now())
	inFlight := s.InFlight()
	s.gauge(GaugeInFlight).Set(float64(inFlight))
	if err != nil {
		s.comp.SetDegraded("queue not read: " + err.Error())
		s.comp.SetSummary(fmt.Sprintf("queue unknown, %d in flight, broker %s", inFlight, s.busState()))
		return
	}
	s.comp.SetHealthy()
	s.gauge(GaugeQueued).Set(float64(q.Queued))
	s.gauge(GaugeDue).Set(float64(q.Due))
	s.gauge(GaugeOldestDueS).Set(q.OldestDueAge.Seconds())
	s.gauge(GaugeSuspended).Set(float64(q.Suspended))
	s.comp.SetSummary(Summary(q, inFlight, s.busState()))
}

// Summary is the status line's reading of the queue: "0 queued, 0 due,
// oldest due 0 s, 0 in flight, broker connected".
func Summary(q store.QueueStats, inFlight int64, broker string) string {
	return fmt.Sprintf("%d queued, %d due, oldest due %d s, %d in flight, broker %s",
		q.Queued, q.Due, int64(q.OldestDueAge/time.Second), inFlight, broker)
}
