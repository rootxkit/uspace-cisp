package stream

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// Defaults of the hub (docs/WORKPACKAGES/WP-7.md; the processes take
// them from CISP_STREAM_*).
const (
	DefaultMaxClients     = 1000
	DefaultSendBuffer     = 64
	DefaultStatusInterval = 2 * time.Second
	DefaultWriteTimeout   = 5 * time.Second
	DefaultLiveMaxAge     = 6 * time.Second
	// closeTimeout bounds the goroutine that closes a client: the close
	// frame of a client that does not read is never written, and the
	// connection is dropped after it.
	closeTimeout = 5 * time.Second
	logEvery     = time.Minute
)

// Close codes the stream sends.
const (
	// CloseTryAgainLater (1013): the client could not keep up.
	CloseTryAgainLater = websocket.StatusTryAgainLater
	// CloseRelogin (4401): no or an invalid session on a non-public
	// stream; the console logs in again (M22).
	CloseRelogin websocket.StatusCode = 4401
	// CloseGoingAway (1001): the instance stops.
	CloseGoingAway = websocket.StatusGoingAway
)

// Component is the status component the hub counts into.
const Component = "stream"

// Counter and gauge names (docs/RUNBOOKS/observability.md).
const (
	GaugeClients           = "stream_clients"
	CounterClientsDropped  = "stream_clients_dropped"
	CounterRefusedCapacity = "stream_refused_capacity"
	CounterRefusedOrigin   = "stream_refused_origin"
	CounterRefusedRequest  = "stream_refused_request"
	CounterSessionRefused  = "stream_session_refused"
	CounterSessionIgnored  = "stream_session_ignored"
	CounterSessions        = "stream_sessions"
	CounterFramesSent      = "stream_frames_sent"
	CounterFramesDropped   = "stream_frames_dropped"
	CounterChanges         = "stream_changes"
	CounterResyncs         = "stream_resyncs"
)

// Parts is the console/status/v1 body every client shares at one
// instant; the hub adds connection_id, dropped_frames and resync_since
// per client. StatusSource builds it without touching a database.
type Parts struct {
	PolicyVersion string
	StaleAfterS   float64
	Degraded      []string
	DegradedSince map[string]time.Time
	Datasets      map[string]DatasetStatus
	CISAgeS       *float64
	NATS          bus.StateKind
	NATSSince     time.Time
	Publishers    []PublisherStatus
}

// StatusSource is what the hub's status frames are made of. It is called
// once per status period and on a resync, never per client, and must
// answer from memory.
type StatusSource func(now time.Time) Parts

// Config configures a Hub. Zero values take the defaults.
type Config struct {
	MaxClients     int
	SendBuffer     int
	StatusInterval time.Duration
	WriteTimeout   time.Duration
	LiveMaxAge     time.Duration
	// Producer is the envelope's producer (DefaultProducer).
	Producer string
	// Source builds the status; nil: an empty status naming nothing
	// degraded.
	Source StatusSource
	// Status counts into its stream component; nil: a private one.
	Status *obs.Status
	Logger *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

func (c *Config) defaults() {
	if c.MaxClients <= 0 {
		c.MaxClients = DefaultMaxClients
	}
	if c.SendBuffer <= 0 {
		c.SendBuffer = DefaultSendBuffer
	}
	if c.StatusInterval <= 0 {
		c.StatusInterval = DefaultStatusInterval
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = DefaultWriteTimeout
	}
	if c.LiveMaxAge <= 0 {
		c.LiveMaxAge = DefaultLiveMaxAge
	}
	if c.Producer == "" {
		c.Producer = DefaultProducer
	}
	if c.Source == nil {
		c.Source = func(time.Time) Parts { return Parts{} }
	}
	if c.Status == nil {
		c.Status = obs.NewStatus("api", nil, time.Now())
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// frameConn is the part of a WebSocket connection the hub writes to;
// *websocket.Conn through wsConn, and fakes in tests.
type frameConn interface {
	Write(ctx context.Context, frame []byte) error
	Close(code websocket.StatusCode, reason string) error
}

// Hub fans the bus's changes out to the stream's clients, with a status
// frame to each on connect and every status period. It never queries a
// database: changes come from the bus and the status from Source.
type Hub struct {
	cfg  Config
	comp *obs.Component

	ctx    context.Context
	cancel context.CancelFunc
	poke   chan struct{}

	countersMu sync.Mutex
	counters   map[string]*obs.Counter
	gauge      *obs.Gauge

	mu       sync.Mutex
	clients  map[*client]struct{}
	reserved int
	closed   bool
}

// NewHub returns a hub; Run sends its status frames.
func NewHub(cfg Config) *Hub {
	cfg.defaults()
	ctx, cancel := context.WithCancel(context.Background())
	h := &Hub{
		cfg: cfg, comp: cfg.Status.Component(Component),
		ctx: ctx, cancel: cancel, poke: make(chan struct{}, 1),
		clients: map[*client]struct{}{}, counters: map[string]*obs.Counter{},
	}
	h.gauge = h.comp.Gauge(GaugeClients, "WS /v1/stream clients connected to this instance.")
	h.gauge.Set(0)
	return h
}

// counter is the named counter of the stream component, looked up once.
func (h *Hub) counter(name string) *obs.Counter {
	h.countersMu.Lock()
	defer h.countersMu.Unlock()
	c, ok := h.counters[name]
	if !ok {
		c = h.comp.Counter(name, "The WS change stream ("+name+").")
		h.counters[name] = c
	}
	return c
}

// client is one connection.
type client struct {
	id       string
	datasets map[string]bool // nil: every dataset
	console  bool
	conn     frameConn
	send     chan []byte
	cancel   context.CancelFunc
	done     <-chan struct{}

	dropped atomic.Uint64
	// droppedTick is set when a frame was dropped since the last status
	// tick; a client still full at the tick is closed.
	droppedTick atomic.Bool
	resync      atomic.Pointer[time.Time]
	gone        sync.Once
}

func (c *client) wants(dataset string) bool {
	return c.datasets == nil || c.datasets[dataset]
}

// Len is the number of clients connected.
func (h *Hub) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// reserve takes a client slot, or reports the hub full (or closed).
func (h *Hub) reserve() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || len(h.clients)+h.reserved >= h.cfg.MaxClients {
		return false
	}
	h.reserved++
	return true
}

func (h *Hub) release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reserved--
}

// attach registers conn on a reserved slot, queues its first status and
// starts its writer. readDone is closed when the peer goes away.
func (h *Hub) attach(conn frameConn, datasets map[string]bool, console bool, readDone <-chan struct{}) {
	ctx, cancel := context.WithCancel(h.ctx)
	c := &client{
		id: NewULID(h.cfg.Now()), datasets: datasets, console: console, conn: conn,
		send: make(chan []byte, h.cfg.SendBuffer), cancel: cancel, done: ctx.Done(),
	}
	h.mu.Lock()
	h.reserved--
	h.clients[c] = struct{}{}
	n := len(h.clients)
	h.mu.Unlock()
	h.gauge.Set(float64(n))

	now := h.cfg.Now()
	if frame, err := h.statusFrame(c, h.cfg.Source(now), now, nil); err == nil {
		h.enqueue(c, frame)
	}
	go h.write(ctx, c)
	if readDone != nil {
		go func() {
			select {
			case <-readDone:
				h.detach(c, websocket.StatusNormalClosure, "")
			case <-ctx.Done():
			}
		}()
	}
}

// detach removes c and closes its connection with code; it runs once
// per client.
func (h *Hub) detach(c *client, code websocket.StatusCode, reason string) {
	c.gone.Do(func() {
		h.mu.Lock()
		delete(h.clients, c)
		n := len(h.clients)
		h.mu.Unlock()
		h.gauge.Set(float64(n))
		c.cancel()
		go func() { _ = c.conn.Close(code, reason) }() // a client that does not read never gets the close frame
	})
}

// write sends c's queued frames, each within WriteTimeout; a write that
// fails or times out ends the client.
func (h *Hub) write(ctx context.Context, c *client) {
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-c.send:
			wctx, cancel := context.WithTimeout(ctx, h.cfg.WriteTimeout)
			err := c.conn.Write(wctx, frame)
			cancel()
			if err != nil {
				h.detach(c, websocket.StatusGoingAway, "write failed")
				return
			}
			h.counter(CounterFramesSent).Inc()
		}
	}
}

// enqueue queues frame for c without blocking; a full queue drops it
// (dropped_frames) and marks the client for the next status tick.
func (h *Hub) enqueue(c *client, frame []byte) bool {
	select {
	case <-c.done:
		return false
	default:
	}
	select {
	case c.send <- frame:
		return true
	default:
		c.dropped.Add(1)
		c.droppedTick.Store(true)
		h.counter(CounterFramesDropped).Inc()
		return false
	}
}

// snapshot is the clients now.
func (h *Hub) snapshot() []*client {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*client, 0, len(h.clients))
	for c := range h.clients {
		out = append(out, c)
	}
	return out
}

// Publish fans a committed change out to every client that asked for
// its dataset: one frame, encoded once, queued without blocking.
func (h *Hub) Publish(m bus.ChangeMessage, rx time.Time) {
	h.counter(CounterChanges).Inc()
	at := m.At
	frame, err := frameOf(SchemaChange, h.cfg.Producer, &at, rx, at, m)
	if err != nil {
		h.cfg.Logger.Error("stream: change frame not encoded", "dataset", m.Dataset, "msg_id", m.MsgID, "error", err.Error())
		return
	}
	for _, c := range h.snapshot() {
		if c.wants(m.Dataset) {
			h.enqueue(c, frame)
		}
	}
}

// Resync tells every client, in a status frame sent now, that changes
// may have been missed since since (resync_since, once per client).
func (h *Hub) Resync(since time.Time) {
	h.counter(CounterResyncs).Inc()
	s := since.UTC()
	for _, c := range h.snapshot() {
		c.resync.Store(&s)
	}
	select {
	case h.poke <- struct{}{}:
	default:
	}
}

// Run sends the status frame to every client on every tick and after a
// resync, until ctx ends; then it closes every client (1001).
func (h *Hub) Run(ctx context.Context, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			h.Close()
			return
		case <-tick:
			h.Tick(h.cfg.Now())
		case <-h.poke:
			h.Tick(h.cfg.Now())
		}
	}
}

// Tick is one status period: a client that dropped a frame since the
// last tick and whose queue is still full is closed with 1013 and
// counted; every other client is sent the status.
func (h *Hub) Tick(now time.Time) {
	parts := h.cfg.Source(now)
	for _, c := range h.snapshot() {
		if c.droppedTick.Swap(false) && len(c.send) == cap(c.send) {
			h.counter(CounterClientsDropped).Inc()
			if ok, held := obs.Once("stream: slow client closed", logEvery); ok {
				h.cfg.Logger.Warn("stream: a client that could not keep up was closed with 1013",
					"connection_id", c.id, "dropped_frames", c.dropped.Load(), "also_closed_since_last_line", held)
			}
			h.detach(c, CloseTryAgainLater, "the client could not keep up")
			continue
		}
		since := c.resync.Swap(nil)
		frame, err := h.statusFrame(c, parts, now, since)
		if err != nil || !h.enqueue(c, frame) {
			if since != nil {
				c.resync.CompareAndSwap(nil, since) // the next status carries it
			}
		}
	}
}

// statusFrame is c's console/status/v1 frame at now.
func (h *Hub) statusFrame(c *client, p Parts, now time.Time, resync *time.Time) ([]byte, error) {
	body := StatusBody{
		ConnectionID: c.id, ServerTS: Timestamp(now), PolicyVersion: p.PolicyVersion,
		StaleAfterS: p.StaleAfterS, LiveMaxAgeS: h.cfg.LiveMaxAge.Seconds(),
		DroppedFrames: c.dropped.Load(), Degraded: p.Degraded, Sources: []json.RawMessage{},
		Datasets: p.Datasets, CISAgeS: p.CISAgeS, NATS: string(p.NATS),
		Publishers: p.Publishers,
	}
	if body.PolicyVersion == "" {
		body.PolicyVersion = "unknown"
	}
	if body.StaleAfterS <= 0 {
		body.StaleAfterS = 60
	}
	if body.Degraded == nil {
		body.Degraded = []string{}
	}
	if body.Publishers == nil {
		body.Publishers = []PublisherStatus{}
	}
	if len(p.DegradedSince) > 0 {
		body.DegradedSince = make(map[string]string, len(p.DegradedSince))
		for k, v := range p.DegradedSince {
			body.DegradedSince[k] = Timestamp(v)
		}
	}
	if !p.NATSSince.IsZero() && p.NATS != bus.StateConnected {
		body.NATSSince = Timestamp(p.NATSSince)
	}
	if resync != nil {
		body.ResyncSince = Timestamp(*resync)
	}
	return frameOf(SchemaStatus, h.cfg.Producer, &now, now, now, body)
}

// Close closes every client with 1001 and refuses new ones.
func (h *Hub) Close() {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	for _, c := range h.snapshot() {
		h.detach(c, CloseGoingAway, "the instance is stopping")
	}
	h.cancel()
}
