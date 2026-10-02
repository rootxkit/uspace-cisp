package obs

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// NewRegistry returns a Prometheus registry with the Go runtime and
// process collectors registered.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return reg
}

// Status is the one place a process's components count into. Every
// counter and gauge is also a Prometheus metric (cisp_<name>_total and
// cisp_<name>, labelled by component), and Log prints all of them in one
// status line: at info when every component is healthy, at warning when
// one reports a warning and none is degraded, at error when any reports
// degraded (LESSONS E-09: silence is indistinguishable from health).
type Status struct {
	process string
	reg     prometheus.Registerer
	started time.Time

	mu         sync.Mutex
	components map[string]*Component
	counterVec map[string]*prometheus.CounterVec
	gaugeVec   map[string]*prometheus.GaugeVec
	probes     []func(context.Context)
	regErrors  []string
	// checkCatalogue refuses (warns about) names outside Catalogue.
	checkCatalogue bool
	uncatalogued   []string
	lines          int
}

// NewStatus returns an empty Status for process, registering metrics in
// reg (nil: metrics are kept only in the status line).
func NewStatus(process string, reg prometheus.Registerer, now time.Time) *Status {
	return &Status{
		process:    process,
		reg:        reg,
		started:    now,
		components: map[string]*Component{},
		counterVec: map[string]*prometheus.CounterVec{},
		gaugeVec:   map[string]*prometheus.GaugeVec{},
	}
}

// Component returns the named component, creating it on first use.
func (s *Status) Component(name string) *Component {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.components[name]
	if !ok {
		c = &Component{name: name, status: s, counters: map[string]*Counter{}, gauges: map[string]*Gauge{}}
		s.components[name] = c
	}
	return c
}

// CheckCatalogue makes every counter and gauge registered from now on
// a name of Catalogue: one outside it is still counted, and the status
// line warns and names it ("metrics": uncatalogued), so a metric nobody
// documented is seen at the first line. The processes turn it on; unit
// tests of other packages keep their ad hoc names.
func (s *Status) CheckCatalogue() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkCatalogue = true
}

func (s *Status) noteCatalogue(full string) {
	if s.checkCatalogue && !Catalogued(full) {
		s.uncatalogued = append(s.uncatalogued, full)
	}
}

// Uncatalogued is every metric registered outside Catalogue since
// CheckCatalogue.
func (s *Status) Uncatalogued() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.uncatalogued...)
}

// AddProbe registers a function run before every status line, so a
// component can refresh its degraded state (a database ping, say).
func (s *Status) AddProbe(probe func(context.Context)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probes = append(s.probes, probe)
}

var metricName = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func (s *Status) registerError(name string, err error) {
	s.regErrors = append(s.regErrors, name+": "+err.Error())
}

func (s *Status) counterFor(name, help, component string) prometheus.Counter {
	s.mu.Lock()
	defer s.mu.Unlock()
	vec, ok := s.counterVec[name]
	if !ok {
		vec = prometheus.NewCounterVec(prometheus.CounterOpts{Name: counterName(name), Help: help}, []string{"component"})
		s.noteCatalogue(counterName(name))
		if !metricName.MatchString(name) {
			s.registerError(name, errors.New("metric name must match "+metricName.String()))
		} else if s.reg != nil {
			if err := s.reg.Register(vec); err != nil {
				s.registerError(name, err)
			}
		}
		s.counterVec[name] = vec
	}
	return vec.WithLabelValues(component)
}

func (s *Status) gaugeFor(name, help, component string) prometheus.Gauge {
	s.mu.Lock()
	defer s.mu.Unlock()
	vec, ok := s.gaugeVec[name]
	if !ok {
		vec = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: gaugeName(name), Help: help}, []string{"component"})
		s.noteCatalogue(gaugeName(name))
		if !metricName.MatchString(name) {
			s.registerError(name, errors.New("metric name must match "+metricName.String()))
		} else if s.reg != nil {
			if err := s.reg.Register(vec); err != nil {
				s.registerError(name, err)
			}
		}
		s.gaugeVec[name] = vec
	}
	return vec.WithLabelValues(component)
}

// Degraded reports whether any component is degraded, or a metric failed
// to register.
func (s *Status) Degraded() bool {
	s.mu.Lock()
	comps := s.sortedComponents()
	regErrors := len(s.regErrors)
	s.mu.Unlock()
	if regErrors > 0 {
		return true
	}
	for _, c := range comps {
		if c.DegradedReason() != "" {
			return true
		}
	}
	return false
}

func (s *Status) sortedComponents() []*Component {
	comps := make([]*Component, 0, len(s.components))
	for _, c := range s.components {
		comps = append(comps, c)
	}
	sort.Slice(comps, func(i, j int) bool { return comps[i].name < comps[j].name })
	return comps
}

// Log runs the probes and writes one status line: every component with
// its counters (the count since the previous line; Prometheus has the
// totals), gauges, summary, warning and degraded reason. The line is at
// info when nothing is degraded or warned, at warning when a component
// warns and none is degraded, and at error when anything is degraded.
// The first line after start carries "start": true: it is the line
// that says what the process found.
func (s *Status) Log(ctx context.Context, logger *slog.Logger, now time.Time) {
	s.mu.Lock()
	probes := append([]func(context.Context){}, s.probes...)
	s.mu.Unlock()
	for _, probe := range probes {
		probe(ctx)
	}

	s.mu.Lock()
	comps := s.sortedComponents()
	regErrors := append([]string{}, s.regErrors...)
	uncatalogued := append([]string{}, s.uncatalogued...)
	first := s.lines == 0
	s.lines++
	s.mu.Unlock()

	level := slog.LevelInfo
	var degraded, warned []string
	attrs := []slog.Attr{slog.Int64("uptime_s", int64(now.Sub(s.started)/time.Second))}
	if first {
		attrs = append(attrs, slog.Bool("start", true))
	}
	for _, c := range comps {
		group, reason, warning := c.attrs()
		if reason != "" {
			degraded = append(degraded, c.name)
		}
		if warning != "" {
			warned = append(warned, c.name)
		}
		attrs = append(attrs, slog.Attr{Key: c.name, Value: slog.GroupValue(group...)})
	}
	if len(regErrors) > 0 {
		degraded = append(degraded, "metrics")
		attrs = append(attrs, slog.Any("metric_register_errors", regErrors))
	}
	if len(uncatalogued) > 0 {
		warned = append(warned, "metrics")
		attrs = append(attrs, slog.Any("metrics_uncatalogued", uncatalogued))
	}
	if len(warned) > 0 {
		level = slog.LevelWarn
		attrs = append(attrs, slog.Any("warnings", warned))
	}
	if len(degraded) > 0 {
		level = slog.LevelError
		attrs = append(attrs, slog.Any("degraded", degraded))
	}
	logger.LogAttrs(ctx, level, "status", attrs...)
}

// Run writes a status line on every tick until ctx is done.
func (s *Status) Run(ctx context.Context, logger *slog.Logger, tick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick:
			s.Log(ctx, logger, now)
		}
	}
}

// Component is one part of a process (http, nats, database, ...) with
// its counters, gauges and degraded state.
type Component struct {
	name   string
	status *Status

	mu       sync.Mutex
	counters map[string]*Counter
	gauges   map[string]*Gauge
	degraded string
	// since is when the component last went from healthy to degraded.
	since time.Time
	// warning is a condition worth a warning-level status line that is
	// not a fault of this process (a silent publisher, say).
	warning string
	// summary is a one-line reading of the component for people
	// ("0 queued, 0 due"); it changes no level.
	summary string
}

// Counter returns the named counter of this component, creating and
// registering it on first use. name is snake_case without the cisp_
// prefix or the _total suffix.
func (c *Component) Counter(name, help string) *Counter {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctr, ok := c.counters[name]; ok {
		return ctr
	}
	ctr := &Counter{prom: c.status.counterFor(name, help, c.name)}
	c.counters[name] = ctr
	return ctr
}

// Gauge returns the named gauge of this component, creating and
// registering it on first use.
func (c *Component) Gauge(name, help string) *Gauge {
	c.mu.Lock()
	defer c.mu.Unlock()
	if g, ok := c.gauges[name]; ok {
		return g
	}
	g := &Gauge{prom: c.status.gaugeFor(name, help, c.name)}
	c.gauges[name] = g
	return g
}

// SetDegraded marks the component degraded with a reason; an empty
// reason marks it healthy.
// The since-time is kept while the component stays degraded, whatever
// the reason becomes.
func (c *Component) SetDegraded(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case reason == "":
		c.since = time.Time{}
	case c.degraded == "":
		c.since = time.Now().UTC()
	}
	c.degraded = reason
}

// DegradedSince is the reason the component is degraded and since when;
// "" and the zero time when it is healthy.
func (c *Component) DegradedSince() (string, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.degraded, c.since
}

// Degradation is one degraded component.
type Degradation struct {
	Component string
	Reason    string
	Since     time.Time
}

// Degradations is every degraded component, by name.
func (s *Status) Degradations() []Degradation {
	s.mu.Lock()
	comps := s.sortedComponents()
	s.mu.Unlock()
	var out []Degradation
	for _, c := range comps {
		if reason, since := c.DegradedSince(); reason != "" {
			out = append(out, Degradation{Component: c.name, Reason: reason, Since: since})
		}
	}
	return out
}

// SetWarning marks the component with a warning; an empty reason clears
// it. A warning raises the status line to warning level, never to error,
// and is independent of the degraded state.
func (c *Component) SetWarning(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warning = reason
}

// SetSummary sets the component's one-line reading, printed as summary
// in every status line ("0 queued, 0 due, 0 in flight"); "" removes it.
// It changes no level: the branch that says nothing is wrong prints it
// too (E-02).
func (c *Component) SetSummary(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.summary = s
}

// Warning is the component's warning, or "".
func (c *Component) Warning() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.warning
}

// SetHealthy clears the degraded state.
func (c *Component) SetHealthy() { c.SetDegraded("") }

// DegradedReason is the reason the component is degraded, or "".
func (c *Component) DegradedReason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.degraded
}

func (c *Component) attrs() ([]slog.Attr, string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := make([]string, 0, len(c.counters)+len(c.gauges))
	for n := range c.counters {
		names = append(names, n)
	}
	for n := range c.gauges {
		names = append(names, n)
	}
	sort.Strings(names)
	attrs := make([]slog.Attr, 0, len(names)+1)
	for _, n := range names {
		if ctr, ok := c.counters[n]; ok {
			attrs = append(attrs, slog.Uint64(n, ctr.sinceLast()))
		}
		if g, ok := c.gauges[n]; ok {
			attrs = append(attrs, slog.Float64(n, g.Value()))
		}
	}
	if c.summary != "" {
		attrs = append(attrs, slog.String("summary", c.summary))
	}
	if c.warning != "" {
		attrs = append(attrs, slog.String("warning", c.warning))
	}
	if c.degraded != "" {
		attrs = append(attrs, slog.String("degraded", c.degraded))
	}
	return attrs, c.degraded, c.warning
}

// Counter is a monotonic count exported to Prometheus and shown in the
// status line as the count since the previous line.
type Counter struct {
	v      atomic.Uint64
	logged atomic.Uint64
	prom   prometheus.Counter
}

// sinceLast is the count since the previous call (the previous line).
func (c *Counter) sinceLast() uint64 {
	v := c.v.Load()
	return v - c.logged.Swap(v)
}

// Inc adds one.
func (c *Counter) Inc() { c.Add(1) }

// Add adds n.
func (c *Counter) Add(n uint64) {
	c.v.Add(n)
	c.prom.Add(float64(n))
}

// Value is the current count.
func (c *Counter) Value() uint64 { return c.v.Load() }

// Gauge is a value that goes up and down, shown in the status line and
// exported to Prometheus.
type Gauge struct {
	bits atomic.Uint64
	prom prometheus.Gauge
}

// Set sets the value.
func (g *Gauge) Set(v float64) {
	g.bits.Store(math.Float64bits(v))
	g.prom.Set(v)
}

// Value is the current value.
func (g *Gauge) Value() float64 { return math.Float64frombits(g.bits.Load()) }

// CounterSource is a set of named counts kept elsewhere (core.Counters).
type CounterSource interface {
	Get(name string) uint64
}

// MirrorCounters returns a probe that copies the named counts of src
// into comp's counters (and so into Prometheus and the status line)
// before every status line: each call adds what src counted since the
// previous one.
func MirrorCounters(comp *Component, src CounterSource, help string, names ...string) func(context.Context) {
	var mu sync.Mutex
	seen := map[string]uint64{}
	return func(context.Context) {
		mu.Lock()
		defer mu.Unlock()
		for _, n := range names {
			v := src.Get(n)
			if v > seen[n] {
				comp.Counter(n, help+" ("+n+").").Add(v - seen[n])
			} else {
				comp.Counter(n, help+" ("+n+").")
			}
			seen[n] = v
		}
	}
}
