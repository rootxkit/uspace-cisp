package deliver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-cisp/internal/bus"
	"github.com/rootxkit/uspace-cisp/internal/publication"
	"github.com/rootxkit/uspace-cisp/internal/store"
	"github.com/rootxkit/uspace-cisp/internal/subscription"
)

// SSRFError is a dial refused because the address it resolved to is not
// public (the SSRF guard, docs/PLAN.md section 8.1).
type SSRFError struct{ Address string }

func (e *SSRFError) Error() string {
	return "refused at dial: " + e.Address + " is not a public address"
}

// newClient is the webhook client: the SSRF guard on the resolved
// address, no proxy, TLS 1.2 or later, no redirects followed, and every
// phase bounded by the timeout.
func newClient(cfg Config) *http.Client {
	pol := cfg.Policy
	dialer := &net.Dialer{
		Timeout: cfg.Timeout,
		// Control runs after resolution, once per address tried, with
		// the address the socket connects to: the guard judges that,
		// never the name (a name can resolve anywhere).
		ControlContext: func(_ context.Context, _, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return &SSRFError{Address: address}
			}
			if !subscription.AllowedAddress(net.ParseIP(host), pol) {
				return &SSRFError{Address: host}
			}
			return nil
		},
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
		TLSHandshakeTimeout:    cfg.Timeout,
		ResponseHeaderTimeout:  cfg.Timeout,
		ExpectContinueTimeout:  time.Second,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           cfg.MaxInFlight,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		// A 3xx is the answer, and a failure: a subscriber's redirect is
		// never followed (it could point anywhere).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Audience is the aud of a webhook: the host of the callback URL,
// lower-case, without its port (M19: the audience rule of M18 applied
// to webhooks).
func Audience(callbackURL string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("deliver: callback URL has no host")
	}
	return strings.ToLower(u.Hostname()), nil
}

// Body is the cis/change/v1 record of a delivery: the change's record
// as the bus and the change feed carry it, with producer this instance;
// for a ping (no change), the subscription_test record of its first
// dataset at that dataset's current version.
func (s *Service) Body(cl store.Claim, c *publication.Change, versions map[publication.Dataset]int64) bus.ChangeMessage {
	if c != nil {
		m := bus.MessageOf(*c, s.cfg.PublicBaseURL)
		m.Producer = ProducerPrefix + s.cfg.Instance
		return m
	}
	ds := publication.DatasetZones
	if len(cl.Datasets) > 0 {
		ds = cl.Datasets[0]
	}
	v := versions[ds]
	return bus.ChangeMessage{
		Schema: bus.SchemaChange, MsgID: cl.DeliveryID, Producer: ProducerPrefix + s.cfg.Instance,
		Dataset: string(ds), Version: v, ETag: publication.ETag(ds, v), FeatureIDs: []string{}, RemovedIDs: []string{},
		Reason: string(publication.ReasonSubscriptionTest), At: cl.CreatedAt.UTC(),
		PullURL: strings.TrimSuffix(s.cfg.PublicBaseURL, "/") + "/v1/" + string(ds) + "?since_version=" + strconv.FormatInt(v, 10),
	}
}

// Sign is the compact JWS of a delivery: core's SignCompact with iss
// the CISP's issuer URL, aud the callback's host, sub the subscription
// and jti the delivery id.
func (s *Service) Sign(cl store.Claim, body bus.ChangeMessage, now time.Time) (string, error) {
	aud, err := Audience(cl.CallbackURL)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("deliver: encode body: %w", err)
	}
	return s.signer.SignCompact(coreauth.CompactClaims{
		Issuer: s.cfg.IssuerURL, Audience: aud, Subject: cl.SubscriptionID, JTI: cl.DeliveryID,
	}, raw, now)
}

// Outcome is what one POST came to.
type Outcome struct {
	// StatusCode is 0 when no response arrived.
	StatusCode int
	// Err says why it failed; nil for a 2xx.
	Err error
	// Code labels cisp_delivery_result_total: the status code, or
	// timeout, ssrf_refused, error.
	Code    string
	Latency time.Duration
}

// OK reports a 2xx.
func (o Outcome) OK() bool { return o.Err == nil }

// Post sends a signed delivery to the callback and reads at most
// MaxResponseBytes of the answer. The URL is checked again for its
// shape (scheme, userinfo, fragment); its name was judged at
// registration and its address is judged at dial.
func (s *Service) Post(ctx context.Context, cl store.Claim, token string) Outcome {
	start := time.Now()
	out := func(code int, label string, err error) Outcome {
		return Outcome{StatusCode: code, Code: label, Err: err, Latency: time.Since(start)}
	}
	shape := subscription.URLPolicy{AllowPrivate: true, AllowInsecure: s.cfg.Policy.AllowInsecure}
	if err := subscription.ValidateCallbackURL(cl.CallbackURL, shape); err != nil {
		return out(0, "error", err)
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cl.CallbackURL, strings.NewReader(token))
	if err != nil {
		return out(0, "error", fmt.Errorf("request: %w", err))
	}
	req.Header.Set("Content-Type", MediaJOSE)
	req.Header.Set("User-Agent", "uspace-cisp/"+s.cfg.Version)
	req.Header.Set(HeaderDeliveryID, cl.DeliveryID)
	req.Header.Set(HeaderAttempt, strconv.Itoa(cl.Attempts+1))
	resp, err := s.client.Do(req)
	if err != nil {
		var ssrf *SSRFError
		var ne net.Error
		switch {
		case errors.As(err, &ssrf):
			s.counter(CounterSSRFRefused).Inc()
			return out(0, "ssrf_refused", ssrf)
		case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
			return out(0, "timeout", fmt.Errorf("no answer within %s", s.cfg.Timeout))
		}
		return out(0, "error", fmt.Errorf("post: %w", err))
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, s.cfg.MaxResponseBytes))
	_ = resp.Body.Close()
	code := strconv.Itoa(resp.StatusCode)
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode <= 299:
		return out(resp.StatusCode, code, nil)
	case resp.StatusCode >= 300 && resp.StatusCode <= 399:
		return out(resp.StatusCode, code, fmt.Errorf("status %d: a redirect is not followed", resp.StatusCode))
	}
	return out(resp.StatusCode, code, fmt.Errorf("status %d", resp.StatusCode))
}

func truncate(s string) string {
	if len(s) <= MaxErrorChars {
		return s
	}
	return s[:MaxErrorChars-3] + "..."
}

// RunSender claims due deliveries and attempts them until ctx ends:
// at once when woken, otherwise every PollInterval. When ctx ends it
// stops claiming and waits at most DrainTimeout for the attempts in
// flight; a delivery still delivering after that is reclaimed by any
// instance once its lease runs out.
func (s *Service) RunSender(ctx context.Context) {
	tick := time.NewTicker(s.cfg.PollInterval)
	defer tick.Stop()
	for {
		for ctx.Err() == nil {
			n, err := s.Dispatch(ctx)
			if err != nil || n == 0 || len(s.sem) == cap(s.sem) {
				break
			}
		}
		select {
		case <-ctx.Done():
			s.drain()
			return
		case <-tick.C:
		case <-s.wake:
		}
	}
}

func (s *Service) drain() {
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		s.logger.Info("deliveries drained")
	case <-time.After(s.cfg.DrainTimeout):
		s.logger.Warn("deliveries still in flight after the drain timeout; their leases make them due again",
			slog.Int64("in_flight", s.InFlight()), slog.Duration("drain_timeout", s.cfg.DrainTimeout))
	}
}

// Wait waits for the attempts in flight (tests and shutdown).
func (s *Service) Wait() { s.wg.Wait() }

// Dispatch claims as many due deliveries as there are free slots and
// starts an attempt for each; it returns how many it claimed. The
// attempts run on their own deadline, not ctx's: a stop lets them finish.
func (s *Service) Dispatch(ctx context.Context) (int, error) {
	free := cap(s.sem) - len(s.sem)
	if free <= 0 {
		return 0, nil
	}
	now := s.now()
	claims, err := s.store.ClaimDeliveries(ctx, now, now.Add(s.cfg.Lease), free)
	if err != nil {
		if ctx.Err() == nil {
			s.counter(CounterClaimFailed).Inc()
			s.logger.Warn("deliveries not claimed", slog.String("error", err.Error()))
		}
		return 0, err
	}
	if len(claims) == 0 {
		return 0, nil
	}
	changes, versions, err := s.contextOf(ctx, claims)
	if err != nil {
		// The rows stay leased and become due again after Lease.
		s.counter(CounterClaimFailed).Inc()
		s.logger.Warn("claimed deliveries not prepared", slog.String("error", err.Error()))
		return len(claims), err
	}
	for i := range claims {
		cl := &claims[i]
		var c *publication.Change
		if cl.ChangeID != nil {
			ch, ok := changes[*cl.ChangeID]
			if !ok {
				s.counter(CounterClaimFailed).Inc()
				s.logger.Error("delivery names a change that does not exist", slog.String("delivery_id", cl.DeliveryID),
					slog.Int64("change_id", *cl.ChangeID))
				continue
			}
			c = &ch
		}
		s.sem <- struct{}{}
		s.inFlight.Add(1)
		s.wg.Add(1)
		go func(cl store.Claim, c *publication.Change) {
			defer func() {
				<-s.sem
				s.inFlight.Add(-1)
				s.wg.Done()
			}()
			s.Attempt(context.WithoutCancel(ctx), cl, c, versions)
		}(*cl, c)
	}
	return len(claims), nil
}

// contextOf reads the changes of the claims and, for pings, the dataset
// versions.
func (s *Service) contextOf(ctx context.Context, claims []store.Claim) (map[int64]publication.Change, map[publication.Dataset]int64, error) {
	var ids []int64
	pings := false
	for i := range claims {
		cl := &claims[i]
		if cl.ChangeID != nil {
			ids = append(ids, *cl.ChangeID)
		} else {
			pings = true
		}
	}
	changes, err := s.store.ChangesByID(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	var versions map[publication.Dataset]int64
	if pings {
		if versions, err = s.store.DatasetVersions(ctx); err != nil {
			return nil, nil, err
		}
	}
	return changes, versions, nil
}

// Attempt makes one attempt of a claimed delivery and records it: the
// delivery_attempts row, the deliveries row, the subscription's run, the
// first-attempt latency and the result counter.
func (s *Service) Attempt(ctx context.Context, cl store.Claim, c *publication.Change, versions map[publication.Dataset]int64) {
	at := s.now()
	changeAt := cl.CreatedAt
	var changeID int64 = store.PingChangeID
	if c != nil {
		changeAt = c.At
		changeID = c.ID
	}
	body := s.Body(cl, c, versions)
	token, err := s.Sign(cl, body, at)
	var o Outcome
	if err != nil {
		s.counter(CounterSignFailed).Inc()
		o = Outcome{Code: "error", Err: fmt.Errorf("not signed: %w", err)}
	} else {
		o = s.Post(ctx, cl, token)
	}
	end := s.now()
	s.results.WithLabelValues(o.Code).Inc()
	if cl.Attempts == 0 {
		s.firstHist.Observe(end.Sub(changeAt).Seconds())
	}
	attempt := store.DeliveryAttempt{
		At: end, DeliveryID: cl.DeliveryID, SubscriptionID: cl.SubscriptionID, ChangeID: changeID, Attempt: cl.Attempts + 1,
		LatencyMs: int(o.Latency / time.Millisecond), PayloadBytes: len(token), Instance: s.cfg.Instance,
	}
	if o.StatusCode != 0 {
		code := o.StatusCode
		attempt.StatusCode = &code
	}
	var errText string
	if o.Err != nil {
		errText = truncate(o.Err.Error())
		attempt.Error = &errText
	}
	if s.log != nil {
		if err := s.log.Record(ctx, attempt); err != nil {
			s.counter(CounterLogWriteFailed).Inc()
			s.logger.Warn("delivery attempt not logged", slog.String("delivery_id", cl.DeliveryID), slog.String("error", err.Error()))
		}
	}
	attrs := []any{
		slog.String("delivery_id", cl.DeliveryID), slog.String("subscription_id", cl.SubscriptionID),
		slog.Int64("change_id", changeID), slog.Int("attempt", cl.Attempts+1), slog.String("result", o.Code),
		slog.Int64("latency_ms", int64(o.Latency/time.Millisecond)),
	}
	if o.OK() {
		s.finishDelivered(ctx, cl, end, o.StatusCode, attrs)
		return
	}
	s.finishFailed(ctx, cl, changeAt, end, o, errText, attrs)
}

func (s *Service) finishDelivered(ctx context.Context, cl store.Claim, end time.Time, code int, attrs []any) {
	d, err := s.store.FinishDelivered(ctx, cl.DeliveryID, cl.SubscriptionID, end, code)
	if err != nil {
		s.counter(CounterRecordFailed).Inc()
		s.logger.Error("delivered but not recorded; the lease will send it again",
			append(attrs, slog.String("error", err.Error()))...)
		return
	}
	s.counter(CounterDelivered).Inc()
	s.logger.Debug("delivered", attrs...)
	if d.Verified {
		s.counter(CounterVerified).Inc()
		s.logger.Info("subscription verified", slog.String("subscription_id", cl.SubscriptionID),
			slog.String("delivery_id", cl.DeliveryID))
	}
}

func (s *Service) finishFailed(ctx context.Context, cl store.Claim, changeAt, end time.Time, o Outcome, errText string, attrs []any) {
	f := store.FailedAttempt{DeliveryID: cl.DeliveryID, SubscriptionID: cl.SubscriptionID, At: end, Error: errText}
	if o.StatusCode != 0 {
		code := o.StatusCode
		f.StatusCode = &code
	}
	next, ok := subscription.NextAttempt(cl.Attempts+1, changeAt, end, s.cfg.Retry)
	if ok {
		f.NextRetryAt = &next
	} else {
		f.Expire = true
	}
	res, err := s.store.FinishFailed(ctx, f)
	if err != nil {
		s.counter(CounterRecordFailed).Inc()
		s.logger.Error("failed attempt not recorded; the lease will try it again",
			append(attrs, slog.String("error", err.Error()))...)
		return
	}
	s.counter(CounterFailed).Inc()
	if res.State == store.DeliveryExpired {
		s.counter(CounterExpired).Inc()
		s.logger.Warn("delivery expired", append(attrs, slog.String("error", errText))...)
	} else {
		s.logger.Info("delivery failed", append(attrs, slog.String("error", errText), slog.Time("next_retry_at", next))...)
	}
	if res.SubscriptionStatus == subscription.Active && subscription.ShouldSuspend(res.ConsecutiveFailures, res.FailingSince, end) {
		reason := fmt.Sprintf("%d consecutive failures since %s; last: %s", res.ConsecutiveFailures,
			res.FailingSince.UTC().Format(time.RFC3339), errText)
		suspended, err := s.store.SuspendSubscription(ctx, cl.SubscriptionID, truncate(reason))
		if err != nil {
			s.counter(CounterRecordFailed).Inc()
			s.logger.Error("subscription not suspended", slog.String("subscription_id", cl.SubscriptionID), slog.String("error", err.Error()))
			return
		}
		if suspended {
			s.counter(CounterSuspended).Inc()
			s.logger.Warn("subscription suspended", slog.String("subscription_id", cl.SubscriptionID), slog.String("reason", reason))
		}
	}
}
