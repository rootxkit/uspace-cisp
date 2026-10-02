// Command subscriber is the reference F3 webhook receiver the e2e tests
// (and the lab) run in a container: it listens at POST
// /v1/cis/notifications (the ecosystem path, M1), verifies each compact
// JWS against the CISP's JWKS with aud = its own host (core's
// CompactVerifier), records every notification as a JSON line on stdout
// and at GET /received, answers 204, and pulls pull_url only for a
// publication or restriction reason and only when its host is the
// CISP's public host (M5): subscription_test, republished and unknown
// reasons are acknowledged without pulling (M16).
//
// Environment: CISP_JWKS_URL, CISP_ISSUER_URL, CISP_PUBLIC_BASE_URL,
// SUBSCRIBER_AUDIENCE (this receiver's host as the callback names it),
// SUBSCRIBER_TOKEN (bearer for the pulls, optional), LISTEN_ADDR
// (:8080), FAIL_FIRST (answer the first n notifications 500), SLOW_MS
// (delay every answer).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	coreauth "github.com/rootxkit/uspace-core/auth"
)

// pullReasons are the reasons that change content (M16); every other
// reason, known or not, is acknowledged without a pull.
var pullReasons = map[string]bool{
	"publication": true, "restriction_created": true, "restriction_activated": true, "restriction_extended": true,
	"restriction_ended": true, "restriction_cancelled": true, "restriction_expired": true,
}

// record is one notification as received.
type record struct {
	ReceivedAt time.Time `json:"received_at"`
	DeliveryID string    `json:"delivery_id"`
	ChangeID   string    `json:"change_id"`
	Reason     string    `json:"reason"`
	Dataset    string    `json:"dataset,omitempty"`
	Verified   bool      `json:"verified"`
	Pulled     bool      `json:"pulled"`
	Note       string    `json:"note,omitempty"`
}

type config struct {
	jwksURL, issuer, publicBase, audience, token string
	failFirst                                    int
	slow                                         time.Duration
}

type receiver struct {
	cfg    config
	client *http.Client
	out    io.Writer

	mu       sync.Mutex
	verifier *coreauth.CompactVerifier
	fetched  time.Time
	records  []record
	seen     int
	pulls    sync.WaitGroup
}

func newReceiver(cfg config, out io.Writer) *receiver {
	return &receiver{cfg: cfg, client: &http.Client{Timeout: 5 * time.Second}, out: out}
}

// verify verifies a token; on a refusal it fetches the JWKS again once,
// when the last fetch is older than 10 s (the CISP may have rotated).
func (r *receiver) verify(ctx context.Context, token string) (json.RawMessage, error) {
	r.mu.Lock()
	v, age := r.verifier, time.Since(r.fetched)
	r.mu.Unlock()
	if v != nil {
		_, body, err := v.Verify(ctx, token)
		if err == nil || age < 10*time.Second {
			return body, err
		}
	}
	set, err := r.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	v, err = coreauth.NewCompactVerifier(ctx, coreauth.CompactConfig{
		Issuers: map[string]coreauth.IssuerConfig{r.cfg.issuer: {Keys: set}}, Audiences: []string{r.cfg.audience},
	})
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.verifier, r.fetched = v, time.Now()
	r.mu.Unlock()
	_, body, err := v.Verify(ctx, token)
	return body, err
}

func (r *receiver) fetchJWKS(ctx context.Context) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.cfg.jwksURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	return jwk.Parse(raw)
}

func (r *receiver) add(rec record) {
	line, _ := json.Marshal(rec)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, rec)
	_, _ = r.out.Write(append(line, '\n'))
}

func (r *receiver) received() []record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]record{}, r.records...)
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/received":
		raw, _ := json.Marshal(r.received())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
		return
	case req.Method != http.MethodPost || req.URL.Path != "/v1/cis/notifications":
		http.NotFound(w, req)
		return
	}
	rec := record{ReceivedAt: time.Now().UTC(), DeliveryID: req.Header.Get("X-CIS-Delivery-Id")}
	time.Sleep(r.cfg.slow)
	r.mu.Lock()
	r.seen++
	fail := r.seen <= r.cfg.failFirst
	r.mu.Unlock()
	if fail {
		rec.Note = "FAIL_FIRST"
		r.add(rec)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	token, _ := io.ReadAll(io.LimitReader(req.Body, 64<<10))
	body, err := r.verify(req.Context(), strings.TrimSpace(string(token)))
	if err != nil {
		rec.Note = "refused: " + err.Error()
		r.add(rec)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rec.Verified = true
	var change struct {
		MsgID   string `json:"msg_id"`
		Reason  string `json:"reason"`
		Dataset string `json:"dataset"`
		PullURL string `json:"pull_url"`
	}
	_ = json.Unmarshal(body, &change)
	rec.ChangeID, rec.Reason, rec.Dataset = change.MsgID, change.Reason, change.Dataset
	w.WriteHeader(http.StatusNoContent)
	switch {
	case !pullReasons[change.Reason]:
		rec.Note = "acknowledged without pulling"
	case !sameHost(change.PullURL, r.cfg.publicBase):
		rec.Note = "pull_url refused: not the CISP's host"
	default:
		// The answer goes first; the pull follows it.
		r.pulls.Add(1)
		go func() {
			defer r.pulls.Done()
			rec.Pulled = r.pull(change.PullURL)
			r.add(rec)
		}()
		return
	}
	r.add(rec)
}

func sameHost(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	return errA == nil && errB == nil && ua.Host != "" && strings.EqualFold(ua.Host, ub.Host)
}

// pull GETs the delta; true on a 200.
func (r *receiver) pull(u string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return false
	}
	if r.cfg.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.cfg.token)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<20))
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg := config{
		jwksURL: os.Getenv("CISP_JWKS_URL"), issuer: os.Getenv("CISP_ISSUER_URL"), publicBase: os.Getenv("CISP_PUBLIC_BASE_URL"),
		audience: os.Getenv("SUBSCRIBER_AUDIENCE"), token: os.Getenv("SUBSCRIBER_TOKEN"),
	}
	cfg.failFirst, _ = strconv.Atoi(os.Getenv("FAIL_FIRST"))
	ms, _ := strconv.Atoi(os.Getenv("SLOW_MS"))
	cfg.slow = time.Duration(ms) * time.Millisecond
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if cfg.jwksURL == "" || cfg.issuer == "" || cfg.audience == "" || cfg.publicBase == "" {
		logger.Error("CISP_JWKS_URL, CISP_ISSUER_URL, CISP_PUBLIC_BASE_URL and SUBSCRIBER_AUDIENCE are required")
		os.Exit(2) //nolint:forbidigo // main: a configuration refused
	}
	srv := &http.Server{Addr: addr, Handler: newReceiver(cfg, os.Stdout), ReadHeaderTimeout: 5 * time.Second}
	logger.Info("listening", "addr", addr, "audience", cfg.audience, "fail_first", cfg.failFirst)
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("serve", "error", err.Error())
		os.Exit(1) //nolint:forbidigo // main: the listener failed
	}
}
