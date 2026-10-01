package httpapi

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-cisp/internal/obs"
)

// ServeOptions configure Serve.
type ServeOptions struct {
	// Addr is the listen address (host:port; port 0 picks a free one,
	// and the "listening" log line names it).
	Addr string
	// ShutdownTimeout bounds the wait for in-flight requests on stop.
	ShutdownTimeout time.Duration
	// StatusInterval is the period of the status line.
	StatusInterval time.Duration
}

// Serve listens on opts.Addr and serves h until ctx ends, writing the
// status line at start and every StatusInterval. On stop the listener
// closes at once and in-flight requests get ShutdownTimeout to finish.
// It returns the process exit code: 0 for a clean stop, 1 when the
// listener could not open, serving failed, or shutdown ran out of time.
func Serve(ctx context.Context, opts ServeOptions, h http.Handler, status *obs.Status, logger *slog.Logger) int {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", opts.Addr)
	if err != nil {
		logger.ErrorContext(ctx, "listen refused", "addr", opts.Addr, "error", err.Error())
		return 1
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	logger.InfoContext(ctx, "listening", "addr", ln.Addr().String())
	status.Log(ctx, logger, time.Now())

	interval := opts.StatusInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	statusCtx, stopStatus := context.WithCancel(context.WithoutCancel(ctx))
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		defer close(done)
		status.Run(statusCtx, logger, ticker.C)
	}()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	code := 0
	select {
	case <-ctx.Done():
		logger.Info("stopping", "reason", "signal")
	case err := <-serveErr:
		logger.Error("serve failed", "error", err.Error())
		code = 1
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opts.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown did not finish in time", "error", err.Error())
		code = 1
	}
	ticker.Stop()
	stopStatus()
	<-done
	return code
}
