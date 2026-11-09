// Package runner serves the platform on Hertz with readiness publication and
// graceful shutdown. Entrypoints choose the Hertz engine and the platform's
// infrastructure drivers.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/platform"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/adaptor"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/network/standard"
)

// Options customizes Run for an entrypoint.
type Options struct {
	// Drivers are the platform's infrastructure clients.
	Drivers platform.Drivers
	// NewEngine builds the Hertz engine from the platform's server options;
	// nil uses server.New.
	NewEngine func(...config.Option) *server.Hertz
	// ListenAddress returns the address the engine will really bind for the
	// platform's configured address; nil keeps the configured address.
	ListenAddress func(configured string) string
	// WrapHandler wraps the platform's request handlers; nil serves them
	// unwrapped.
	WrapHandler func(app.HandlerFunc) app.HandlerFunc
}

func (o Options) wrap(handler app.HandlerFunc) app.HandlerFunc {
	if o.WrapHandler == nil {
		return handler
	}
	return o.WrapHandler(handler)
}

// Run serves until SIGINT/SIGTERM or a fatal server error.
func Run(opts Options) error {
	app, err := platform.NewFromEnvironment(opts.Drivers)
	if err != nil {
		return fmt.Errorf("initialize platform: %w", err)
	}
	defer app.Close()
	listenAddress := app.ListenAddress()
	if opts.ListenAddress != nil {
		listenAddress = opts.ListenAddress(listenAddress)
	}
	newEngine := opts.NewEngine
	if newEngine == nil {
		newEngine = server.New
	}

	h := newEngine(
		server.WithHostPorts(listenAddress),
		server.WithTransport(standard.NewTransporter),
		server.WithIdleTimeout(0),
		server.WithReadTimeout(0),
		server.WithWriteTimeout(0),
		server.WithMaxRequestBodySize(20<<20),
		server.WithExitWaitTime(5*time.Second),
		// Node writes no Content-Type unless the handler sets one (a 302
		// redirect, an empty 204). Hertz would otherwise stamp
		// "text/plain; charset=utf-8" on every such response.
		server.WithDisableDefaultContentType(true),
	)
	// Hijacked connections back WebSocket tunnels and raw peer forwarding. They
	// must never be returned to Hertz's connection pool.
	h.NoHijackConnPool = true
	handler := opts.wrap(adaptor.HertzHandler(app))
	for _, method := range []string{
		http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace,
	} {
		h.Handle(method, "/*path", handler)
	}
	h.HEAD("/*path", opts.wrap(hertzHeadHandler(app)))
	// Application-owned WebSockets are intentionally long lived. Close them as
	// part of Hertz's shutdown hook so the transport's active-connection wait
	// can actually drain; waiting for the deferred app.Close would otherwise
	// leave Shutdown blocked until its timeout whenever a daemon is connected.
	h.OnShutdown = append(h.OnShutdown, func(context.Context) {
		if err := app.Close(); err != nil {
			slog.Warn("close platform during shutdown", "error", err)
		}
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := app.MarkNotReady(); err != nil {
		return fmt.Errorf("publish initial not-ready status: %w", err)
	}
	return superviseHertz(
		ctx,
		h,
		func(readyCtx context.Context) error {
			return waitForHTTPReady(readyCtx, listenAddress, 10*time.Second)
		},
		app.MarkReady,
		app.MarkNotReady,
		6*time.Second,
	)
}

type hertzLifecycle interface {
	Run() error
	Shutdown(context.Context) error
	IsRunning() bool
}

func superviseHertz(
	ctx context.Context,
	h hertzLifecycle,
	readyProbe func(context.Context) error,
	markReady func() error,
	markNotReady func() error,
	shutdownTimeout time.Duration,
) error {
	runErr := make(chan error, 1)
	go func() { runErr <- h.Run() }()

	readyCtx, cancelReady := context.WithCancel(ctx)
	defer cancelReady()
	ready := make(chan error, 1)
	go func() { ready <- readyProbe(readyCtx) }()

	for {
		select {
		case err := <-runErr:
			return errors.Join(normalizeRunError(err), publishStatus("not-ready", markNotReady))
		case err := <-ready:
			ready = nil
			if err != nil {
				statusErr := publishStatus("not-ready", markNotReady)
				stopErr := shutdownAndWait(h, runErr, shutdownTimeout)
				if ctx.Err() != nil {
					return errors.Join(statusErr, stopErr)
				}
				return errors.Join(err, statusErr, stopErr)
			}
			// Do not publish a transient ready state if the signal or Run exit
			// raced with the successful health response.
			if ctx.Err() != nil {
				return errors.Join(
					publishStatus("not-ready", markNotReady),
					shutdownAndWait(h, runErr, shutdownTimeout),
				)
			}
			if h.IsRunning() {
				if err := publishStatus("ready", markReady); err != nil {
					return errors.Join(
						err,
						publishStatus("not-ready", markNotReady),
						shutdownAndWait(h, runErr, shutdownTimeout),
					)
				}
			}
		case <-ctx.Done():
			return errors.Join(
				publishStatus("not-ready", markNotReady),
				shutdownAndWait(h, runErr, shutdownTimeout),
			)
		}
	}
}

func publishStatus(value string, publish func() error) error {
	if publish == nil {
		return fmt.Errorf("publish %s status: callback is nil", value)
	}
	if err := publish(); err != nil {
		return fmt.Errorf("publish %s status: %w", value, err)
	}
	return nil
}

func normalizeRunError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func shutdownAndWait(h hertzLifecycle, runErr <-chan error, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// A termination signal can arrive between starting the Run goroutine and
	// Engine.MarkAsRunning. Shutdown returns "engine is not running" in that
	// window, so wait briefly for either a running engine or Run's real error.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for !h.IsRunning() {
		select {
		case err := <-runErr:
			return normalizeRunError(err)
		case <-ctx.Done():
			return fmt.Errorf("hertz did not enter running state before shutdown: %w", ctx.Err())
		case <-ticker.C:
		}
	}

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- h.Shutdown(ctx) }()
	var runResult, shutdownResult error
	var runDone, shutdownFinished bool
	for !runDone || !shutdownFinished {
		select {
		case err := <-runErr:
			runResult, runDone = err, true
			runErr = nil
		case err := <-shutdownDone:
			shutdownResult, shutdownFinished = err, true
			shutdownDone = nil
		case <-ctx.Done():
			return errors.Join(
				normalizeRunError(runResult),
				wrapShutdownError(shutdownResult),
				fmt.Errorf("hertz shutdown/run completion timed out: %w", ctx.Err()),
			)
		}
	}
	return errors.Join(normalizeRunError(runResult), wrapShutdownError(shutdownResult))
}

func wrapShutdownError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("hertz shutdown: %w", err)
}

func waitForHTTPReady(ctx context.Context, address string, timeout time.Duration) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("parse listen address %q: %w", address, err)
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	} else if host == "::" || host == "[::]" {
		host = "::1"
	}
	target := "http://" + net.JoinHostPort(strings.Trim(host, "[]"), port) + "/healthz"
	transport := &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   500 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var lastErr error
	for {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if requestErr != nil {
			return requestErr
		}
		request.Close = true
		response, requestErr := client.Do(request)
		if requestErr == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 16))
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && string(body) == "ok" {
				return nil
			}
			lastErr = fmt.Errorf("status=%d body=%q", response.StatusCode, body)
		} else {
			lastErr = requestErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("health endpoint %s was not ready within %s: %w", target, timeout, lastErr)
		case <-ticker.C:
		}
	}
}
