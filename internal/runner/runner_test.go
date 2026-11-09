package runner

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSuperviseHertzHandlesSignalBeforeRunning(t *testing.T) {
	fake := newFakeLifecycle(25 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var ready, notReady atomic.Int32

	started := time.Now()
	err := superviseHertz(
		ctx,
		fake,
		func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
		func() error { ready.Add(1); return nil },
		func() error { notReady.Add(1); return nil },
		300*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("superviseHertz = %v", err)
	}
	if time.Since(started) >= 300*time.Millisecond {
		t.Fatal("early signal waited until the shutdown deadline")
	}
	if ready.Load() != 0 || notReady.Load() == 0 {
		t.Fatalf("ready=%d notReady=%d", ready.Load(), notReady.Load())
	}
	if fake.shutdownCalls.Load() != 1 {
		t.Fatalf("shutdown calls = %d", fake.shutdownCalls.Load())
	}
}

func TestSuperviseHertzPublishesReadyThenStops(t *testing.T) {
	fake := newFakeLifecycle(0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ready, notReady atomic.Int32

	err := superviseHertz(
		ctx,
		fake,
		func(context.Context) error {
			for !fake.IsRunning() {
				time.Sleep(time.Millisecond)
			}
			return nil
		},
		func() error { ready.Add(1); cancel(); return nil },
		func() error { notReady.Add(1); return nil },
		300*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Load() != 1 || notReady.Load() == 0 {
		t.Fatalf("ready=%d notReady=%d", ready.Load(), notReady.Load())
	}
}

func TestSuperviseHertzStopsWhenReadyStatusCannotBePublished(t *testing.T) {
	fake := newFakeLifecycle(0)
	var notReady atomic.Int32
	want := errors.New("status disk unavailable")

	err := superviseHertz(
		context.Background(),
		fake,
		func(context.Context) error {
			for !fake.IsRunning() {
				time.Sleep(time.Millisecond)
			}
			return nil
		},
		func() error { return want },
		func() error { notReady.Add(1); return nil },
		300*time.Millisecond,
	)
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "publish ready status") {
		t.Fatalf("superviseHertz error = %v", err)
	}
	if fake.shutdownCalls.Load() != 1 || fake.IsRunning() {
		t.Fatalf("failed ready publication did not stop Hertz: shutdown=%d running=%v", fake.shutdownCalls.Load(), fake.IsRunning())
	}
	if notReady.Load() != 1 {
		t.Fatalf("not-ready publications = %d", notReady.Load())
	}
}

func TestShutdownAndWaitIsBounded(t *testing.T) {
	fake := newFakeLifecycle(0)
	fake.blockShutdown = true
	runErr := make(chan error, 1)
	go func() { runErr <- fake.Run() }()
	defer fake.stopOnce.Do(func() { close(fake.stop) })
	for !fake.IsRunning() {
		time.Sleep(time.Millisecond)
	}

	started := time.Now()
	err := shutdownAndWait(fake, runErr, 80*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("shutdownAndWait error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 300*time.Millisecond {
		t.Fatalf("shutdownAndWait was not bounded: %s", elapsed)
	}
}

func TestWaitForHTTPReadyChecksApplicationResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	if err := waitForHTTPReady(context.Background(), listener.Addr().String(), time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestWaitForHTTPReadyRejectsUnrelatedListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	err = waitForHTTPReady(context.Background(), listener.Addr().String(), 80*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "was not ready") {
		t.Fatalf("waitForHTTPReady error = %v", err)
	}
}

type fakeLifecycle struct {
	startDelay    time.Duration
	running       atomic.Bool
	shutdownCalls atomic.Int32
	stop          chan struct{}
	stopOnce      sync.Once
	blockShutdown bool
}

func newFakeLifecycle(delay time.Duration) *fakeLifecycle {
	return &fakeLifecycle{startDelay: delay, stop: make(chan struct{})}
}

func (f *fakeLifecycle) Run() error {
	if f.startDelay > 0 {
		time.Sleep(f.startDelay)
	}
	f.running.Store(true)
	<-f.stop
	f.running.Store(false)
	return nil
}

func (f *fakeLifecycle) Shutdown(ctx context.Context) error {
	f.shutdownCalls.Add(1)
	if f.blockShutdown {
		<-ctx.Done()
		return ctx.Err()
	}
	if !f.running.Load() {
		return errors.New("engine is not running")
	}
	f.stopOnce.Do(func() { close(f.stop) })
	return nil
}

func (f *fakeLifecycle) IsRunning() bool { return f.running.Load() }
