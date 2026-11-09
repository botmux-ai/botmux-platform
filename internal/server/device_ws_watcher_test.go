package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

type fakeDeviceReader struct {
	mu     sync.Mutex
	doc    *store.DeviceDoc
	err    error
	nCalls int
}

func (f *fakeDeviceReader) GetDevice(context.Context, string) (store.DeviceDoc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nCalls++
	if f.err != nil {
		return store.DeviceDoc{}, f.err
	}
	if f.doc == nil {
		return store.DeviceDoc{}, store.ErrNotFound
	}
	return *f.doc, nil
}

func (f *fakeDeviceReader) set(doc *store.DeviceDoc, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.doc, f.err = doc, err
}

func activeDevice(version int64) *store.DeviceDoc {
	return &store.DeviceDoc{ID: "dev-1", Status: store.DeviceStatusActive, CredentialVersion: version}
}

func newTestWatcher(reader *fakeDeviceReader) *DeviceSocketWatcher {
	d := NewDeviceSocketWatcher(auth.NewDeviceStateCache(reader))
	d.interval = time.Hour // ticks are driven by hand
	return d
}

type closeCounter struct{ n atomic.Int32 }

func (c *closeCounter) destroy() { c.n.Add(1) }

func farClaims(version int64) DeviceSocketClaims {
	return DeviceSocketClaims{DeviceID: "dev-1", CredentialVersion: version, AuthExp: time.Now().Add(time.Hour).Unix()}
}

func TestDeviceSocketWatcherClosesOnAuthorityChange(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  *store.DeviceDoc
		err  error
		want int32
	}{
		{"active same version stays open", activeDevice(3), nil, 0},
		{"credential rotated", activeDevice(4), nil, 1},
		{"revoked", &store.DeviceDoc{ID: "dev-1", Status: store.DeviceStatusRevoked, CredentialVersion: 3}, nil, 1},
		{"device gone", nil, nil, 1},
		{"authority unavailable", nil, errors.New("down"), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &fakeDeviceReader{}
			d := newTestWatcher(reader)
			var closed closeCounter
			release, ok := d.Register(farClaims(3), closed.destroy, nil)
			if !ok {
				t.Fatal("register refused")
			}
			defer release()
			reader.set(tc.doc, tc.err)
			d.tick("dev-1")
			if got := closed.n.Load(); got != tc.want {
				t.Fatalf("closed %d times, want %d", got, tc.want)
			}
		})
	}
}

func TestDeviceSocketWatcherClosesOnlyStaleVersion(t *testing.T) {
	reader := &fakeDeviceReader{}
	d := newTestWatcher(reader)
	var stale, fresh closeCounter
	releaseStale, _ := d.Register(farClaims(3), stale.destroy, nil)
	defer releaseStale()
	releaseFresh, _ := d.Register(farClaims(4), fresh.destroy, nil)
	defer releaseFresh()
	reader.set(activeDevice(4), nil)
	d.tick("dev-1")
	if stale.n.Load() != 1 || fresh.n.Load() != 0 {
		t.Fatalf("stale closed %d, fresh closed %d", stale.n.Load(), fresh.n.Load())
	}
}

func TestDeviceSocketWatcherLeaseAndFence(t *testing.T) {
	reader := &fakeDeviceReader{}
	states := auth.NewDeviceStateCache(reader)
	d := NewDeviceSocketWatcher(states)

	var expired closeCounter
	release, ok := d.Register(DeviceSocketClaims{DeviceID: "dev-1", CredentialVersion: 1, AuthExp: time.Now().Unix() - 1}, expired.destroy, nil)
	if !ok {
		t.Fatal("register refused")
	}
	deadline := time.Now().Add(2 * time.Second)
	for expired.n.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if expired.n.Load() != 1 {
		t.Fatal("authExp lease did not close the socket")
	}
	release()
	release() // idempotent

	epoch := states.Epoch("dev-1")
	states.Invalidate("dev-1")
	var fenced closeCounter
	if _, ok := d.Register(farClaims(1), fenced.destroy, &epoch); ok || fenced.n.Load() != 1 {
		t.Fatalf("epoch fence: ok=%v closed=%d", ok, fenced.n.Load())
	}

	var a, b closeCounter
	releaseA, _ := d.Register(farClaims(1), a.destroy, nil)
	releaseB, _ := d.Register(farClaims(1), b.destroy, nil)
	if n := d.CloseDevice("dev-1", "revoked"); n != 2 || a.n.Load() != 1 || b.n.Load() != 1 {
		t.Fatalf("CloseDevice closed %d (a=%d b=%d)", n, a.n.Load(), b.n.Load())
	}
	d.CloseDevice("dev-1", "revoked")
	if a.n.Load() != 1 {
		t.Fatal("destroy ran twice")
	}
	releaseA()
	releaseB()
	d.mu.Lock()
	left := len(d.watches)
	d.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d device watches leaked after release", left)
	}
}
