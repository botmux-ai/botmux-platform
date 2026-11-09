package server

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Port of src/proxy/device-ws-watcher.ts. A device-authenticated WebSocket
// outlives the access token that opened it, so every registered socket is
// (1) closed at its authExp lease and (2) re-checked against the device
// authority every watch interval; revocation, credential rotation or an
// unreachable authority closes it (fail-closed).

const (
	deviceWSDefaultWatch      = 30 * time.Second
	deviceWSHardCapWatch      = 60 * time.Second
	deviceWSAuthorityDeadline = 2 * time.Second
)

// DeviceSocketClaims are the device-token claims a registered socket is
// bound to. AuthExp is in Unix seconds, like the token claim.
type DeviceSocketClaims struct {
	DeviceID          string
	CredentialVersion int64
	AuthExp           int64
}

type deviceSocketEntry struct {
	credentialVersion int64
	destroy           func()
	once              sync.Once
	lease             *time.Timer
}

func (e *deviceSocketEntry) close() {
	e.lease.Stop()
	e.once.Do(e.destroy)
}

type deviceWatch struct {
	conns map[*deviceSocketEntry]struct{}
	stop  chan struct{}
}

// DeviceSocketWatcher tracks the live device WebSockets of this pod.
type DeviceSocketWatcher struct {
	states   *auth.DeviceStateCache
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	watches map[string]*deviceWatch
}

// NewDeviceSocketWatcher reads DEVICE_WS_WATCH_MS (min 1s, capped at 60s,
// default 30s) like the Node watcher.
func NewDeviceSocketWatcher(states *auth.DeviceStateCache) *DeviceSocketWatcher {
	interval := deviceWSDefaultWatch
	if ms, err := strconv.ParseFloat(os.Getenv("DEVICE_WS_WATCH_MS"), 64); err == nil && ms >= 1000 {
		interval = min(time.Duration(ms*float64(time.Millisecond)), deviceWSHardCapWatch)
	}
	return &DeviceSocketWatcher{states: states, interval: interval, now: time.Now, watches: make(map[string]*deviceWatch)}
}

// Register binds a live socket to the device. destroy must close the socket;
// the caller must invoke the returned release exactly once when the socket
// closes for any reason. epochFence, when non-nil, is the device-state epoch
// observed at authentication time: if a revocation landed in between, the
// socket is destroyed instead of registered (ok=false).
func (d *DeviceSocketWatcher) Register(claims DeviceSocketClaims, destroy func(), epochFence *uint64) (release func(), ok bool) {
	if epochFence != nil && d.states != nil && d.states.Epoch(claims.DeviceID) != *epochFence {
		slog.Warn("设备流登记撞 epoch fence（鉴权期间发生过吊销），拒登记并断开", "deviceId", claims.DeviceID)
		destroy()
		return func() {}, false
	}
	entry := &deviceSocketEntry{credentialVersion: claims.CredentialVersion, destroy: destroy}
	lease := time.Unix(claims.AuthExp, 0).Sub(d.now())
	entry.lease = time.AfterFunc(max(lease, 0), func() {
		slog.Info("设备 WS 到 authExp 租约关闭", "deviceId", claims.DeviceID)
		// Not entry.close(): an already-past authExp can fire before
		// entry.lease is assigned, and a fired timer needs no Stop.
		entry.once.Do(entry.destroy)
	})

	d.mu.Lock()
	w := d.watches[claims.DeviceID]
	if w == nil {
		w = &deviceWatch{conns: make(map[*deviceSocketEntry]struct{}), stop: make(chan struct{})}
		d.watches[claims.DeviceID] = w
		go d.loop(claims.DeviceID, w)
	}
	w.conns[entry] = struct{}{}
	d.mu.Unlock()

	var released sync.Once
	return func() {
		released.Do(func() {
			entry.lease.Stop()
			d.mu.Lock()
			defer d.mu.Unlock()
			cur := d.watches[claims.DeviceID]
			if cur == nil {
				return
			}
			delete(cur.conns, entry)
			if len(cur.conns) == 0 {
				close(cur.stop)
				delete(d.watches, claims.DeviceID)
			}
		})
	}, true
}

// CloseDevice destroys every socket of the device on this pod (revocation
// takes effect immediately on the revoking pod) and returns how many.
func (d *DeviceSocketWatcher) CloseDevice(deviceID, reason string) int {
	entries := d.snapshot(deviceID)
	if len(entries) > 0 {
		slog.Info("断开设备全部 WS", "deviceId", deviceID, "reason", reason, "count", len(entries))
	}
	for _, e := range entries {
		e.close()
	}
	return len(entries)
}

func (d *DeviceSocketWatcher) snapshot(deviceID string) []*deviceSocketEntry {
	d.mu.Lock()
	defer d.mu.Unlock()
	w := d.watches[deviceID]
	if w == nil {
		return nil
	}
	out := make([]*deviceSocketEntry, 0, len(w.conns))
	for e := range w.conns {
		out = append(out, e)
	}
	return out
}

func (d *DeviceSocketWatcher) loop(deviceID string, w *deviceWatch) {
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			d.tick(deviceID)
		}
	}
}

// tick is watchTick: one authoritative re-check of the device.
func (d *DeviceSocketWatcher) tick(deviceID string) {
	if len(d.snapshot(deviceID)) == 0 {
		return
	}
	if d.states == nil {
		d.CloseDevice(deviceID, "authority_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), deviceWSAuthorityDeadline)
	defer cancel()
	state, err := d.states.Get(ctx, deviceID, auth.DeviceStateOptions{BypassCache: true})
	if err != nil {
		d.CloseDevice(deviceID, "authority_unavailable")
		return
	}
	if state == nil {
		d.CloseDevice(deviceID, "device_gone")
		return
	}
	if state.Status != store.DeviceStatusActive {
		d.CloseDevice(deviceID, "revoked")
		return
	}
	for _, e := range d.snapshot(deviceID) {
		if e.credentialVersion != state.CredentialVersion {
			e.close()
		}
	}
}
