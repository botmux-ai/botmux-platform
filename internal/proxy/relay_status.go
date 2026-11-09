package proxy

import (
	"context"
	"sync/atomic"
)

// Relayed status marking for the failure-rate metric.
//
// The platform reverse-proxies machine daemons (machine subdomains, webhooks,
// /openapi/machines/:id/proxy/*) and passes the daemon's status through
// verbatim. A daemon that answers 500 for its own reasons is not a platform
// failure, but Hertz's server span only sees the final status. The proxy
// records "this status came from upstream" in a per-request holder carried on
// the request context; the success decider reads it back and counts a relayed
// 5xx as success. Everything the platform writes itself (502 from a failed
// round trip, 503 while shutting down, store errors, panics) is never marked
// and stays a failure.

type relayMarkerKey struct{}

// RelayMarker remembers the last upstream status relayed for one request.
type RelayMarker struct{ status atomic.Int64 }

// WithRelayMarker returns a context carrying a fresh marker.
func WithRelayMarker(ctx context.Context) (context.Context, *RelayMarker) {
	marker := &RelayMarker{}
	return context.WithValue(ctx, relayMarkerKey{}, marker), marker
}

// MarkRelayedStatus records that status was copied from an upstream response.
// It is a no-op when ctx carries no marker (tests, background work).
func MarkRelayedStatus(ctx context.Context, status int) {
	if ctx == nil || status <= 0 {
		return
	}
	if marker, ok := ctx.Value(relayMarkerKey{}).(*RelayMarker); ok {
		marker.status.Store(int64(status))
	}
}

// Status returns the relayed status, or 0 when nothing was relayed.
func (m *RelayMarker) Status() int {
	if m == nil {
		return 0
	}
	return int(m.status.Load())
}
