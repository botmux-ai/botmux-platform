package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
)

// Lifecycle owns cross-pod proxy work that is not represented by the local
// tunnel/support registries. Closing it cancels forwarded HTTP requests and
// tears down both endpoints of every raw bridge, allowing Hertz shutdown to
// drain hijacked handlers deterministically.
type Lifecycle struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	closed bool
	active map[*bridgePair]struct{}
}

type bridgePair struct {
	left  net.Conn
	right net.Conn
}

func NewLifecycle() *Lifecycle {
	ctx, cancel := context.WithCancel(context.Background())
	return &Lifecycle{ctx: ctx, cancel: cancel, active: make(map[*bridgePair]struct{})}
}

func (l *Lifecycle) ForwardHTTP(peerAddress string, w http.ResponseWriter, r *http.Request) error {
	if l == nil {
		return ForwardHTTP(peerAddress, w, r)
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(l.ctx, cancel)
	defer func() {
		stop()
		cancel()
	}()
	if err := l.ctx.Err(); err != nil {
		writeProxyError(w, "跨 pod 转发已停止", err)
		return err
	}
	return forwardHTTP(ctx, peerAddress, w, r)
}

func (l *Lifecycle) ForwardWebSocket(peerAddress string, w http.ResponseWriter, r *http.Request) error {
	if l == nil {
		return ForwardWebSocket(peerAddress, w, r)
	}
	if err := l.ctx.Err(); err != nil {
		http.Error(w, "service shutting down", http.StatusServiceUnavailable)
		return err
	}
	return forwardWebSocket(l, peerAddress, w, r)
}

func (l *Lifecycle) track(left, right net.Conn) (*bridgePair, bool) {
	pair := &bridgePair{left: left, right: right}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		_ = left.Close()
		_ = right.Close()
		return nil, false
	}
	l.active[pair] = struct{}{}
	l.mu.Unlock()
	return pair, true
}

func (l *Lifecycle) release(pair *bridgePair) {
	if l == nil || pair == nil {
		return
	}
	l.mu.Lock()
	delete(l.active, pair)
	l.mu.Unlock()
}

func (l *Lifecycle) Close() error {
	if l == nil {
		return nil
	}
	l.cancel()
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	pairs := make([]*bridgePair, 0, len(l.active))
	for pair := range l.active {
		pairs = append(pairs, pair)
	}
	l.mu.Unlock()

	var errs []error
	for _, pair := range pairs {
		for _, conn := range []net.Conn{pair.left, pair.right} {
			if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
