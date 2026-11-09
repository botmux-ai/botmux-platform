package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const ForwardHeader = "X-Botmux-Forwarded"

var peerHTTPTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	ForceAttemptHTTP2:     false,
	MaxIdleConns:          128,
	MaxIdleConnsPerHost:   32,
	IdleConnTimeout:       60 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
}

func ForwardHTTP(peerAddress string, w http.ResponseWriter, r *http.Request) error {
	return forwardHTTP(r.Context(), peerAddress, w, r)
}

func forwardHTTP(ctx context.Context, peerAddress string, w http.ResponseWriter, r *http.Request) error {
	request, err := http.NewRequestWithContext(ctx, r.Method, "http://"+peerAddress+RequestTarget(r), r.Body)
	if err != nil {
		return err
	}
	request.Header = cloneHeader(r.Header)
	removeHopByHopHeaders(request.Header)
	request.Header.Set(ForwardHeader, "1")
	request.Host = r.Host
	request.ContentLength = r.ContentLength

	response, err := peerHTTPTransport.RoundTrip(request)
	if err != nil {
		if ctx.Err() != nil {
			abortClient(w)
			return err
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "跨 pod 转发失败："+nodeErrorString(err))
		return err
	}
	defer response.Body.Close()
	// The owner pod destroys its response when its own upstream aborts; this
	// hop must pass that abort on, or the zombie stream just moves here.
	copyUpstreamResponse(w, response, false)
	return nil
}

// ForwardWebSocket forwards an unconsumed HTTP upgrade to another pod as raw
// bytes. The peer performs WebSocket termination so all in-memory ownership
// remains on the pod holding the tunnel.
func ForwardWebSocket(peerAddress string, w http.ResponseWriter, r *http.Request) error {
	return forwardWebSocket(nil, peerAddress, w, r)
}

func forwardWebSocket(lifecycle *Lifecycle, peerAddress string, w http.ResponseWriter, r *http.Request) error {
	client, buffered, err := hijack(w)
	if err != nil {
		return err
	}
	upstream, err := net.DialTimeout("tcp", peerAddress, 3*time.Second)
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		_ = client.Close()
		return err
	}
	pair := (*bridgePair)(nil)
	if lifecycle != nil {
		var tracked bool
		pair, tracked = lifecycle.track(client, upstream)
		if !tracked {
			return net.ErrClosed
		}
		defer lifecycle.release(pair)
	}
	headers := cloneHeader(r.Header)
	headers.Set(ForwardHeader, "1")
	if err := writeRawRequest(upstream, r, headers, buffered); err != nil {
		_ = upstream.Close()
		_ = client.Close()
		return err
	}
	bridge(client, upstream)
	return nil
}

func writeRawRequest(dst io.Writer, r *http.Request, headers http.Header, buffered *bufio.ReadWriter) error {
	path := RequestTarget(r)
	if _, err := fmt.Fprintf(dst, "%s %s HTTP/1.1\r\n", r.Method, path); err != nil {
		return err
	}
	if headers.Get("Host") == "" && r.Host != "" {
		headers.Set("Host", r.Host)
	}
	for name, values := range headers {
		for _, value := range values {
			if _, err := fmt.Fprintf(dst, "%s: %s\r\n", name, value); err != nil {
				return err
			}
		}
	}
	if _, err := io.WriteString(dst, "\r\n"); err != nil {
		return err
	}
	if buffered != nil && buffered.Reader.Buffered() > 0 {
		data, err := buffered.Reader.Peek(buffered.Reader.Buffered())
		if err != nil {
			return err
		}
		if _, err := dst.Write(data); err != nil {
			return err
		}
		_, _ = buffered.Reader.Discard(len(data))
	}
	return nil
}

func hijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, errorsNew("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}

func bridge(left, right net.Conn) {
	done := make(chan error, 2)
	copyOne := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err == nil {
			closeWriteOrClose(dst)
		}
		done <- err
	}
	go copyOne(left, right)
	go copyOne(right, left)
	// A clean EOF is propagated by copyOne, preserving the reverse direction
	// when the destination supports half-close. A real read/write error means
	// one side is broken (including server shutdown), so close both endpoints
	// immediately to unblock the other io.Copy goroutine.
	if err := <-done; err != nil {
		_ = left.Close()
		_ = right.Close()
	}
	<-done
	_ = left.Close()
	_ = right.Close()
}

// closeWriteOrClose propagates EOF without truncating the reverse direction
// when the destination exposes TCP-style half-close. Hertz's net/http adaptor
// wraps the accepted socket in a net.Conn that does not expose CloseWrite; in
// that case a full close is required so an upstream EOF cannot leave the
// reverse io.Copy blocked forever on an otherwise-idle client connection.
func closeWriteOrClose(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if halfCloser, ok := conn.(closeWriter); ok {
		_ = halfCloser.CloseWrite()
		return
	}
	_ = conn.Close()
}

func cloneHeader(source http.Header) http.Header {
	out := make(http.Header, len(source))
	for name, values := range source {
		out[name] = append([]string(nil), values...)
	}
	return out
}

func copyResponseHeader(target, source http.Header) {
	hopByHop := hopByHopHeaderNames(source)
	for name, values := range source {
		if _, drop := hopByHop[strings.ToLower(name)]; drop {
			continue
		}
		for _, value := range values {
			target.Add(name, value)
		}
	}
}

type stringError string

func (e stringError) Error() string { return string(e) }
func errorsNew(value string) error  { return stringError(strings.TrimSpace(value)) }
