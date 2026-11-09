package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestForwardHTTPPreservesEndToEndHeadersAddsLoopMarkerAndReusesConnection(t *testing.T) {
	type observedRequest struct {
		method, uri, host, marker, endToEnd, cookie, connectionOnly, body string
	}
	observed := make(chan observedRequest, 2)
	var newConnections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		observed <- observedRequest{
			method: r.Method, uri: r.URL.RequestURI(), host: r.Host,
			marker: r.Header.Get(ForwardHeader), endToEnd: r.Header.Get("X-End-To-End"),
			cookie: r.Header.Get("Cookie"), connectionOnly: r.Header.Get("X-Client-Hop"), body: string(body),
		}
		w.Header().Set("X-Peer", "ok")
		w.Header().Add("Set-Cookie", "peer-session=preserved")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "peer-response")
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConnections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	defer peerHTTPTransport.CloseIdleConnections()
	peerAddress := strings.TrimPrefix(server.URL, "http://")

	for index := 0; index < 2; index++ {
		method, payload := http.MethodGet, ""
		if index == 0 {
			method, payload = http.MethodPost, "request-body"
		}
		request := httptest.NewRequest(method, "http://m-machine.example/api/path?q=1", strings.NewReader(payload))
		request.Host = "m-machine.example"
		request.Header.Set(ForwardHeader, "untrusted-old-value")
		request.Header.Set("X-End-To-End", "preserve-me")
		request.Header.Set("Cookie", "proxy-session=secret")
		request.Header.Set("Connection", "keep-alive, X-Client-Hop")
		request.Header.Set("X-Client-Hop", "drop-me")
		recorder := httptest.NewRecorder()

		if err := ForwardHTTP(peerAddress, recorder, request); err != nil {
			t.Fatal(err)
		}
		seen := <-observed
		if seen.method != method || seen.uri != "/api/path?q=1" || seen.host != "m-machine.example" {
			t.Fatalf("peer request = %#v", seen)
		}
		if seen.marker != "1" || seen.endToEnd != "preserve-me" || seen.cookie != "proxy-session=secret" {
			t.Fatalf("peer headers = %#v", seen)
		}
		if seen.connectionOnly != "" {
			t.Fatalf("Connection-nominated header reached peer: %#v", seen)
		}
		if seen.body != payload {
			t.Fatalf("peer body = %q, want %q", seen.body, payload)
		}
		if request.Header.Get(ForwardHeader) != "untrusted-old-value" || request.Header.Get("X-Client-Hop") != "drop-me" {
			t.Fatal("ForwardHTTP mutated the incoming request headers")
		}
		if recorder.Code != http.StatusAccepted || recorder.Body.String() != "peer-response" || recorder.Header().Get("X-Peer") != "ok" {
			t.Fatalf("forwarded response = %d %q %#v", recorder.Code, recorder.Body.String(), recorder.Header())
		}
		if got := recorder.Header().Get("Set-Cookie"); got != "peer-session=preserved" {
			t.Fatalf("peer Set-Cookie = %q", got)
		}
	}
	if got := newConnections.Load(); got != 1 {
		t.Fatalf("peer transport opened %d connections for two sequential requests, want reuse", got)
	}
}

func TestWriteRawRequestForwardsHeadersAndBufferedHead(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	buffered := bufio.NewReadWriter(bufio.NewReader(strings.NewReader("buffered-head")), bufio.NewWriter(io.Discard))
	if _, err := buffered.Reader.Peek(len("buffered-head")); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://m-machine.example/term?session=1", nil)
	request.Host = "m-machine.example"
	headers := http.Header{
		"Connection": {"Upgrade"},
		"Upgrade":    {"websocket"},
		"X-Multi":    {"one", "two"},
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- writeRawRequest(writer, request, headers, buffered)
		_ = writer.Close()
	}()
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.HasPrefix(text, "GET /term?session=1 HTTP/1.1\r\n") {
		t.Fatalf("request line = %q", text)
	}
	for _, fragment := range []string{"Host: m-machine.example\r\n", "Upgrade: websocket\r\n", "X-Multi: one\r\n", "X-Multi: two\r\n"} {
		if !strings.Contains(text, fragment) {
			t.Errorf("raw request missing %q: %q", fragment, text)
		}
	}
	if !strings.HasSuffix(text, "\r\n\r\nbuffered-head") {
		t.Fatalf("buffered head missing: %q", text)
	}
	if buffered.Reader.Buffered() != 0 {
		t.Fatalf("buffered bytes were not consumed: %d", buffered.Reader.Buffered())
	}
}

func TestBridgePreservesDelayedResponseAfterClientHalfClose(t *testing.T) {
	client, left := tcpConnPair(t)
	upstream, right := tcpConnPair(t)
	connections := []*net.TCPConn{client, left, upstream, right}
	deadline := time.Now().Add(3 * time.Second)
	for _, connection := range connections {
		if err := connection.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
	}

	bridged := make(chan struct{})
	go func() {
		bridge(left, right)
		close(bridged)
	}()

	const requestPayload = "request-before-half-close"
	if _, err := io.WriteString(client, requestPayload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	requestBytes := make([]byte, len(requestPayload))
	if _, err := io.ReadFull(upstream, requestBytes); err != nil {
		t.Fatal(err)
	}
	if string(requestBytes) != requestPayload {
		t.Fatalf("upstream request = %q", requestBytes)
	}
	one := make([]byte, 1)
	if n, err := upstream.Read(one); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("upstream did not receive forwarded half-close: n=%d err=%v", n, err)
	}

	// The response intentionally starts only after the request direction has
	// half-closed. Closing both bridge sockets on the first io.Copy completion
	// truncates this payload.
	const responsePayload = "complete-delayed-response"
	if _, err := io.WriteString(upstream, responsePayload); err != nil {
		t.Fatal(err)
	}
	if err := upstream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	responseBytes := make([]byte, len(responsePayload))
	if _, err := io.ReadFull(client, responseBytes); err != nil {
		t.Fatal(err)
	}
	if string(responseBytes) != responsePayload {
		t.Fatalf("client response = %q", responseBytes)
	}
	if n, err := client.Read(one); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("client did not receive response half-close: n=%d err=%v", n, err)
	}

	select {
	case <-bridged:
	case <-time.After(time.Second):
		t.Fatal("bridge did not finish after both directions half-closed")
	}
}

func TestBridgeForcedEndpointCloseUnblocksBothDirections(t *testing.T) {
	client, left := tcpConnPair(t)
	upstream, right := tcpConnPair(t)
	defer client.Close()
	defer upstream.Close()

	bridged := make(chan struct{})
	go func() {
		bridge(left, right)
		close(bridged)
	}()

	// Closing the bridge-owned endpoint models Registry.Close terminating an
	// active tunnel data connection while the browser side is otherwise idle.
	if err := right.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-bridged:
	case <-time.After(time.Second):
		t.Fatal("bridge remained blocked after a forced endpoint close")
	}

	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("client side remained open after forced bridge teardown")
	}
}

func TestBridgePropagatesUpstreamEOFThroughWrappedClientConnection(t *testing.T) {
	client, left := tcpConnPair(t)
	upstream, right := tcpConnPair(t)
	defer client.Close()
	defer upstream.Close()

	// Hertz's net/http adaptor returns a private net.Conn wrapper whose method
	// set does not expose the underlying TCPConn.CloseWrite. Model that exact
	// property instead of using TCPConn on both bridge endpoints.
	wrappedLeft := &connWithoutCloseWrite{Conn: left}
	bridged := make(chan struct{})
	go func() {
		bridge(wrappedLeft, right)
		close(bridged)
	}()

	const finalPayload = "final-upstream-bytes"
	if _, err := io.WriteString(upstream, finalPayload); err != nil {
		t.Fatal(err)
	}
	if err := upstream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, len(finalPayload))
	if _, err := io.ReadFull(client, payload); err != nil {
		t.Fatal(err)
	}
	if string(payload) != finalPayload {
		t.Fatalf("client payload = %q", payload)
	}
	buffer := make([]byte, 1)
	if n, err := client.Read(buffer); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("wrapped client did not receive upstream EOF: n=%d err=%v", n, err)
	}

	select {
	case <-bridged:
	case <-time.After(time.Second):
		t.Fatal("bridge remained blocked after upstream EOF through wrapped client")
	}
}

func TestLifecycleCloseCancelsForwardedHTTP(t *testing.T) {
	requestStarted := make(chan struct{})
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
	}))
	defer peer.Close()

	lifecycle := NewLifecycle()
	request := httptest.NewRequest(http.MethodGet, "http://m-machine.example/slow", nil)
	recorder := httptest.NewRecorder()
	result := make(chan error, 1)
	go func() {
		result <- lifecycle.ForwardHTTP(strings.TrimPrefix(peer.URL, "http://"), recorder, request)
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("forwarded request did not reach peer")
	}
	if err := lifecycle.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("forward result = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("forwarded HTTP did not stop with lifecycle")
	}
	if err := lifecycle.Close(); err != nil {
		t.Fatalf("second lifecycle close = %v", err)
	}
}

func TestLifecycleCloseTerminatesTrackedRawBridge(t *testing.T) {
	client, left := tcpConnPair(t)
	upstream, right := tcpConnPair(t)
	defer client.Close()
	defer upstream.Close()
	lifecycle := NewLifecycle()
	pair, ok := lifecycle.track(left, right)
	if !ok {
		t.Fatal("active lifecycle rejected bridge")
	}
	bridged := make(chan struct{})
	go func() {
		bridge(left, right)
		lifecycle.release(pair)
		close(bridged)
	}()
	if err := lifecycle.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-bridged:
	case <-time.After(time.Second):
		t.Fatal("raw bridge remained active after lifecycle close")
	}
}

func tcpConnPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()
	peer, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case connection := <-accepted:
		return peer, connection
	case err := <-acceptErr:
		_ = peer.Close()
		t.Fatal(err)
		return nil, nil
	case <-time.After(time.Second):
		_ = peer.Close()
		t.Fatal("timed out accepting TCP test connection")
		return nil, nil
	}
}

type connWithoutCloseWrite struct {
	net.Conn
}
