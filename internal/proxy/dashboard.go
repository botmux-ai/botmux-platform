package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

const dashboardCookie = "botmux_dashboard_token"

type Dashboard struct {
	registry *tunnel.Registry
	ctx      context.Context
	cancel   context.CancelFunc

	poolEnabled   bool
	directEnabled bool
	mu            sync.Mutex
	closed        bool
	transports    map[string]*http.Transport
	directState   map[string]directStatus
	directClient  *http.Client
}

type directStatus struct {
	host    string
	checked time.Time
	probing bool
}

func NewDashboard(registry *tunnel.Registry) *Dashboard {
	ctx, cancel := context.WithCancel(context.Background())
	directTransport := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 900 * time.Millisecond, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   false,
		MaxConnsPerHost:     32,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     60 * time.Second,
	}
	return &Dashboard{
		registry:      registry,
		ctx:           ctx,
		cancel:        cancel,
		poolEnabled:   os.Getenv("DASHBOARD_CONN_POOL") != "0",
		directEnabled: os.Getenv("DASHBOARD_DIRECT") != "0",
		transports:    make(map[string]*http.Transport),
		directState:   make(map[string]directStatus),
		directClient:  &http.Client{Transport: directTransport},
	}
}

// PlatformHeaders are the authority headers the platform decided **after**
// authentication (role / actor / scopes / login bootstrap URL). They are a
// separate parameter instead of being written onto the incoming request so a
// client-supplied header and a platform decision can never share a carrier:
// every client x-botmux-* authority header is dropped by upstreamHeaders, and
// only these values are written back. Empty fields are not sent.
//
// Role and Scopes are not a pair: the daemon only honours scopes when it
// recognises a role, and absent role means legacy-owner. The dashboard proxy
// therefore never sends a role for owners or co-managers (product decision
// 2026-09); only the terminal surface sends owner/guest.
type PlatformHeaders struct {
	Role     string
	Actor    string
	Scopes   string
	LoginURL string
}

// ErrUpstreamAborted reports that the machine dashboard closed a response
// before its body completed (dashboard restart / tunnel drop).
var ErrUpstreamAborted = errors.New("upstream_aborted")

// ProxyHTTP reverse-proxies one browser request to the machine dashboard,
// preferring a reachable direct host for bodyless requests and falling back
// to the tunnel. Cancelling r's context at any point (client gone, device
// revocation, desktop lease expiry, Dashboard.Close) aborts the browser
// connection instead of ending the response, so EventSource and friends can
// tell failure from a clean end.
func (d *Dashboard) ProxyHTTP(w http.ResponseWriter, r *http.Request, machine tunnel.MachineConn, platform PlatformHeaders) {
	ctx, release := d.requestContext(r.Context())
	defer release()
	r = r.WithContext(ctx)

	headers := upstreamHeaders(r.Header, r.Host, machine, false, isWebhookPath(r), platform)
	// Body presence is read from the framing headers, never guessed from the
	// method: a DELETE with a JSON body used to forward Content-Length while
	// piping nothing, hanging the dashboard until the gateway timed out.
	hasBody := requestHasBody(r)
	if !hasBody {
		if host := d.directHost(machine); host != "" {
			response, err := d.roundTrip(r, headers, d.directClient.Transport, "http://"+host, 2, false)
			if err == nil {
				d.writeResponse(w, response)
				return
			}
			if ctx.Err() != nil {
				abortClient(w)
				return
			}
			d.mu.Lock()
			if !d.closed {
				d.directState[machine.MachineID] = directStatus{checked: time.Now()}
			}
			d.mu.Unlock()
		}
	}

	transport := d.transportFor(machine.MachineID)
	maxRetry := 3
	if !d.poolEnabled {
		maxRetry = 0
	}
	response, err := d.roundTrip(r, headers, transport, "http://127.0.0.1:"+strconv.Itoa(machine.DashboardPort), maxRetry, hasBody)
	if err != nil {
		if ctx.Err() != nil {
			abortClient(w)
			return
		}
		slog.Warn("反代上游错误", "machineId", machine.MachineID, "error", err)
		writeProxyError(w, "反代失败", err)
		return
	}
	d.writeResponse(w, response)
}

func (d *Dashboard) roundTrip(r *http.Request, headers http.Header, transport http.RoundTripper, base string, maxRetry int, hasBody bool) (*http.Response, error) {
	var body io.ReadCloser
	if hasBody {
		body = r.Body
	}
	var lastErr error
	for attempt := 0; attempt <= maxRetry; attempt++ {
		target := base + RequestTarget(r)
		request, err := http.NewRequestWithContext(r.Context(), r.Method, target, body)
		if err != nil {
			return nil, err
		}
		request.Header = headers.Clone()
		if _, ok := request.Header["User-Agent"]; !ok {
			// Node forwards no User-Agent when the browser sent none; an empty
			// value stops net/http from inventing "Go-http-client/1.1".
			request.Header["User-Agent"] = []string{""}
		}
		request.Host = headers.Get("Host")
		if hasBody {
			request.ContentLength = r.ContentLength
			if request.ContentLength == 0 {
				request.ContentLength = -1
			}
		} else {
			request.ContentLength = 0
		}
		response, err := transport.RoundTrip(request)
		if err == nil {
			return response, nil
		}
		lastErr = err
		if hasBody || r.Context().Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// writeResponse streams an upstream response to the browser. A mid-body
// upstream failure aborts the browser connection (pipeline semantics in
// Node): ending the response cleanly would leave SSE clients on a zombie
// stream that never reconnects. A browser that goes away first releases the
// upstream through response.Body.Close.
func (d *Dashboard) writeResponse(w http.ResponseWriter, response *http.Response) {
	defer response.Body.Close()
	copyUpstreamResponse(w, response, true)
}

func copyUpstreamResponse(w http.ResponseWriter, response *http.Response, stripCookies bool) {
	hopByHop := hopByHopHeaderNames(response.Header)
	for name, values := range response.Header {
		lower := strings.ToLower(name)
		_, hop := hopByHop[lower]
		if (stripCookies && lower == "set-cookie") || hop {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	status := response.StatusCode
	if status == 0 {
		status = http.StatusBadGateway
	} else if response.Request != nil {
		// The status is the upstream's own answer, not a platform failure.
		MarkRelayedStatus(response.Request.Context(), status)
	}
	w.WriteHeader(status)
	readErr, writeErr := copyStreaming(w, response.Body)
	if writeErr != nil {
		slog.Debug("dashboard response client gone", "error", writeErr)
		return
	}
	if readErr != nil {
		slog.Debug("dashboard response upstream aborted", "error", readErr)
		abortClient(w)
	}
}

// copyStreaming copies and flushes every chunk so SSE frames are delivered
// immediately. It distinguishes the upstream side failing (readErr) from the
// browser side failing (writeErr).
func copyStreaming(w http.ResponseWriter, body io.Reader) (readErr, writeErr error) {
	buf := make([]byte, 32<<10)
	flusher, _ := w.(http.Flusher)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return nil, werr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, nil
			}
			return err, nil
		}
	}
}

// abortClient tears down the browser connection without finalizing the
// response (no terminating chunk), which is how Node's pipeline/destroy
// surfaces an upstream failure. Hijack works after headers on both net/http
// and Hertz's adaptor. Writers that cannot hijack (test recorders) are left
// as-is.
func abortClient(w http.ResponseWriter) {
	conn, _, err := hijack(w)
	if err != nil {
		return
	}
	_ = conn.Close()
}

func (d *Dashboard) transportFor(machineID string) *http.Transport {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return closedDashboardTransport()
	}
	if existing := d.transports[machineID]; existing != nil {
		return existing
	}
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   false,
		MaxConnsPerHost:     24,
		MaxIdleConnsPerHost: 24,
		IdleConnTimeout:     60 * time.Second,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.registry.RequestStream(ctx, machineID, 10*time.Second)
		},
	}
	if !d.poolEnabled {
		transport.DisableKeepAlives = true
		transport.MaxIdleConnsPerHost = 0
	}
	d.transports[machineID] = transport
	return transport
}

func (d *Dashboard) DropMachine(machineID string) {
	d.mu.Lock()
	transport := d.transports[machineID]
	delete(d.transports, machineID)
	delete(d.directState, machineID)
	d.mu.Unlock()
	if transport != nil {
		transport.CloseIdleConnections()
	}
}

func (d *Dashboard) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	transports := d.transports
	d.transports = make(map[string]*http.Transport)
	d.directState = make(map[string]directStatus)
	d.mu.Unlock()
	if d.cancel != nil {
		d.cancel()
	}
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
	if transport, ok := d.directClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

func (d *Dashboard) directHost(machine tunnel.MachineConn) string {
	if !d.directEnabled || len(machine.DirectHosts) == 0 {
		return ""
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return ""
	}
	status := d.directState[machine.MachineID]
	now := time.Now()
	if status.host != "" && now.Sub(status.checked) < time.Minute {
		d.mu.Unlock()
		return status.host
	}
	if status.host == "" && !status.checked.IsZero() && now.Sub(status.checked) < 30*time.Second {
		d.mu.Unlock()
		return ""
	}
	if !status.probing {
		status.probing = true
		d.directState[machine.MachineID] = status
		hosts := append([]string(nil), machine.DirectHosts...)
		go d.probe(machine.MachineID, hosts)
	}
	d.mu.Unlock()
	return ""
}

func (d *Dashboard) probe(machineID string, hosts []string) {
	selected := ""
	for _, host := range hosts {
		parent := d.ctx
		if parent == nil {
			parent = context.Background()
		}
		ctx, cancel := context.WithTimeout(parent, 900*time.Millisecond)
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+normalizeHostPort(host)+"/__health", nil)
		response, err := d.directClient.Do(request)
		cancel()
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode < 500 {
			selected = normalizeHostPort(host)
			break
		}
	}
	d.mu.Lock()
	if !d.closed {
		d.directState[machineID] = directStatus{host: selected, checked: time.Now()}
	}
	d.mu.Unlock()
}

func normalizeHostPort(value string) string {
	if _, _, err := net.SplitHostPort(value); err == nil {
		return value
	}
	if strings.Count(value, ":") > 1 && !strings.HasPrefix(value, "[") {
		return "[" + value + "]:7891"
	}
	if !strings.Contains(value, ":") {
		return net.JoinHostPort(value, "7891")
	}
	return value
}

// ProxyWebSocket bridges a browser WebSocket upgrade into the machine
// dashboard over a fresh tunnel stream. Cancelling r's context closes both
// sides (device revocation, Dashboard.Close).
func (d *Dashboard) ProxyWebSocket(w http.ResponseWriter, r *http.Request, machine tunnel.MachineConn, platform PlatformHeaders) error {
	requestCtx, release := d.requestContext(r.Context())
	defer release()
	client, buffered, err := hijack(w)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(requestCtx, 10*time.Second)
	upstream, err := d.registry.RequestStream(ctx, machine.MachineID, 10*time.Second)
	cancel()
	if err != nil {
		slog.Warn("WS 反代取隧道通道失败", "machineId", machine.MachineID, "error", err)
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		_ = client.Close()
		return err
	}
	stop := context.AfterFunc(requestCtx, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer stop()
	if err := writeRawRequest(upstream, r, upstreamHeaders(r.Header, r.Host, machine, true, false, platform), buffered); err != nil {
		_ = upstream.Close()
		_ = client.Close()
		return err
	}
	// Interactive terminals need Nagle off on the browser leg; Go TCP
	// connections default to TCP_NODELAY, so only wrapped conns need help.
	setNoDelay(client)
	bridge(client, upstream)
	return nil
}

// CallAPI calls one machine dashboard API over the tunnel and reads the full
// response (platform-initiated daemon calls such as group pulls). A body cut
// off mid-way fails with ErrUpstreamAborted instead of returning a truncated
// payload.
func (d *Dashboard) CallAPI(ctx context.Context, machine tunnel.MachineConn, method, path string, body any) (int, []byte, error) {
	ctx, release := d.requestContext(ctx)
	defer release()

	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:"+strconv.Itoa(machine.DashboardPort)+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	request.Header = upstreamHeaders(nil, "", machine, false, false, PlatformHeaders{})
	request.Header.Set("Content-Type", "application/json")
	request.ContentLength = int64(len(payload))
	response, err := d.transportFor(machine.MachineID).RoundTrip(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, fmt.Errorf("%w: %v", ErrUpstreamAborted, err)
	}
	return response.StatusCode, data, nil
}

func (d *Dashboard) requestContext(parent context.Context) (context.Context, func()) {
	if d.ctx == nil {
		return parent, func() {}
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(d.ctx, cancel)
	if d.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() {
		stop()
		cancel()
	}
}

func closedDashboardTransport() *http.Transport {
	return &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, net.ErrClosed
		},
	}
}

// upstreamHeaders builds the request headers sent to the machine dashboard
// (buildUpstreamHeaders in dashboard-proxy.ts):
//   - the browser Cookie is replaced by the dashboard token cookie so platform
//     and proxy sessions never reach the dashboard;
//   - Authorization/Proxy-Authorization are platform credentials and are
//     dropped, except on /webhook/* where they belong to the third-party
//     protocol (path token + upstream verify them);
//   - client X-Forwarded-Host/-Proto are dropped; X-Forwarded-Host is then set
//     from the browser Host this proxy actually served, which the dashboard
//     same-origin gate relies on;
//   - every reserved x-botmux-* header is dropped (second, independent layer
//     behind the machine entry point), then the platform decision is written;
//   - plain requests lose hop-by-hop fields; upgrades keep Connection/Upgrade.
func upstreamHeaders(incoming http.Header, browserHost string, machine tunnel.MachineConn, upgrade, preserveThirdPartyAuthorization bool, platform PlatformHeaders) http.Header {
	out := make(http.Header, len(incoming)+6)
	var hopByHop map[string]struct{}
	if !upgrade {
		hopByHop = hopByHopHeaderNames(incoming)
	}
	for name, values := range incoming {
		lower := strings.ToLower(name)
		switch lower {
		case "cookie", "host", "x-forwarded-host", "x-forwarded-proto":
			continue
		case "authorization", "proxy-authorization":
			if !preserveThirdPartyAuthorization {
				continue
			}
			out[name] = append([]string(nil), values...)
			continue
		}
		if IsReservedBotmuxHeader(lower) {
			continue
		}
		if _, hop := hopByHop[lower]; hop {
			continue
		}
		out[name] = append([]string(nil), values...)
	}
	if machine.DashboardToken != "" {
		out.Set("Cookie", dashboardCookie+"="+machine.DashboardToken)
	}
	if platform.Role != "" {
		out.Set("X-Botmux-Role", platform.Role)
	}
	if platform.Actor != "" {
		out.Set("X-Botmux-Actor", platform.Actor)
	}
	if platform.Scopes != "" {
		out.Set("X-Botmux-Scopes", platform.Scopes)
	}
	if platform.LoginURL != "" {
		out.Set("X-Botmux-Login-Url", platform.LoginURL)
	}
	if browserHost != "" {
		out.Set("X-Forwarded-Host", browserHost)
	}
	out.Set("Host", "127.0.0.1:"+strconv.Itoa(machine.DashboardPort))
	return out
}

// requestHasBody reads only Transfer-Encoding / Content-Length, for every
// method. Content-Length: 0 counts as bodyless so such requests keep their
// direct-path and stale-reuse retry eligibility.
func requestHasBody(r *http.Request) bool {
	if len(r.TransferEncoding) > 0 || r.Header.Get("Transfer-Encoding") != "" {
		return true
	}
	if r.ContentLength > 0 {
		return true
	}
	if value := r.Header.Get("Content-Length"); value != "" {
		if n, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil && n > 0 {
			return true
		}
	}
	return false
}

// isWebhookPath decides on the WHATWG pathname of the raw target, like
// dashboard-proxy.ts (`new URL(req.url, base).pathname`).
func isWebhookPath(r *http.Request) bool {
	path, _ := SplitRequestTarget(r)
	return strings.HasPrefix(WHATWGPathname(path), "/webhook/")
}

type proxyErrorBody struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error"`
	Detail string `json:"detail"`
}

// writeProxyError answers a failed proxy attempt with the JSON body the
// dashboard frontend can parse ({ok:false,error,detail}, JSON.stringify
// bytes). detail mirrors Node's String(err) ("Error: <message>").
func writeProxyError(w http.ResponseWriter, message string, detail error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = w.Write(marshalJSONCompat(proxyErrorBody{OK: false, Error: message, Detail: nodeErrorString(detail)}))
}

func nodeErrorString(err error) string {
	if err == nil {
		return "Error"
	}
	return "Error: " + err.Error()
}

// marshalJSONCompat encodes like JSON.stringify: no HTML escaping and no
// trailing newline.
func marshalJSONCompat(value any) []byte {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

func setNoDelay(conn net.Conn) {
	type noDelayer interface{ SetNoDelay(bool) error }
	if tcp, ok := conn.(noDelayer); ok {
		_ = tcp.SetNoDelay(true)
	}
}
