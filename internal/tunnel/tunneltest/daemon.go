// Package tunneltest runs a fake botmux daemon against a real tunnel server
// for tests: the daemon registers over /tunnel/control and, for every
// open-stream, dials /tunnel/data back and bridges it to a local TCP
// "dashboard". This is the Go equivalent of the fake TunnelRegistry whose
// requestStream connects straight to a test upstream in the Node tests,
// except that the real control/data protocol is exercised too.
package tunneltest

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/tunnel"
	"github.com/gorilla/websocket"
)

// Options describe the machine the fake daemon registers.
type Options struct {
	MachineID      string
	UnionID        string
	OwnerName      string
	Name           string
	DashboardToken string
	// BotmuxVersion is the version the fake daemon registers with
	// (default "test").
	BotmuxVersion string
}

// Daemon is a running fake daemon and its tunnel server.
type Daemon struct {
	Registry *tunnel.Registry
	Server   *tunnel.Server
	Machine  tunnel.MachineConn

	httpServer *httptest.Server
	upstream   string
	control    *websocket.Conn
	wg         sync.WaitGroup
	mu         sync.Mutex
	streams    []*websocket.Conn
	closed     bool
}

type verifier struct{ claims tunnel.MachineClaims }

func (v verifier) VerifyMachineToken(token string) (*tunnel.MachineClaims, bool) {
	if token != "daemon-token" {
		return nil, false
	}
	claims := v.claims
	return &claims, true
}

type authority struct{ record tunnel.MachineRecord }

func (a authority) LookupMachineRecord(context.Context, string) (tunnel.MachineRecord, bool, error) {
	return a.record, true, nil
}

// Start registers a fake daemon whose dashboard is the TCP listener at
// upstreamAddr (host:port). The dashboard port reported at registration is
// the upstream's port, like the Node tests' fakeMachine.
func Start(t testing.TB, upstreamAddr string, opts Options) *Daemon {
	t.Helper()
	if opts.BotmuxVersion == "" {
		opts.BotmuxVersion = "test"
	}
	if opts.MachineID == "" {
		opts.MachineID = "feedfacefeedface"
	}
	if opts.UnionID == "" {
		opts.UnionID = "u-owner"
	}
	if opts.DashboardToken == "" {
		opts.DashboardToken = "tok-123"
	}
	if opts.Name == "" {
		opts.Name = "fake-daemon"
	}
	_, portText, _ := net.SplitHostPort(upstreamAddr)
	port, _ := strconv.Atoi(portText)

	registry := tunnel.NewRegistry(time.Minute, "", nil)
	server := tunnel.NewServer(registry, verifier{claims: tunnel.MachineClaims{
		MachineID: opts.MachineID, UnionID: opts.UnionID, OwnerName: opts.OwnerName, IssuedAt: 1,
	}})
	server.Machines = authority{record: tunnel.MachineRecord{UnionID: opts.UnionID, OwnerName: opts.OwnerName}}
	server.Fanout = tunnel.NewFanoutThrottle()
	d := &Daemon{Registry: registry, Server: server, httpServer: httptest.NewServer(server), upstream: upstreamAddr}
	t.Cleanup(d.Close)

	base := "ws" + strings.TrimPrefix(d.httpServer.URL, "http")
	control, _, err := websocket.DefaultDialer.Dial(base+"/tunnel/control?token=daemon-token", nil)
	if err != nil {
		t.Fatalf("fake daemon control dial: %v", err)
	}
	d.control = control
	if err := control.WriteJSON(map[string]any{
		"type": "register", "name": opts.Name, "botmuxVersion": opts.BotmuxVersion,
		"dashboardToken": opts.DashboardToken, "dashboardPort": port,
	}); err != nil {
		t.Fatalf("fake daemon register: %v", err)
	}
	var reply struct {
		Type string `json:"type"`
	}
	_ = control.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := control.ReadJSON(&reply); err != nil || reply.Type != "registered" {
		t.Fatalf("fake daemon registration: %+v %v", reply, err)
	}
	_ = control.SetReadDeadline(time.Time{})
	machine, ok := registry.Get(opts.MachineID)
	if !ok {
		t.Fatal("fake daemon not in registry")
	}
	d.Machine = machine

	d.wg.Add(1)
	go d.controlLoop(base)
	return d
}

func (d *Daemon) controlLoop(base string) {
	defer d.wg.Done()
	for {
		_, data, err := d.control.ReadMessage()
		if err != nil {
			return
		}
		var message struct {
			Type     string `json:"type"`
			StreamID string `json:"streamId"`
		}
		if json.Unmarshal(data, &message) != nil || message.Type != "open-stream" {
			continue
		}
		d.wg.Add(1)
		go d.serveStream(base, message.StreamID)
	}
}

func (d *Daemon) serveStream(base, streamID string) {
	defer d.wg.Done()
	ws, _, err := websocket.DefaultDialer.Dial(base+"/tunnel/data?token=daemon-token&stream="+streamID, nil)
	if err != nil {
		return
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		_ = ws.Close()
		return
	}
	d.streams = append(d.streams, ws)
	d.mu.Unlock()
	upstream, err := net.Dial("tcp", d.upstream)
	if err != nil {
		_ = ws.Close()
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 32<<10)
		for {
			n, err := upstream.Read(buffer)
			if n > 0 {
				if ws.WriteMessage(websocket.BinaryMessage, buffer[:n]) != nil {
					return
				}
			}
			if err != nil {
				// The dashboard ended or died: end the tunnel stream like the
				// daemon does (close frame, then the socket).
				_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
				_ = ws.Close()
				return
			}
		}
	}()
	for {
		_, reader, err := ws.NextReader()
		if err != nil {
			break
		}
		if _, err := io.Copy(upstream, reader); err != nil {
			break
		}
	}
	_ = upstream.Close()
	<-done
}

// Close stops the daemon and its tunnel server.
func (d *Daemon) Close() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	streams := d.streams
	d.mu.Unlock()
	if d.control != nil {
		_ = d.control.Close()
	}
	for _, ws := range streams {
		_ = ws.Close()
	}
	_ = d.Registry.Close()
	d.httpServer.CloseClientConnections()
	d.httpServer.Close()
	d.wg.Wait()
}
