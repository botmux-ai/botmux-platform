package tunnel

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type acceptingMachineVerifier struct{}

func (acceptingMachineVerifier) VerifyMachineToken(string) (*MachineClaims, bool) {
	return &MachineClaims{MachineID: "machine-1", UnionID: "user-1", OwnerName: "Owner", IssuedAt: 1}, true
}

type protocolRouteRecorder struct {
	setMachine      atomic.Int32
	setStream       atomic.Int32
	deletes         atomic.Int32
	revocationReads atomic.Int32
}

func (r *protocolRouteRecorder) SetStreamOwner(context.Context, string, string, time.Duration) error {
	r.setStream.Add(1)
	return nil
}

func (r *protocolRouteRecorder) IsMachineTokenRevoked(context.Context, string, int64) (bool, error) {
	r.revocationReads.Add(1)
	return false, nil
}
func (r *protocolRouteRecorder) SetMachineRoute(context.Context, string, string, time.Duration) error {
	r.setMachine.Add(1)
	return nil
}
func (r *protocolRouteRecorder) DeleteMachineRoute(context.Context, string, string) error {
	r.deletes.Add(1)
	return nil
}
func (*protocolRouteRecorder) GetStreamOwner(context.Context, string) (string, error) {
	return "", nil
}

type protocolPersistenceRecorder struct {
	registers  atomic.Int32
	heartbeats atomic.Int32
}

func (p *protocolPersistenceRecorder) PersistRegister(context.Context, MachineConn) error {
	p.registers.Add(1)
	return nil
}
func (p *protocolPersistenceRecorder) PersistHeartbeat(context.Context, string, DaemonMessage, time.Time) error {
	p.heartbeats.Add(1)
	return nil
}

type protocolTeamSyncRecorder struct{ calls atomic.Int32 }

func (s *protocolTeamSyncRecorder) MaybeSendTeamSync(context.Context, string, string) error {
	s.calls.Add(1)
	return nil
}

func TestControlRequiresRegisterBeforeHeartbeatWithoutSideEffects(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(time.Minute, "pod-a", nil)
	routes := &protocolRouteRecorder{}
	persistence := &protocolPersistenceRecorder{}
	teamSync := &protocolTeamSyncRecorder{}
	server := NewServer(registry, acceptingMachineVerifier{})
	server.Routes = routes
	server.Persistence = persistence
	server.TeamSync = teamSync
	server.SelfPodAddress = "pod-a"
	done := make(chan struct{})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.ServeHTTP(w, r)
		close(done)
	}))
	defer httpServer.Close()

	dialer := websocket.Dialer{EnableCompression: true}
	conn, response, err := dialer.Dial(websocketURL(httpServer.URL)+"/tunnel/control?token=valid", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if extension := strings.ToLower(response.Header.Get("Sec-WebSocket-Extensions")); strings.Contains(extension, "permessage-deflate") {
		t.Fatalf("server negotiated forbidden compression: %q", extension)
	}
	if err := conn.WriteJSON(map[string]any{
		"type": "heartbeat", "botmuxVersion": "2.80.0", "teamSyncRev": "rev",
	}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err = conn.ReadMessage()
	assertCloseCode(t, err, 4002)
	waitHandler(t, done)

	if _, ok := registry.Get("machine-1"); ok {
		t.Fatal("pre-register heartbeat created a live machine")
	}
	if persistence.registers.Load() != 0 || persistence.heartbeats.Load() != 0 {
		t.Fatalf("persistence side effects: register=%d heartbeat=%d", persistence.registers.Load(), persistence.heartbeats.Load())
	}
	if routes.setMachine.Load() != 0 || routes.setStream.Load() != 0 || routes.deletes.Load() != 0 {
		t.Fatalf("route side effects: machine=%d stream=%d delete=%d", routes.setMachine.Load(), routes.setStream.Load(), routes.deletes.Load())
	}
	// Like Node: the handshake check plus the per-message cutoff check that
	// runs before any message is dispatched.
	if routes.revocationReads.Load() != 2 {
		t.Fatalf("pre-register heartbeat performed %d revocation reads; want handshake + message", routes.revocationReads.Load())
	}
	if teamSync.calls.Load() != 0 {
		t.Fatalf("team-sync side effects = %d", teamSync.calls.Load())
	}
}

func TestRegistryCloseTerminatesPreRegisterControl(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(time.Minute, "", nil)
	server := NewServer(registry, acceptingMachineVerifier{})
	conn, done, closeServer := dialTunnelControl(t, server, false)
	defer closeServer()

	deadline := time.Now().Add(time.Second)
	for registry.Snapshot().ActiveControls != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := registry.Snapshot().ActiveControls; got != 1 {
		t.Fatalf("active pre-register controls = %d", got)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("pre-register control remained open after registry shutdown")
	}
	waitHandler(t, done)
	if got := registry.Snapshot().ActiveControls; got != 0 {
		t.Fatalf("active controls after shutdown = %d", got)
	}
}

func TestControlReadLimitBoundary(t *testing.T) {
	t.Parallel()
	t.Run("exact limit accepted", func(t *testing.T) {
		server := NewServer(NewRegistry(time.Minute, "", nil), acceptingMachineVerifier{})
		server.Machines = &memoryMachineAuthority{record: &MachineRecord{UnionID: "user-1", OwnerName: "Owner"}}
		// Reading and decoding 16MiB under -race takes ~9-11s on CI build
		// machines, so the production 10s register timeout would make this
		// boundary check flaky. The timeout is not what is under test here.
		server.RegisterTimeout = time.Minute
		conn, done, closeServer := dialTunnelControl(t, server, false)
		defer closeServer()
		payload := registerPayload(controlReadLimit)
		if len(payload) != controlReadLimit {
			t.Fatalf("payload size = %d", len(payload))
		}
		_ = conn.SetWriteDeadline(time.Now().Add(time.Minute))
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(time.Minute))
		var reply struct {
			Type      string `json:"type"`
			MachineID string `json:"machineId"`
		}
		if err := conn.ReadJSON(&reply); err != nil {
			t.Fatal(err)
		}
		if reply.Type != "registered" || reply.MachineID != "machine-1" {
			t.Fatalf("reply = %+v", reply)
		}
		_ = conn.Close()
		waitHandler(t, done)
	})

	t.Run("one byte over closes 1009", func(t *testing.T) {
		server := NewServer(NewRegistry(time.Minute, "", nil), acceptingMachineVerifier{})
		conn, done, closeServer := dialTunnelControl(t, server, false)
		defer closeServer()
		payload := make([]byte, controlReadLimit+1)
		for i := range payload {
			payload[i] = 'x'
		}
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, _, err := conn.ReadMessage()
		assertCloseCode(t, err, websocket.CloseMessageTooBig)
		waitHandler(t, done)
	})
}

func dialTunnelControl(t *testing.T, server *Server, compression bool) (*websocket.Conn, <-chan struct{}, func()) {
	t.Helper()
	done := make(chan struct{})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.ServeHTTP(w, r)
		close(done)
	}))
	dialer := websocket.Dialer{EnableCompression: compression}
	conn, _, err := dialer.Dial(websocketURL(httpServer.URL)+"/tunnel/control?token=valid", nil)
	if err != nil {
		httpServer.Close()
		t.Fatal(err)
	}
	return conn, done, func() {
		_ = conn.Close()
		httpServer.Close()
	}
}

func registerPayload(size int) []byte {
	prefix := []byte(`{"type":"register","name":"`)
	suffix := []byte(`"}`)
	if size < len(prefix)+len(suffix) {
		return nil
	}
	payload := make([]byte, size)
	copy(payload, prefix)
	for i := len(prefix); i < size-len(suffix); i++ {
		payload[i] = 'a'
	}
	copy(payload[size-len(suffix):], suffix)
	return payload
}

func assertCloseCode(t *testing.T, err error, code int) {
	t.Helper()
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) || closeErr.Code != code {
		t.Fatalf("close error = %v, want code %d", err, code)
	}
}

func waitHandler(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("tunnel handler did not exit")
	}
}

func websocketURL(httpURL string) string { return "ws" + strings.TrimPrefix(httpURL, "http") }

var (
	_ MachineTokenVerifier = acceptingMachineVerifier{}
	_ RouteStore           = (*protocolRouteRecorder)(nil)
	_ MachinePersistence   = (*protocolPersistenceRecorder)(nil)
	_ TeamSyncSender       = (*protocolTeamSyncRecorder)(nil)
)
