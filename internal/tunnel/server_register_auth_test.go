package tunnel

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Port of test/tunnel-register-auth.test.ts plus the backend fanout gating of
// src/tunnel/server.ts (test/tunnel-fanout-throttle.test.ts covers the memo
// itself in fanout_throttle_test.go).

const registerAuthMachineID = "feedfacefeedface"

type fixedClaimsVerifier struct{ claims MachineClaims }

func (v fixedClaimsVerifier) VerifyMachineToken(token string) (*MachineClaims, bool) {
	if token != "valid" {
		return nil, false
	}
	claims := v.claims
	return &claims, true
}

type memoryMachineAuthority struct {
	mu     sync.Mutex
	record *MachineRecord
	err    error
	reads  atomic.Int32
}

func (a *memoryMachineAuthority) LookupMachineRecord(context.Context, string) (MachineRecord, bool, error) {
	a.reads.Add(1)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.err != nil {
		return MachineRecord{}, false, a.err
	}
	if a.record == nil {
		return MachineRecord{}, false, nil
	}
	return *a.record, true, nil
}

type switchableRevocation struct {
	protocolRouteRecorder
	revoked atomic.Bool
}

func (r *switchableRevocation) IsMachineTokenRevoked(ctx context.Context, machineID string, issuedAt int64) (bool, error) {
	_, _ = r.protocolRouteRecorder.IsMachineTokenRevoked(ctx, machineID, issuedAt)
	return r.revoked.Load(), nil
}

func aliceRecord() *MachineRecord {
	return &MachineRecord{UnionID: "u-alice", OwnerName: "Alice Current", Status: "ACTIVE"}
}

func registerAuthServer(authority MachineAuthority) (*Server, *Registry) {
	registry := NewRegistry(time.Minute, "", nil)
	server := NewServer(registry, fixedClaimsVerifier{claims: MachineClaims{
		MachineID: registerAuthMachineID, UnionID: "u-alice", OwnerName: "Alice Historical", IssuedAt: 1,
	}})
	server.Machines = authority
	server.Fanout = NewFanoutThrottle()
	return server, registry
}

func registerMessage() map[string]any {
	return map[string]any{
		"type": "register", "name": "test-host", "botmuxVersion": "2.0.0",
		"dashboardToken": "dashboard-token", "dashboardPort": 7891,
		"memberships": []any{}, "bots": []any{},
	}
}

func readCloseCode(t *testing.T, conn *websocket.Conn) (int, []string) {
	t.Helper()
	var messages []string
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			var closeErr *websocket.CloseError
			if !errors.As(err, &closeErr) {
				t.Fatalf("read error = %v, want close frame", err)
			}
			return closeErr.Code, messages
		}
		messages = append(messages, string(data))
	}
}

func TestRegisterActiveOwnerReceivesRegisteredWithCurrentOwnerName(t *testing.T) {
	t.Parallel()
	server, registry := registerAuthServer(&memoryMachineAuthority{record: aliceRecord()})
	conn, done, closeServer := dialTunnelControl(t, server, false)
	defer closeServer()

	if err := conn.WriteJSON(registerMessage()); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	kind, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	// JSON.stringify bytes: key order of the Node literal, no trailing newline.
	if kind != websocket.TextMessage || string(data) != `{"type":"registered","machineId":"feedfacefeedface"}` {
		t.Fatalf("registered reply = %d %q", kind, data)
	}
	machine, ok := registry.Get(registerAuthMachineID)
	if !ok || machine.UnionID != "u-alice" {
		t.Fatalf("registry entry = %+v, %v", machine, ok)
	}
	// The display identity comes from the current MachineDoc, not the token.
	if machine.OwnerName != "Alice Current" || machine.Name != "test-host" {
		t.Fatalf("owner/name = %q/%q", machine.OwnerName, machine.Name)
	}
	_ = conn.Close()
	waitHandler(t, done)
}

func TestRegisterRejectsForeignOwnerToken(t *testing.T) {
	t.Parallel()
	server, registry := registerAuthServer(&memoryMachineAuthority{record: &MachineRecord{UnionID: "u-bob", OwnerName: "Bob", Status: "ACTIVE"}})
	conn, done, closeServer := dialTunnelControl(t, server, false)
	defer closeServer()
	if err := conn.WriteJSON(registerMessage()); err != nil {
		t.Fatal(err)
	}
	code, messages := readCloseCode(t, conn)
	if code != 4005 || len(messages) != 0 {
		t.Fatalf("close=%d messages=%q, want 4005 and none", code, messages)
	}
	waitHandler(t, done)
	if _, ok := registry.Get(registerAuthMachineID); ok {
		t.Fatal("foreign owner token reached the registry fast path")
	}
}

func TestRegisterRejectsRetiredAndMissingMachines(t *testing.T) {
	t.Parallel()
	for name, record := range map[string]*MachineRecord{
		"retired": {UnionID: "u-alice", OwnerName: "Alice", Status: "RETIRED"},
		"missing": nil,
	} {
		t.Run(name, func(t *testing.T) {
			server, registry := registerAuthServer(&memoryMachineAuthority{record: record})
			conn, done, closeServer := dialTunnelControl(t, server, false)
			defer closeServer()
			if err := conn.WriteJSON(registerMessage()); err != nil {
				t.Fatal(err)
			}
			if code, _ := readCloseCode(t, conn); code != 4005 {
				t.Fatalf("close = %d, want 4005", code)
			}
			waitHandler(t, done)
			if _, ok := registry.Get(registerAuthMachineID); ok {
				t.Fatal("machine came back online")
			}
		})
	}
}

func TestRegisterLegacyDocumentWithoutStatusIsActive(t *testing.T) {
	t.Parallel()
	server, registry := registerAuthServer(&memoryMachineAuthority{record: &MachineRecord{UnionID: "u-alice", OwnerName: "Alice"}})
	conn, done, closeServer := dialTunnelControl(t, server, false)
	defer closeServer()
	message := registerMessage()
	message["name"] = "\x01  "
	if err := conn.WriteJSON(message); err != nil {
		t.Fatal(err)
	}
	var reply registeredMessage
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := conn.ReadJSON(&reply); err != nil || reply.Type != "registered" {
		t.Fatalf("reply = %+v, %v", reply, err)
	}
	// An empty sanitized name falls back to the authoritative owner name.
	if machine, _ := registry.Get(registerAuthMachineID); machine.Name != "Alice" {
		t.Fatalf("fallback name = %q", machine.Name)
	}
	_ = conn.Close()
	waitHandler(t, done)
}

func TestRegisterAuthorityUnavailableFailsClosed(t *testing.T) {
	t.Parallel()
	failing := &memoryMachineAuthority{err: errors.New("database down")}
	if owner, reason := AuthorizeMachineRegistration(context.Background(), failing, registerAuthMachineID, "u-alice"); reason != RegistrationUnavailable || owner != "" {
		t.Fatalf("authorize = %q/%q, want unavailable", owner, reason)
	}
	if _, reason := AuthorizeMachineRegistration(context.Background(), nil, registerAuthMachineID, "u-alice"); reason != RegistrationUnavailable {
		t.Fatalf("nil authority = %q, want unavailable", reason)
	}

	server, registry := registerAuthServer(failing)
	conn, done, closeServer := dialTunnelControl(t, server, false)
	defer closeServer()
	if err := conn.WriteJSON(registerMessage()); err != nil {
		t.Fatal(err)
	}
	if code, _ := readCloseCode(t, conn); code != 1013 {
		t.Fatalf("close = %d, want 1013", code)
	}
	waitHandler(t, done)
	if _, ok := registry.Get(registerAuthMachineID); ok {
		t.Fatal("unavailable authority published the machine")
	}
}

func TestRegisterPreRegisterHeartbeatHasNoSideEffects(t *testing.T) {
	t.Parallel()
	authority := &memoryMachineAuthority{record: aliceRecord()}
	server, registry := registerAuthServer(authority)
	conn, done, closeServer := dialTunnelControl(t, server, false)
	defer closeServer()
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "botmuxVersion": "evil"}); err != nil {
		t.Fatal(err)
	}
	if code, _ := readCloseCode(t, conn); code != 4002 {
		t.Fatalf("close = %d, want 4002", code)
	}
	waitHandler(t, done)
	if _, ok := registry.Get(registerAuthMachineID); ok {
		t.Fatal("heartbeat published the machine")
	}
	if authority.reads.Load() != 0 {
		t.Fatalf("heartbeat triggered %d authority reads", authority.reads.Load())
	}
}

func TestControlIgnoresUnparseableAndRepeatedRegister(t *testing.T) {
	t.Parallel()
	authority := &memoryMachineAuthority{record: aliceRecord()}
	server, registry := registerAuthServer(authority)
	conn, done, closeServer := dialTunnelControl(t, server, false)
	defer closeServer()

	// Garbage and unknown types are dropped silently, before registration too.
	for _, raw := range []string{"not json", `{"type":"bogus"}`, `[]`, `null`} {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.WriteJSON(registerMessage()); err != nil {
		t.Fatal(err)
	}
	var reply registeredMessage
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := conn.ReadJSON(&reply); err != nil || reply.Type != "registered" {
		t.Fatalf("reply = %+v, %v", reply, err)
	}
	second := registerMessage()
	second["name"] = "renamed"
	if err := conn.WriteJSON(second); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "botmuxVersion": "2.1.0"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool {
		machine, _ := registry.Get(registerAuthMachineID)
		return machine.BotmuxVersion == "2.1.0"
	})
	machine, _ := registry.Get(registerAuthMachineID)
	if machine.Name != "test-host" {
		t.Fatalf("repeated register renamed the machine to %q", machine.Name)
	}
	if authority.reads.Load() != 1 {
		t.Fatalf("authority reads = %d, want 1 (repeated register ignored)", authority.reads.Load())
	}
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, data, err := conn.ReadMessage(); err == nil {
		t.Fatalf("unexpected reply to ignored messages: %q", data)
	}
	_ = conn.Close()
	waitHandler(t, done)
}

func TestControlRevokedAfterHandshakeClosesUnbound(t *testing.T) {
	t.Parallel()
	server, registry := registerAuthServer(&memoryMachineAuthority{record: aliceRecord()})
	routes := &switchableRevocation{}
	server.Routes = routes
	persistence := &protocolPersistenceRecorder{}
	server.Persistence = persistence
	conn, done, closeServer := dialTunnelControl(t, server, false)
	defer closeServer()
	if err := conn.WriteJSON(registerMessage()); err != nil {
		t.Fatal(err)
	}
	var reply registeredMessage
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := conn.ReadJSON(&reply); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return persistence.registers.Load() == 1 })

	routes.revoked.Store(true)
	if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "botmuxVersion": "after-unbind"}); err != nil {
		t.Fatal(err)
	}
	if code, _ := readCloseCode(t, conn); code != 4005 {
		t.Fatalf("close = %d, want 4005", code)
	}
	waitHandler(t, done)
	if _, ok := registry.Get(registerAuthMachineID); ok {
		t.Fatal("revoked control still registered")
	}
	if persistence.heartbeats.Load() != 0 {
		t.Fatal("revoked heartbeat was persisted")
	}
}

func TestTunnelHandshakeRejectionIsRawStatusLine(t *testing.T) {
	t.Parallel()
	for name, setup := range map[string]func(*Server){
		"invalid token": func(*Server) {},
		"revoked token": func(s *Server) {
			routes := &switchableRevocation{}
			routes.revoked.Store(true)
			s.Routes = routes
		},
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := registerAuthServer(&memoryMachineAuthority{record: aliceRecord()})
			setup(server)
			token := "valid"
			if name == "invalid token" {
				token = "forged"
			}
			httpServer := httptest.NewServer(server)
			defer httpServer.Close()
			conn, err := net.Dial("tcp", strings.TrimPrefix(httpServer.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_, _ = io.WriteString(conn, "GET /tunnel/control?token="+token+" HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
				"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			raw, _ := io.ReadAll(bufio.NewReader(conn))
			if string(raw) != "HTTP/1.1 401 Unauthorized\r\n\r\n" {
				t.Fatalf("handshake rejection = %q", raw)
			}
		})
	}
}

func TestBackendFanoutGatesPersistenceRouteAndTeamSyncOnly(t *testing.T) {
	t.Parallel()
	server, registry := registerAuthServer(&memoryMachineAuthority{record: aliceRecord()})
	routes := &protocolRouteRecorder{}
	persistence := &protocolPersistenceRecorder{}
	teamSync := &protocolTeamSyncRecorder{}
	server.Routes, server.Persistence, server.TeamSync = routes, persistence, teamSync
	server.SelfPodAddress = "pod-a"
	server.FanoutWindow = time.Hour
	conn, done, closeServer := dialTunnelControl(t, server, false)
	defer closeServer()

	message := registerMessage()
	message["teamSyncRev"] = "rev-1"
	if err := conn.WriteJSON(message); err != nil {
		t.Fatal(err)
	}
	var reply registeredMessage
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := conn.ReadJSON(&reply); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := conn.WriteJSON(map[string]any{"type": "heartbeat", "botmuxVersion": "storm", "teamSyncRev": "rev-1"}); err != nil {
			t.Fatal(err)
		}
	}
	// The in-memory registry is never throttled.
	eventually(t, func() bool {
		machine, _ := registry.Get(registerAuthMachineID)
		return machine.BotmuxVersion == "storm"
	})
	eventually(t, func() bool {
		return persistence.registers.Load() == 1 && routes.setMachine.Load() == 1 && teamSync.calls.Load() == 1
	})
	time.Sleep(50 * time.Millisecond)
	if persistence.heartbeats.Load() != 0 || routes.setMachine.Load() != 1 || teamSync.calls.Load() != 1 {
		t.Fatalf("storm leaked fan-out: heartbeats=%d routes=%d teamSync=%d",
			persistence.heartbeats.Load(), routes.setMachine.Load(), teamSync.calls.Load())
	}
	// Revocation is a security check: it runs for every message.
	if got := routes.revocationReads.Load(); got != 7 {
		t.Fatalf("revocation reads = %d, want handshake + 6 messages", got)
	}
	if stats := server.Fanout.Stats(); stats.Runs != 1 || stats.Skipped != 5 {
		t.Fatalf("fanout stats = %+v", stats)
	}
	_ = conn.Close()
	waitHandler(t, done)
}

func TestBackendFanoutRunsEveryBeatOutsideWindow(t *testing.T) {
	t.Parallel()
	server, _ := registerAuthServer(&memoryMachineAuthority{record: aliceRecord()})
	persistence := &protocolPersistenceRecorder{}
	server.Persistence = persistence
	server.FanoutWindow = time.Nanosecond
	conn, done, closeServer := dialTunnelControl(t, server, false)
	defer closeServer()
	if err := conn.WriteJSON(registerMessage()); err != nil {
		t.Fatal(err)
	}
	var reply registeredMessage
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := conn.ReadJSON(&reply); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		time.Sleep(time.Millisecond)
		if err := conn.WriteJSON(map[string]any{"type": "heartbeat"}); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, func() bool { return persistence.registers.Load() == 1 && persistence.heartbeats.Load() == 3 })
	_ = conn.Close()
	waitHandler(t, done)
}

func TestRegistryListAll(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(time.Minute, "", nil)
	if got := registry.ListAll(); len(got) != 0 {
		t.Fatalf("empty registry ListAll = %+v", got)
	}
	registry.machines["a"] = &MachineConn{MachineID: "a"}
	registry.machines["b"] = &MachineConn{MachineID: "b"}
	got := registry.ListAll()
	if len(got) != 2 {
		t.Fatalf("ListAll = %+v", got)
	}
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var (
	_ MachineAuthority = (*memoryMachineAuthority)(nil)
	_ RouteStore       = (*switchableRevocation)(nil)
	_ http.Handler     = (*Server)(nil)
)

func TestMapControlMessagesKeepNodeKeyOrder(t *testing.T) {
	for _, tc := range []struct {
		message map[string]any
		want    string
	}{
		{map[string]any{"type": "team-sync", "rev": "r1", "teams": []any{}}, `{"type":"team-sync","rev":"r1","teams":[]}`},
		{map[string]any{"type": "leave-team", "teamId": "t<1>"}, `{"type":"leave-team","teamId":"t<1>"}`},
	} {
		got, err := marshalMessage(tc.message)
		if err != nil || string(got) != tc.want {
			t.Fatalf("marshalMessage = %s, %v; want %s", got, err, tc.want)
		}
	}
	got, _ := marshalMessage(registeredMessage{Type: "registered", MachineID: "m1"})
	if string(got) != `{"type":"registered","machineId":"m1"}` {
		t.Fatalf("typed = %s", got)
	}
}

func TestSnapshotKeepsEmptyMembershipsAndBots(t *testing.T) {
	conn := MachineConn{Memberships: []MembershipInfo{}, Bots: []BotInfo{}}
	snapshot := conn.Snapshot()
	if snapshot.Memberships == nil || snapshot.Bots == nil || snapshot.DirectHosts != nil {
		t.Fatalf("snapshot = %#v", snapshot)
	}
}
