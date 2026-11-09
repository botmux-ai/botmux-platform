package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	tunnelShutdownCloseGrace     = 250 * time.Millisecond
	tunnelShutdownCloseAbortWait = 250 * time.Millisecond
)

type ControlSocket struct {
	conn      *websocket.Conn
	mu        sync.Mutex
	closeCode atomic.Int64
}

func NewControlSocket(conn *websocket.Conn) *ControlSocket { return &ControlSocket{conn: conn} }

// Send writes one platform message as a text frame with JSON.stringify bytes
// (no trailing newline, no HTML escaping), like ws.send(JSON.stringify(msg)).
func (c *ControlSocket) Send(value any) error {
	data, err := marshalMessage(value)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.conn.WriteMessage(websocket.TextMessage, data)
}

func (c *ControlSocket) Ping() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
}

func (c *ControlSocket) Close(code int, reason string) error {
	c.closeCode.CompareAndSwap(0, int64(code))
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
	return c.conn.Close()
}

func (c *ControlSocket) Terminate() error {
	c.closeCode.CompareAndSwap(0, websocket.CloseAbnormalClosure)
	return c.conn.Close()
}

func (c *ControlSocket) ObservedCloseCode(err error) int {
	if code := c.closeCode.Load(); code != 0 {
		return int(code)
	}
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		return closeErr.Code
	}
	if err != nil {
		return websocket.CloseAbnormalClosure
	}
	return websocket.CloseNormalClosure
}

func (c *ControlSocket) Raw() *websocket.Conn { return c.conn }

type MachineConn struct {
	MachineID      string
	UnionID        string
	OwnerName      string
	Name           string
	BotmuxVersion  string
	DashboardToken string
	DashboardPort  int
	DirectHosts    []string
	Memberships    []MembershipInfo
	Bots           []BotInfo
	TeamSyncRev    *string
	LastSeen       time.Time
	Control        *ControlSocket
}

// cloneSlice copies values keeping nil and empty apart: the daemon's
// `memberships: []` is persisted and listed as [] (TS stores the array as
// received), never as null.
func cloneSlice[T any](values []T) []T {
	if values == nil {
		return nil
	}
	return append(make([]T, 0, len(values)), values...)
}

func (m *MachineConn) Snapshot() MachineConn {
	out := *m
	out.DirectHosts = cloneSlice(m.DirectHosts)
	out.Memberships = cloneSlice(m.Memberships)
	out.Bots = cloneSlice(m.Bots)
	if m.TeamSyncRev != nil {
		rev := *m.TeamSyncRev
		out.TeamSyncRev = &rev
	}
	return out
}

type StreamOwnerStore interface {
	SetStreamOwner(ctx context.Context, streamID, owner string, ttl time.Duration) error
}

type pendingStream struct {
	machineID string
	result    chan streamResult
	timer     *time.Timer
}

type streamResult struct {
	conn net.Conn
	err  error
}

type Registry struct {
	mu          sync.RWMutex
	machines    map[string]*MachineConn
	pending     map[string]*pendingStream
	controls    map[*ControlSocket]struct{}
	dataConns   map[*trackedDataConn]struct{}
	activeCtrl  atomic.Int64
	activeData  atomic.Int64
	staleAfter  time.Duration
	selfPodAddr string
	routes      StreamOwnerStore
	onDrop      func(string)
	closed      bool
}

// RegistrySnapshot is deliberately identifier-free so it can be exported to
// a metrics bridge or logged without exposing machine or stream credentials.
// ActiveControls includes upgraded sockets that have not registered yet;
// RegisteredMachines counts authoritative controls in the registry.
type RegistrySnapshot struct {
	ActiveControls     int64 `json:"activeControls"`
	RegisteredMachines int   `json:"registeredMachines"`
	ActiveDataStreams  int64 `json:"activeDataStreams"`
	PendingStreams     int   `json:"pendingStreams"`
}

func NewRegistry(staleAfter time.Duration, selfPodAddr string, routes StreamOwnerStore) *Registry {
	return &Registry{
		machines:    make(map[string]*MachineConn),
		pending:     make(map[string]*pendingStream),
		controls:    make(map[*ControlSocket]struct{}),
		dataConns:   make(map[*trackedDataConn]struct{}),
		staleAfter:  staleAfter,
		selfPodAddr: selfPodAddr,
		routes:      routes,
	}
}

func (r *Registry) SetDropHook(fn func(string)) {
	r.mu.Lock()
	r.onDrop = fn
	r.mu.Unlock()
}

func (r *Registry) Snapshot() RegistrySnapshot {
	r.mu.RLock()
	registered := len(r.machines)
	pending := len(r.pending)
	r.mu.RUnlock()
	return RegistrySnapshot{
		ActiveControls:     r.activeCtrl.Load(),
		RegisteredMachines: registered,
		ActiveDataStreams:  r.activeData.Load(),
		PendingStreams:     pending,
	}
}

func (r *Registry) controlOpened(control *ControlSocket) (int64, bool) {
	r.mu.Lock()
	if r.closed {
		active := r.activeCtrl.Load()
		r.mu.Unlock()
		return active, false
	}
	r.controls[control] = struct{}{}
	active := r.activeCtrl.Add(1)
	r.mu.Unlock()
	return active, true
}

func (r *Registry) controlClosed(control *ControlSocket) int64 {
	r.mu.Lock()
	_, tracked := r.controls[control]
	if tracked {
		delete(r.controls, control)
	}
	r.mu.Unlock()
	if tracked {
		return r.activeCtrl.Add(-1)
	}
	return r.activeCtrl.Load()
}

func (r *Registry) Upsert(conn *MachineConn) {
	_ = r.Register(conn, true)
}

// Register installs conn as the authoritative machine control. A control's
// first register may replace an existing connection; subsequent register
// messages may only refresh state while that same control is still current.
// This prevents a replaced control from retaking authority by replaying its
// register message.
func (r *Registry) Register(conn *MachineConn, mayReplace bool) bool {
	if conn == nil {
		return false
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return false
	}
	previous := r.machines[conn.MachineID]
	if !mayReplace && (previous == nil || previous.Control != conn.Control) {
		r.mu.Unlock()
		return false
	}
	r.machines[conn.MachineID] = conn
	r.mu.Unlock()
	if previous != nil && previous.Control != nil && previous.Control.conn != nil && previous.Control != conn.Control {
		go func() { _ = previous.Control.Close(4001, "replaced by new control connection") }()
	}
	return true
}

func (r *Registry) IsCurrent(machineID string, control *ControlSocket) bool {
	r.mu.RLock()
	machine := r.machines[machineID]
	current := machine != nil && machine.Control == control
	r.mu.RUnlock()
	return current
}

func (r *Registry) Heartbeat(machineID string, control *ControlSocket, msg *DaemonMessage) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	machine := r.machines[machineID]
	if machine == nil || machine.Control != control {
		return false
	}
	if msg.BotmuxVersion != "" {
		machine.BotmuxVersion = msg.BotmuxVersion
	}
	if msg.DashboardToken != "" {
		machine.DashboardToken = msg.DashboardToken
	}
	if msg.DirectHosts != nil {
		machine.DirectHosts = cloneSlice(msg.DirectHosts)
	}
	if msg.Memberships != nil {
		machine.Memberships = cloneSlice(msg.Memberships)
	}
	if msg.Bots != nil {
		machine.Bots = cloneSlice(msg.Bots)
	}
	if msg.TeamSyncRev != nil {
		rev := *msg.TeamSyncRev
		machine.TeamSyncRev = &rev
	}
	machine.LastSeen = time.Now()
	return true
}

// Remove tears down machine state only when control is still authoritative.
// The return value lets callers guard related external cleanup (for example,
// deleting the Redis route) against a stale connection's deferred close.
func (r *Registry) Remove(machineID string, control *ControlSocket) bool {
	var rejected []*pendingStream
	var onDrop func(string)
	r.mu.Lock()
	current := r.machines[machineID]
	if current == nil || current.Control != control {
		// A replacement control is already authoritative. The old control's
		// deferred cleanup must not delete streams opened through the new
		// connection or clear its dashboard connection pool.
		r.mu.Unlock()
		return false
	}
	delete(r.machines, machineID)
	for id, pending := range r.pending {
		if pending.machineID == machineID {
			delete(r.pending, id)
			pending.timer.Stop()
			rejected = append(rejected, pending)
		}
	}
	onDrop = r.onDrop
	r.mu.Unlock()
	for _, pending := range rejected {
		pending.result <- streamResult{err: errors.New("machine disconnected")}
	}
	if onDrop != nil {
		onDrop(machineID)
	}
	return true
}

func (r *Registry) Get(machineID string) (MachineConn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	machine := r.machines[machineID]
	if machine == nil {
		return MachineConn{}, false
	}
	return machine.Snapshot(), true
}

func (r *Registry) HasPending(streamID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.pending[streamID]
	return ok
}

func (r *Registry) ListForUser(unionID string) []MachineConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]MachineConn, 0)
	for _, machine := range r.machines {
		if machine.UnionID == unionID {
			out = append(out, machine.Snapshot())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (r *Registry) ListForUnionIDs(unionIDs []string) []MachineConn {
	wanted := make(map[string]struct{}, len(unionIDs))
	for _, id := range unionIDs {
		wanted[id] = struct{}{}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]MachineConn, 0)
	for _, machine := range r.machines {
		if _, ok := wanted[machine.UnionID]; ok {
			out = append(out, machine.Snapshot())
		}
	}
	return out
}

// ListAll returns every machine registered on this pod (the version
// dashboard overlays live versions with it).
func (r *Registry) ListAll() []MachineConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]MachineConn, 0, len(r.machines))
	for _, machine := range r.machines {
		out = append(out, machine.Snapshot())
	}
	return out
}

func (r *Registry) ListForTeam(teamID string) []MachineConn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]MachineConn, 0)
	for _, machine := range r.machines {
		for _, membership := range machine.Memberships {
			if membership.TeamID == teamID {
				out = append(out, machine.Snapshot())
				break
			}
		}
	}
	return out
}

func (r *Registry) IsStale(machine MachineConn) bool {
	return time.Since(machine.LastSeen) > r.staleAfter
}

func (r *Registry) SendToMachine(machineID string, message any) bool {
	r.mu.RLock()
	machine := r.machines[machineID]
	r.mu.RUnlock()
	return machine != nil && machine.Control.Send(message) == nil
}

func (r *Registry) SendToUser(unionID string, message any) int {
	machines := r.ListForUser(unionID)
	delivered := 0
	for i := range machines {
		if machines[i].Control.Send(message) == nil {
			delivered++
		}
	}
	return delivered
}

func (r *Registry) UnbindLocal(machineID string) bool {
	r.mu.RLock()
	machine := r.machines[machineID]
	r.mu.RUnlock()
	if machine == nil {
		return false
	}
	_ = machine.Control.Send(unboundMessage{Type: "unbound"})
	_ = machine.Control.Close(4005, "unbound")
	return true
}

func (r *Registry) RequestStream(ctx context.Context, machineID string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	r.mu.RLock()
	machine := r.machines[machineID]
	r.mu.RUnlock()
	if machine == nil {
		return nil, errors.New("machine_offline")
	}
	streamID, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	result := make(chan streamResult, 1)
	pending := &pendingStream{machineID: machineID, result: result}
	pending.timer = time.AfterFunc(timeout, func() {
		r.finishPending(streamID, streamResult{err: errors.New("stream_timeout")})
	})
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		pending.timer.Stop()
		return nil, net.ErrClosed
	}
	r.pending[streamID] = pending
	r.mu.Unlock()

	if r.routes != nil && r.selfPodAddr != "" {
		if err := r.routes.SetStreamOwner(ctx, streamID, r.selfPodAddr, 30*time.Second); err != nil {
			// The local pending stream still works. Cross-pod return may fail, so
			// keep the original fail-open behavior and let the timeout report it.
			slog.Warn("runtime dependency failure", "dependency", "redis", "operation", "set_stream_owner", "machineId", machineID, "streamId", streamID, "error", err)
		}
	}
	if err := machine.Control.Send(openStreamMessage{Type: "open-stream", StreamID: streamID}); err != nil {
		r.finishPending(streamID, streamResult{err: err})
	}

	select {
	case got := <-result:
		return got.conn, got.err
	case <-ctx.Done():
		r.finishPending(streamID, streamResult{err: ctx.Err()})
		return nil, ctx.Err()
	}
}

func (r *Registry) AttachDataStream(streamID, machineID string, ws *websocket.Conn) bool {
	return r.attachDataConn(streamID, machineID, NewWebSocketConn(ws))
}

func (r *Registry) attachDataConn(streamID, machineID string, conn net.Conn) bool {
	r.mu.Lock()
	pending := r.pending[streamID]
	if r.closed || pending == nil || pending.machineID != machineID {
		r.mu.Unlock()
		return false
	}
	delete(r.pending, streamID)
	pending.timer.Stop()
	tracked := r.newTrackedDataConn(conn, machineID, streamID)
	r.dataConns[tracked] = struct{}{}
	active := r.activeData.Add(1)
	r.mu.Unlock()
	slog.Info("tunnel data opened", "machineId", machineID, "streamId", streamID, "activeDataStreams", active)
	pending.result <- streamResult{conn: tracked}
	return true
}

func (r *Registry) trackDataConn(conn net.Conn, machineID, streamID string) net.Conn {
	tracked := r.newTrackedDataConn(conn, machineID, streamID)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = tracked.Close()
		return tracked
	}
	r.dataConns[tracked] = struct{}{}
	active := r.activeData.Add(1)
	r.mu.Unlock()
	slog.Info("tunnel data opened", "machineId", machineID, "streamId", streamID, "activeDataStreams", active)
	return tracked
}

func (r *Registry) newTrackedDataConn(conn net.Conn, machineID, streamID string) *trackedDataConn {
	tracked := &trackedDataConn{Conn: conn}
	tracked.onClose = func(err error) {
		r.mu.Lock()
		_, existed := r.dataConns[tracked]
		if existed {
			delete(r.dataConns, tracked)
		}
		r.mu.Unlock()
		if existed {
			active := r.activeData.Add(-1)
			slog.Info("tunnel data closed", "machineId", machineID, "streamId", streamID, "activeDataStreams", active, "error", err)
		}
	}
	return tracked
}

type trackedDataConn struct {
	net.Conn
	once    sync.Once
	onClose func(error)
}

func (c *trackedDataConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.onClose(err) })
	return err
}

func (r *Registry) finishPending(streamID string, got streamResult) {
	r.mu.Lock()
	pending := r.pending[streamID]
	if pending != nil {
		delete(r.pending, streamID)
		pending.timer.Stop()
	}
	r.mu.Unlock()
	if pending != nil {
		pending.result <- got
	}
}

func (r *Registry) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	controls := make([]*ControlSocket, 0, len(r.controls))
	for control := range r.controls {
		controls = append(controls, control)
	}
	dataConns := make([]*trackedDataConn, 0, len(r.dataConns))
	for conn := range r.dataConns {
		dataConns = append(dataConns, conn)
	}
	pending := r.pending
	r.machines = make(map[string]*MachineConn)
	r.pending = make(map[string]*pendingStream)
	r.mu.Unlock()
	for _, item := range pending {
		item.timer.Stop()
		item.result <- streamResult{err: net.ErrClosed}
	}
	connections := make([]shutdownConnection, 0, len(controls)+len(dataConns))
	for _, control := range controls {
		control := control
		connections = append(connections, shutdownConnection{
			close: func() { _ = control.Close(websocket.CloseGoingAway, "server shutdown") },
			abort: func() { _ = control.Terminate() },
		})
	}
	for _, conn := range dataConns {
		conn := conn
		connections = append(connections, shutdownConnection{
			close: func() { _ = conn.Close() },
			abort: func() { _ = conn.Close() },
		})
	}
	if !closeConnectionsConcurrently(
		connections,
		tunnelShutdownCloseGrace,
		tunnelShutdownCloseAbortWait,
	) {
		slog.Warn("tunnel connections did not drain before shutdown deadline", "controls", len(controls), "dataStreams", len(dataConns))
	}
	return nil
}

type shutdownConnection struct {
	close func()
	abort func()
}

func closeConnectionsConcurrently(
	connections []shutdownConnection,
	gracePeriod time.Duration,
	abortPeriod time.Duration,
) bool {
	var wait sync.WaitGroup
	wait.Add(len(connections))
	for _, connection := range connections {
		go func(connection shutdownConnection) {
			defer wait.Done()
			connection.close()
		}(connection)
	}
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	if waitForControlClosures(done, gracePeriod) {
		return true
	}
	for _, connection := range connections {
		if connection.abort != nil {
			go connection.abort()
		}
	}
	return waitForControlClosures(done, abortPeriod)
}

func waitForControlClosures(done <-chan struct{}, timeout time.Duration) bool {
	if timeout <= 0 {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// marshalMessage encodes a control message like JSON.stringify: no HTML
// escaping, no trailing newline. Typed messages keep their struct order.
// Callers outside this package still pass map literals ({type: 'team-sync',
// rev, teams}, {type: 'leave-team', teamId}); encoding/json would sort the
// keys and put "type" last, so maps are written with "type" first and the
// rest sorted, which is the key order of each of those Node literals.
func marshalMessage(message any) ([]byte, error) {
	if fields, ok := message.(map[string]any); ok {
		return marshalTypeFirst(fields)
	}
	return marshalCompat(message)
}

func marshalTypeFirst(fields map[string]any) ([]byte, error) {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		if key != "type" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if _, ok := fields["type"]; ok {
		keys = append([]string{"type"}, keys...)
	}
	out := []byte{'{'}
	for i, key := range keys {
		if i > 0 {
			out = append(out, ',')
		}
		name, err := marshalCompat(key)
		if err != nil {
			return nil, err
		}
		value, err := marshalCompat(fields[key])
		if err != nil {
			return nil, err
		}
		out = append(append(append(out, name...), ':'), value...)
	}
	return append(out, '}'), nil
}

func marshalCompat(message any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(message); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// Platform → daemon control messages with the key order of the Node literals.
type registeredMessage struct {
	Type      string `json:"type"`
	MachineID string `json:"machineId"`
}

type openStreamMessage struct {
	Type     string `json:"type"`
	StreamID string `json:"streamId"`
}

type unboundMessage struct {
	Type string `json:"type"`
}
