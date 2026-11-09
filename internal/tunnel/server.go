package tunnel

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const controlReadLimit = 16 << 20

const defaultRegisterTimeout = 10 * time.Second

type MachineClaims struct {
	MachineID string
	UnionID   string
	OwnerName string
	IssuedAt  int64
}

type MachineTokenVerifier interface {
	VerifyMachineToken(token string) (*MachineClaims, bool)
}

type RouteStore interface {
	StreamOwnerStore
	IsMachineTokenRevoked(ctx context.Context, machineID string, issuedAt int64) (bool, error)
	SetMachineRoute(ctx context.Context, machineID, owner string, ttl time.Duration) error
	DeleteMachineRoute(ctx context.Context, machineID, expectedOwner string) error
	GetStreamOwner(ctx context.Context, streamID string) (string, error)
}

type MachinePersistence interface {
	PersistRegister(ctx context.Context, machine MachineConn) error
	PersistHeartbeat(ctx context.Context, machineID string, message DaemonMessage, lastSeen time.Time) error
}

type TeamSyncSender interface {
	MaybeSendTeamSync(ctx context.Context, machineID, daemonRevision string) error
}

type RawWebSocketForwarder func(owner string, w http.ResponseWriter, r *http.Request) error

// MachineRecord is the projection of the authoritative MachineDoc that
// registration re-reads. An empty Status means ACTIVE (documents written
// before the lifecycle migration).
type MachineRecord struct {
	UnionID   string
	OwnerName string
	Status    string
}

// MachineAuthority reads the current MachineDoc. found=false means there is
// no document; any error means the store is unavailable and registration
// fails closed.
type MachineAuthority interface {
	LookupMachineRecord(ctx context.Context, machineID string) (record MachineRecord, found bool, err error)
}

// RegistrationRejection is why AuthorizeMachineRegistration refused a token.
type RegistrationRejection string

const (
	RegistrationUnavailable   RegistrationRejection = "unavailable"
	RegistrationNotActive     RegistrationRejection = "not_active"
	RegistrationOwnerMismatch RegistrationRejection = "owner_mismatch"
)

const machineStatusActive = "ACTIVE"

// AuthorizeMachineRegistration re-reads ownership before a control socket is
// published. A signed machine token is historical authority, not current
// ownership: an unbound/rebound or RETIRED machine must not come back online
// on this pod's fast path. On success it returns the current owner display
// name from the MachineDoc.
func AuthorizeMachineRegistration(ctx context.Context, authority MachineAuthority, machineID, unionID string) (string, RegistrationRejection) {
	if authority == nil {
		return "", RegistrationUnavailable
	}
	record, found, err := authority.LookupMachineRecord(ctx, machineID)
	if err != nil {
		return "", RegistrationUnavailable
	}
	if !found || (record.Status != "" && record.Status != machineStatusActive) {
		return "", RegistrationNotActive
	}
	if record.UnionID != unionID {
		return "", RegistrationOwnerMismatch
	}
	return record.OwnerName, ""
}

type Server struct {
	Registry       *Registry
	Tokens         MachineTokenVerifier
	Routes         RouteStore
	Persistence    MachinePersistence
	TeamSync       TeamSyncSender
	ForwardRawWS   RawWebSocketForwarder
	SelfPodAddress string
	RouteTTL       time.Duration
	StaleAfter     time.Duration
	OnMachineDrop  func(string)
	// Machines is the registration authority (current MachineDoc owner and
	// lifecycle). Nil fails closed: every register is refused with 1013.
	Machines MachineAuthority
	// Fanout throttles the eventually consistent register/heartbeat side
	// effects (MongoDB writes, route refresh, team-sync) per machine. Nil
	// uses the process-wide throttle, like the module-level memo in Node.
	Fanout       *FanoutThrottle
	FanoutWindow time.Duration
	// RegisterTimeout closes a control socket with 4002 if no register
	// arrives in time. Zero means defaultRegisterTimeout.
	RegisterTimeout time.Duration

	upgrader websocket.Upgrader
}

func NewServer(registry *Registry, tokens MachineTokenVerifier) *Server {
	return &Server{
		Registry:     registry,
		Tokens:       tokens,
		RouteTTL:     180 * time.Second,
		StaleAfter:   90 * time.Second,
		FanoutWindow: BackendFanoutThrottle,
		upgrader: websocket.Upgrader{
			ReadBufferSize:    32 << 10,
			WriteBufferSize:   32 << 10,
			EnableCompression: false,
			CheckOrigin:       func(*http.Request) bool { return true },
		},
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/tunnel/control" && r.URL.Path != "/tunnel/data" {
		http.NotFound(w, r)
		return
	}
	if !websocket.IsWebSocketUpgrade(r) {
		http.Error(w, "websocket upgrade required", http.StatusUpgradeRequired)
		return
	}
	claims, ok := s.Tokens.VerifyMachineToken(r.URL.Query().Get("token"))
	if !ok {
		rejectHandshake(w)
		return
	}
	// Unbind revocation: machine tokens are stateless, so an iat cutoff is the
	// server-side invalidation. A rebound machine's newer token passes.
	if s.revoked(r.Context(), claims) {
		rejectHandshake(w)
		return
	}

	if r.URL.Path == "/tunnel/control" {
		s.serveControl(w, r, claims)
		return
	}
	s.serveData(w, r, claims)
}

func (s *Server) serveData(w http.ResponseWriter, r *http.Request, claims *MachineClaims) {
	streamID := r.URL.Query().Get("stream")
	if s.Registry.HasPending(streamID) {
		ws, err := s.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ws.SetReadLimit(controlReadLimit)
		if !s.Registry.AttachDataStream(streamID, claims.MachineID, ws) {
			slog.Info("tunnel data rejected", "machineId", claims.MachineID, "streamId", streamID, "closeCode", 4004, "reason", "no_matching_stream")
			_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4004, "no matching stream"), time.Now().Add(time.Second))
			_ = ws.Close()
		}
		return
	}

	if s.Routes != nil && s.ForwardRawWS != nil {
		owner, err := s.Routes.GetStreamOwner(r.Context(), streamID)
		if err == nil && owner != "" && owner != s.SelfPodAddress {
			if err := s.ForwardRawWS(owner, w, r); err != nil {
				slog.Warn("proxy failure", "proxyPath", "peer_tunnel_data_ws", "streamId", streamID, "owner", owner, "error", err)
			}
			return
		}
		if err != nil {
			slog.Warn("runtime dependency failure", "dependency", "redis", "operation", "get_stream_owner", "machineId", claims.MachineID, "streamId", streamID, "error", err)
		}
	}

	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	slog.Info("tunnel data rejected", "machineId", claims.MachineID, "streamId", streamID, "closeCode", 4004, "reason", "no_matching_stream")
	_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(4004, "no matching stream"), time.Now().Add(time.Second))
	_ = ws.Close()
}

func (s *Server) serveControl(w http.ResponseWriter, r *http.Request, claims *MachineClaims) {
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(controlReadLimit)
	control := NewControlSocket(ws)
	openedAt := time.Now()
	activeControls, accepted := s.Registry.controlOpened(control)
	if !accepted {
		_ = control.Terminate()
		slog.Info("tunnel control rejected during shutdown", "machineId", claims.MachineID, "activeControls", activeControls)
		return
	}
	slog.Info("tunnel control opened", "machineId", claims.MachineID, "activeControls", activeControls)
	var terminalErr error
	var registered atomic.Bool
	var pongAlive atomic.Bool
	pongAlive.Store(true)
	ws.SetPongHandler(func(string) error {
		pongAlive.Store(true)
		return nil
	})

	registerTimeout := s.RegisterTimeout
	if registerTimeout <= 0 {
		registerTimeout = defaultRegisterTimeout
	}
	registerTimer := time.AfterFunc(registerTimeout, func() {
		if !registered.Load() {
			_ = control.Close(4002, "register timeout")
		}
	})
	defer registerTimer.Stop()

	lastMessage := atomic.Int64{}
	lastMessage.Store(time.Now().UnixMilli())
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if !pongAlive.Swap(false) {
					_ = control.Terminate()
					return
				}
				if err := control.Ping(); err != nil {
					_ = control.Terminate()
					return
				}
				if time.Since(time.UnixMilli(lastMessage.Load())) > s.StaleAfter+60*time.Second {
					_ = control.Close(4003, "heartbeat timeout")
					return
				}
			case <-done:
				return
			}
		}
	}()

	defer func() {
		close(done)
		s.cleanupControl(claims.MachineID, control)
		_ = ws.Close()
		activeControls := s.Registry.controlClosed(control)
		slog.Info("tunnel control closed", "machineId", claims.MachineID, "registered", registered.Load(), "closeCode", control.ObservedCloseCode(terminalErr), "activeControls", activeControls, "durationMs", time.Since(openedAt).Milliseconds(), "error", terminalErr)
	}()

	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			terminalErr = err
			return
		}
		// Refreshed before the revocation read so a slow lookup cannot make
		// the heartbeat watchdog fire on a live daemon.
		lastMessage.Store(time.Now().UnixMilli())
		// Like Node: anything that is not a register/heartbeat JSON object is
		// ignored, before and after registration.
		message, ok := ParseDaemonMessage(data)
		if !ok {
			continue
		}
		// Every message re-checks the unbind cutoff first and skips all side
		// effects once revoked: this closes a live tunnel unbound after its
		// handshake within one heartbeat, without knowing which pod holds it.
		if s.revoked(context.Background(), claims) {
			_ = control.Close(4005, "unbound")
			return
		}
		if registered.Load() && !s.Registry.IsCurrent(claims.MachineID, control) {
			_ = control.Close(4001, "replaced by new control connection")
			return
		}
		switch message.Type {
		case "register":
			if registered.Load() {
				// A repeated register is ignored, never re-authorized or re-published.
				continue
			}
			ownerName, rejection := s.authorizeRegistration(claims)
			if rejection != "" {
				unavailable := rejection == RegistrationUnavailable
				slog.Warn("tunnel registration rejected", "machineId", claims.MachineID, "reason", string(rejection))
				if unavailable {
					_ = control.Close(1013, "registry unavailable")
				} else {
					_ = control.Close(4005, "unbound")
				}
				return
			}
			if !s.registerControl(claims, control, message, ownerName, &registered) {
				_ = control.Close(4001, "replaced by new control connection")
				return
			}
			registerTimer.Stop()
		case "heartbeat":
			// Before the authoritative register completes a heartbeat must have
			// no registry, persistence or route side effect on this pod.
			if !registered.Load() {
				_ = control.Close(4002, "register required")
				return
			}
			if !s.handleHeartbeat(claims, control, message) {
				_ = control.Close(4001, "replaced by new control connection")
				return
			}
		}
	}
}

func (s *Server) authorizeRegistration(claims *MachineClaims) (string, RegistrationRejection) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return AuthorizeMachineRegistration(ctx, s.Machines, claims.MachineID, claims.UnionID)
}

// rejectHandshake answers a refused tunnel upgrade with Node's raw status line.
func rejectHandshake(w http.ResponseWriter) {
	if hijacker, ok := w.(http.Hijacker); ok {
		if conn, buffered, err := hijacker.Hijack(); err == nil {
			_, _ = buffered.WriteString("HTTP/1.1 401 Unauthorized\r\n\r\n")
			_ = buffered.Flush()
			_ = conn.Close()
			return
		}
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// shouldRunFanout gates the backend fan-out (persistence, route refresh,
// team-sync). The in-memory registry update and the registered reply are
// never throttled.
func (s *Server) shouldRunFanout(machineID string) bool {
	window := s.FanoutWindow
	if window <= 0 {
		window = BackendFanoutThrottle
	}
	throttle := s.Fanout
	if throttle == nil {
		throttle = defaultFanoutThrottle
	}
	return throttle.ShouldRun(machineID, window, time.Now())
}

func (s *Server) cleanupControl(machineID string, control *ControlSocket) {
	if !s.Registry.Remove(machineID, control) {
		return
	}
	if s.OnMachineDrop != nil {
		s.OnMachineDrop(machineID)
	}
	if s.Routes == nil || s.SelfPodAddress == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Routes.DeleteMachineRoute(ctx, machineID, s.SelfPodAddress); err != nil {
		slog.Warn("runtime dependency failure", "dependency", "redis", "operation", "delete_machine_route", "machineId", machineID, "error", err)
	}
}

// handleDaemonMessage applies one parsed message for an already authorized
// control socket (tests drive it directly). A repeated register is ignored.
// It returns false when the control lost its registry slot.
func (s *Server) handleDaemonMessage(claims *MachineClaims, control *ControlSocket, message *DaemonMessage, registered *atomic.Bool) bool {
	if message.Type == "register" {
		if registered.Load() {
			return s.Registry.IsCurrent(claims.MachineID, control)
		}
		return s.registerControl(claims, control, message, claims.OwnerName, registered)
	}
	return s.handleHeartbeat(claims, control, message)
}

// registerControl publishes an authorized control socket. authorityOwnerName
// is the owner display name of the current MachineDoc; it wins over the
// historical name signed into the token.
func (s *Server) registerControl(claims *MachineClaims, control *ControlSocket, message *DaemonMessage, authorityOwnerName string, registered *atomic.Bool) bool {
	now := time.Now()
	name := sanitizeName(message.Name)
	if name == "" {
		name = firstNonEmpty(authorityOwnerName, claims.OwnerName, prefix(claims.MachineID, 8))
	}
	version := message.BotmuxVersion
	if version == "" {
		version = "unknown"
	}
	port := message.DashboardPort
	if port == 0 {
		port = 7891
	}
	machine := &MachineConn{
		MachineID:      claims.MachineID,
		UnionID:        claims.UnionID,
		OwnerName:      firstNonEmpty(authorityOwnerName, claims.OwnerName),
		Name:           name,
		BotmuxVersion:  version,
		DashboardToken: message.DashboardToken,
		DashboardPort:  port,
		DirectHosts:    cleanStrings(message.DirectHosts),
		Memberships:    nonNilMemberships(message.Memberships),
		Bots:           nonNilBots(message.Bots),
		TeamSyncRev:    cloneString(message.TeamSyncRev),
		LastSeen:       now,
		Control:        control,
	}
	if !s.Registry.Register(machine, !registered.Load()) {
		return false
	}
	registered.Store(true)
	_ = control.Send(registeredMessage{Type: "registered", MachineID: claims.MachineID})
	// Storm protection: only sub-window register/heartbeat floods are merged;
	// the registry upsert and the registered reply above stay real time.
	if !s.shouldRunFanout(claims.MachineID) {
		return true
	}
	if s.Persistence != nil {
		snapshot := machine.Snapshot()
		go s.persistRegister(control, snapshot)
	}
	if s.Routes != nil && s.SelfPodAddress != "" {
		go s.refreshRoute(claims.MachineID, control)
	}
	if message.TeamSyncRev != nil && s.TeamSync != nil {
		go s.sendTeamSync(claims.MachineID, control, *message.TeamSyncRev)
	}
	return true
}

func (s *Server) handleHeartbeat(claims *MachineClaims, control *ControlSocket, message *DaemonMessage) bool {
	now := time.Now()
	if !s.Registry.Heartbeat(claims.MachineID, control, message) {
		return false
	}
	if !s.shouldRunFanout(claims.MachineID) {
		return true
	}
	if s.Persistence != nil {
		copy := *message
		go s.persistHeartbeat(claims.MachineID, control, copy, now)
	}
	if s.Routes != nil && s.SelfPodAddress != "" {
		go s.refreshRoute(claims.MachineID, control)
	}
	if message.TeamSyncRev != nil && s.TeamSync != nil {
		go s.sendTeamSync(claims.MachineID, control, *message.TeamSyncRev)
	}
	return true
}

func (s *Server) revoked(ctx context.Context, claims *MachineClaims) bool {
	if s.Routes == nil {
		return false
	}
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	revoked, err := s.Routes.IsMachineTokenRevoked(checkCtx, claims.MachineID, claims.IssuedAt)
	if err != nil {
		slog.Warn("runtime dependency failure", "dependency", "redis", "operation", "token_revocation_lookup", "failureMode", "fail_open", "machineId", claims.MachineID, "error", err)
		return false
	}
	return revoked
}

func (s *Server) persistRegister(control *ControlSocket, machine MachineConn) {
	if !s.Registry.IsCurrent(machine.MachineID, control) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Persistence.PersistRegister(ctx, machine); err != nil {
		slog.Warn("runtime dependency failure", "dependency", "mongodb", "operation", "persist_machine_register", "machineId", machine.MachineID, "error", err)
	}
}

func (s *Server) persistHeartbeat(machineID string, control *ControlSocket, message DaemonMessage, now time.Time) {
	if !s.Registry.IsCurrent(machineID, control) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Persistence.PersistHeartbeat(ctx, machineID, message, now); err != nil {
		slog.Warn("runtime dependency failure", "dependency", "mongodb", "operation", "persist_machine_heartbeat", "machineId", machineID, "error", err)
	}
}

func (s *Server) refreshRoute(machineID string, control *ControlSocket) {
	if !s.Registry.IsCurrent(machineID, control) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Routes.SetMachineRoute(ctx, machineID, s.SelfPodAddress, s.RouteTTL); err != nil {
		slog.Warn("runtime dependency failure", "dependency", "redis", "operation", "set_machine_route", "machineId", machineID, "error", err)
	}
}

func (s *Server) sendTeamSync(machineID string, control *ControlSocket, revision string) {
	if !s.Registry.IsCurrent(machineID, control) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.TeamSync.MaybeSendTeamSync(ctx, machineID, revision); err != nil {
		slog.Warn("send team sync", "machineId", machineID, "error", err)
	}
}

var controlCharacters = regexp.MustCompile(`[\x00-\x1f\x7f]`)

func sanitizeName(value string) string {
	value = strings.TrimSpace(controlCharacters.ReplaceAllString(value, ""))
	runes := []rune(value)
	if len(runes) > 64 {
		runes = runes[:64]
	}
	return string(runes)
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

// nonNilMemberships keeps Node's `Array.isArray(x) ? x : []` for register:
// an absent list is persisted as an empty array, not omitted.
func nonNilMemberships(values []MembershipInfo) []MembershipInfo {
	return append([]MembershipInfo{}, values...)
}

func nonNilBots(values []BotInfo) []BotInfo {
	return append([]BotInfo{}, values...)
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func prefix(value string, length int) string {
	if len(value) <= length {
		return value
	}
	return value[:length]
}
