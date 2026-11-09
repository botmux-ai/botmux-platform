package tunnel

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type routeCleanupRecorder struct{ deletes atomic.Int32 }

func (*routeCleanupRecorder) SetStreamOwner(context.Context, string, string, time.Duration) error {
	return nil
}
func (*routeCleanupRecorder) IsMachineTokenRevoked(context.Context, string, int64) (bool, error) {
	return false, nil
}
func (*routeCleanupRecorder) SetMachineRoute(context.Context, string, string, time.Duration) error {
	return nil
}
func (r *routeCleanupRecorder) DeleteMachineRoute(context.Context, string, string) error {
	r.deletes.Add(1)
	return nil
}
func (*routeCleanupRecorder) GetStreamOwner(context.Context, string) (string, error) {
	return "", nil
}

func TestServerStaleControlCleanupDoesNotDeleteReplacementRoute(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(time.Minute, "pod-a", nil)
	oldControl := &ControlSocket{}
	newControl := &ControlSocket{}
	registry.machines["machine-1"] = &MachineConn{MachineID: "machine-1", Control: newControl}
	routes := &routeCleanupRecorder{}
	var serverDrops atomic.Int32
	server := &Server{
		Registry: registry, Routes: routes, SelfPodAddress: "pod-a",
		OnMachineDrop: func(string) { serverDrops.Add(1) },
	}

	server.cleanupControl("machine-1", oldControl)
	if routes.deletes.Load() != 0 || serverDrops.Load() != 0 {
		t.Fatalf("stale cleanup: route deletes=%d, drop hooks=%d", routes.deletes.Load(), serverDrops.Load())
	}
	if got, ok := registry.Get("machine-1"); !ok || got.Control != newControl {
		t.Fatalf("replacement lost after stale cleanup: %+v, ok=%v", got, ok)
	}

	server.cleanupControl("machine-1", newControl)
	if routes.deletes.Load() != 1 || serverDrops.Load() != 1 {
		t.Fatalf("authoritative cleanup: route deletes=%d, drop hooks=%d", routes.deletes.Load(), serverDrops.Load())
	}
}

func TestServerStaleControlMessagesHaveNoSideEffects(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(time.Minute, "pod-a", nil)
	oldControl := &ControlSocket{}
	newControl := &ControlSocket{}
	registeredAt := time.Now().Add(-time.Minute)
	registry.machines["machine-1"] = &MachineConn{
		MachineID: "machine-1", Name: "replacement", BotmuxVersion: "current",
		LastSeen: registeredAt, Control: newControl,
	}
	routes := &protocolRouteRecorder{}
	persistence := &protocolPersistenceRecorder{}
	teamSync := &protocolTeamSyncRecorder{}
	server := &Server{
		Registry: registry, Routes: routes, Persistence: persistence, TeamSync: teamSync,
		SelfPodAddress: "pod-a", RouteTTL: time.Minute,
	}
	claims := &MachineClaims{MachineID: "machine-1", UnionID: "user-1", OwnerName: "Owner"}
	var registered atomic.Bool
	registered.Store(true)
	revision := "stale-revision"

	if server.handleDaemonMessage(claims, oldControl, &DaemonMessage{
		Type: "heartbeat", BotmuxVersion: "stale", TeamSyncRev: &revision,
	}, &registered) {
		t.Fatal("stale heartbeat was accepted")
	}
	if server.handleDaemonMessage(claims, oldControl, &DaemonMessage{
		Type: "register", Name: "retaken", BotmuxVersion: "stale", TeamSyncRev: &revision,
	}, &registered) {
		t.Fatal("stale repeated register was accepted")
	}

	// These calls model asynchronous work queued before the replacement won.
	// Each worker must recheck authority when it starts.
	server.persistRegister(oldControl, MachineConn{MachineID: "machine-1"})
	server.persistHeartbeat("machine-1", oldControl, DaemonMessage{Type: "heartbeat"}, time.Now())
	server.refreshRoute("machine-1", oldControl)
	server.sendTeamSync("machine-1", oldControl, revision)

	got, ok := registry.Get("machine-1")
	if !ok || got.Control != newControl || got.Name != "replacement" || got.BotmuxVersion != "current" || !got.LastSeen.Equal(registeredAt) {
		t.Fatalf("replacement mutated by stale control: %+v, ok=%v", got, ok)
	}
	if persistence.registers.Load() != 0 || persistence.heartbeats.Load() != 0 {
		t.Fatalf("stale persistence effects: register=%d heartbeat=%d", persistence.registers.Load(), persistence.heartbeats.Load())
	}
	if routes.setMachine.Load() != 0 || teamSync.calls.Load() != 0 {
		t.Fatalf("stale external effects: route=%d teamSync=%d", routes.setMachine.Load(), teamSync.calls.Load())
	}
}

var _ RouteStore = (*routeCleanupRecorder)(nil)
