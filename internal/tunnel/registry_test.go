package tunnel

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistrySnapshotAndTrackedDataConnection(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(time.Minute, "", nil)
	control := &ControlSocket{}
	if _, ok := registry.controlOpened(control); !ok {
		t.Fatal("control rejected by open registry")
	}
	registry.mu.Lock()
	registry.machines["machine-1"] = &MachineConn{MachineID: "machine-1"}
	registry.pending["stream-pending"] = &pendingStream{}
	registry.mu.Unlock()

	client, server := net.Pipe()
	defer server.Close()
	tracked := registry.trackDataConn(client, "machine-1", "stream-active")

	snapshot := registry.Snapshot()
	if snapshot.ActiveControls != 1 || snapshot.RegisteredMachines != 1 || snapshot.ActiveDataStreams != 1 || snapshot.PendingStreams != 1 {
		t.Fatalf("snapshot with live connections = %+v", snapshot)
	}

	if err := tracked.Close(); err != nil {
		t.Fatalf("close tracked data connection: %v", err)
	}
	_ = tracked.Close()
	registry.controlClosed(control)
	snapshot = registry.Snapshot()
	if snapshot.ActiveControls != 0 || snapshot.ActiveDataStreams != 0 {
		t.Fatalf("snapshot after close = %+v", snapshot)
	}
}

func TestCloseControlsConcurrently(t *testing.T) {
	t.Parallel()
	controls := []*ControlSocket{{}, {}, {}, {}}
	connections := make([]shutdownConnection, 0, len(controls))
	started := make(chan struct{}, len(controls))
	release := make(chan struct{})
	for range controls {
		connections = append(connections, shutdownConnection{close: func() {
			started <- struct{}{}
			<-release
		}})
	}
	done := make(chan struct{})
	go func() {
		closeConnectionsConcurrently(
			connections,
			time.Second,
			time.Second,
		)
		close(done)
	}()

	for range controls {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("control shutdown was serialized")
		}
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("concurrent control shutdown did not complete")
	}
}

func TestCloseControlsConcurrentlyAbortsBlockedCloses(t *testing.T) {
	t.Parallel()
	connections := make([]shutdownConnection, 0, 4)
	for range 4 {
		release := make(chan struct{})
		connections = append(connections, shutdownConnection{
			close: func() { <-release },
			abort: func() { close(release) },
		})
	}
	started := time.Now()
	completed := closeConnectionsConcurrently(
		connections,
		20*time.Millisecond,
		100*time.Millisecond,
	)
	if !completed {
		t.Fatal("blocked controls did not drain after abort")
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("control shutdown exceeded its budget: %s", elapsed)
	}
}

func TestCloseControlsConcurrentlyHasHardDeadline(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	started := time.Now()
	completed := closeConnectionsConcurrently(
		[]shutdownConnection{{close: func() { <-release }, abort: func() {}}},
		15*time.Millisecond,
		15*time.Millisecond,
	)
	if completed {
		close(release)
		t.Fatal("blocked control reported completion")
	}
	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		close(release)
		t.Fatalf("control shutdown was not bounded: %s", elapsed)
	}
	close(release)
}

func TestRegistryCloseClosesActiveDataStreams(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(time.Minute, "", nil)
	local, remote := net.Pipe()
	defer remote.Close()
	tracked := registry.trackDataConn(local, "machine-1", "stream-1")

	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := remote.Read(make([]byte, 1)); err == nil {
		t.Fatal("active data stream remained open after registry shutdown")
	}
	if snapshot := registry.Snapshot(); snapshot.ActiveDataStreams != 0 {
		t.Fatalf("active data streams after shutdown = %d", snapshot.ActiveDataStreams)
	}
	_ = tracked.Close()
}

func TestAttachDataStreamAndRegistryCloseHaveAtomicOwnership(t *testing.T) {
	t.Parallel()
	for range 100 {
		registry := NewRegistry(time.Minute, "", nil)
		result := make(chan streamResult, 1)
		registry.pending["stream-1"] = &pendingStream{
			machineID: "machine-1",
			result:    result,
			timer:     time.NewTimer(time.Hour),
		}
		local, remote := net.Pipe()
		gate := make(chan struct{})
		attached := make(chan bool, 1)
		closed := make(chan struct{})
		go func() {
			<-gate
			attached <- registry.attachDataConn("stream-1", "machine-1", local)
		}()
		go func() {
			<-gate
			_ = registry.Close()
			close(closed)
		}()
		close(gate)
		wasAttached := <-attached
		<-closed
		got := <-result
		if wasAttached {
			if got.err != nil || got.conn == nil {
				t.Fatalf("attached stream result = conn:%v err:%v", got.conn, got.err)
			}
		} else {
			if got.err != net.ErrClosed || got.conn != nil {
				t.Fatalf("shutdown-won stream result = conn:%v err:%v", got.conn, got.err)
			}
			_ = local.Close()
		}
		if snapshot := registry.Snapshot(); snapshot.ActiveDataStreams != 0 || snapshot.PendingStreams != 0 {
			t.Fatalf("post-race snapshot = %+v", snapshot)
		}
		_ = remote.Close()
	}
}

func TestRegistryRejectsAuthorityFromReplacedControl(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(time.Minute, "", nil)
	oldControl := &ControlSocket{}
	newControl := &ControlSocket{}
	if !registry.Register(&MachineConn{MachineID: "machine-1", Name: "old", Control: oldControl}, true) {
		t.Fatal("initial register rejected")
	}
	if !registry.Register(&MachineConn{MachineID: "machine-1", Name: "new", Control: newControl}, true) {
		t.Fatal("replacement register rejected")
	}
	message := &DaemonMessage{Type: "heartbeat", BotmuxVersion: "stale"}
	if registry.Heartbeat("machine-1", oldControl, message) {
		t.Fatal("stale control heartbeat was accepted")
	}
	if registry.Register(&MachineConn{MachineID: "machine-1", Name: "retaken", Control: oldControl}, false) {
		t.Fatal("stale control retook authority with repeated register")
	}
	got, ok := registry.Get("machine-1")
	if !ok || got.Control != newControl || got.Name != "new" || got.BotmuxVersion == "stale" {
		t.Fatalf("replacement state mutated by stale control: %+v, ok=%v", got, ok)
	}
	if !registry.Heartbeat("machine-1", newControl, &DaemonMessage{Type: "heartbeat", BotmuxVersion: "current"}) {
		t.Fatal("current control heartbeat rejected")
	}
	got, _ = registry.Get("machine-1")
	if got.BotmuxVersion != "current" {
		t.Fatalf("current heartbeat version = %q", got.BotmuxVersion)
	}
}

func TestRegistryCloseRejectsPendingStreamsAndIsIdempotent(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(time.Minute, "", nil)
	results := make([]chan streamResult, 2)
	for index := range results {
		results[index] = make(chan streamResult, 1)
		registry.pending[string(rune('a'+index))] = &pendingStream{
			result: results[index],
			timer:  time.NewTimer(time.Hour),
		}
	}
	if err := registry.Close(); err != nil {
		t.Fatalf("close registry: %v", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatalf("second close registry: %v", err)
	}
	for index, result := range results {
		got := <-result
		if got.err != net.ErrClosed {
			t.Fatalf("pending result %d = %v", index, got.err)
		}
	}
	if snapshot := registry.Snapshot(); snapshot.RegisteredMachines != 0 || snapshot.PendingStreams != 0 {
		t.Fatalf("snapshot after close = %+v", snapshot)
	}
}

func TestStaleControlRemovePreservesReplacementState(t *testing.T) {
	t.Parallel()
	registry := NewRegistry(time.Minute, "", nil)
	oldControl := &ControlSocket{}
	newControl := &ControlSocket{}
	registry.machines["machine-1"] = &MachineConn{
		MachineID: "machine-1",
		Name:      "replacement",
		Control:   newControl,
	}
	result := make(chan streamResult, 1)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	registry.pending["new-stream"] = &pendingStream{
		machineID: "machine-1",
		result:    result,
		timer:     timer,
	}
	var drops atomic.Int32
	registry.SetDropHook(func(machineID string) {
		if machineID != "machine-1" {
			t.Errorf("drop hook machine = %q", machineID)
		}
		drops.Add(1)
	})

	// This models the old control's defer running after the replacement has
	// registered and opened a new pending dashboard stream.
	if registry.Remove("machine-1", oldControl) {
		t.Fatal("stale control reported authoritative removal")
	}
	got, ok := registry.Get("machine-1")
	if !ok || got.Control != newControl || got.Name != "replacement" {
		t.Fatalf("replacement removed: %+v, ok=%v", got, ok)
	}
	if !registry.HasPending("new-stream") {
		t.Fatal("replacement pending stream was removed by stale control")
	}
	if drops.Load() != 0 {
		t.Fatalf("stale removal triggered %d drop hooks", drops.Load())
	}
	select {
	case value := <-result:
		t.Fatalf("replacement pending stream rejected: %v", value.err)
	default:
	}

	// The authoritative control's removal owns all machine cleanup exactly
	// once: machine, pending streams and dashboard drop hook.
	if !registry.Remove("machine-1", newControl) {
		t.Fatal("current control did not report authoritative removal")
	}
	if _, ok := registry.Get("machine-1"); ok {
		t.Fatal("authoritative control was not removed")
	}
	if registry.HasPending("new-stream") {
		t.Fatal("authoritative removal retained pending stream")
	}
	select {
	case value := <-result:
		if value.err == nil || !strings.Contains(value.err.Error(), "machine disconnected") {
			t.Fatalf("pending result = %v", value.err)
		}
	default:
		t.Fatal("authoritative removal did not reject pending stream")
	}
	if drops.Load() != 1 {
		t.Fatalf("authoritative removal triggered %d drop hooks", drops.Load())
	}
	if registry.Remove("machine-1", newControl) {
		t.Fatal("duplicate removal reported success")
	}
	if drops.Load() != 1 {
		t.Fatalf("duplicate removal triggered %d drop hooks", drops.Load())
	}
}
