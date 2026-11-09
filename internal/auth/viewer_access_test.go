package auth

import (
	"reflect"
	"testing"

	"github.com/botmux-ai/botmux-platform/internal/store"
)

func TestViewerResolvesToFixedReadOnlyScopes(t *testing.T) {
	doc := &store.MachineDoc{ID: "m1", UnionID: "u-owner", CoManagers: []store.MachineCoManager{
		// Stored scopes on a viewer entry are ignored, even when they would be
		// grantable to a co-manager.
		{UnionID: "u-view", Role: store.CoManagerRoleViewer, Scopes: ComanagerGrantableScopes()},
		{UnionID: "u-view-empty", Role: store.CoManagerRoleViewer},
	}}
	for _, id := range []string{"u-view", "u-view-empty"} {
		access := ResolveMachineAccess(doc, id)
		if !access.OK || access.Role != MachineRoleViewer || !IsViewer(access) {
			t.Fatalf("%s access = %+v", id, access)
		}
		if !reflect.DeepEqual(access.Scopes, []string{store.DeviceScopeMachinesRead}) {
			t.Fatalf("%s scopes = %v", id, access.Scopes)
		}
		if AccessCanControlTerminal(access) || AccessCanUseDaemonAPI(access) || AccessHasScope(access, store.DeviceScopeDashboardManage) {
			t.Fatalf("%s viewer holds a write capability: %+v", id, access)
		}
	}
}

func TestLegacyAndExplicitCoManagerRoleUnchanged(t *testing.T) {
	doc := &store.MachineDoc{ID: "m1", UnionID: "u-owner", CoManagers: []store.MachineCoManager{
		{UnionID: "u-legacy", Scopes: ComanagerDefaultScopes()},
		{UnionID: "u-explicit", Role: store.CoManagerRoleManager, Scopes: ComanagerGrantableScopes()},
	}}
	legacy := ResolveMachineAccess(doc, "u-legacy")
	if !legacy.OK || legacy.Role != MachineRoleCoManager || !reflect.DeepEqual(legacy.Scopes, ComanagerDefaultScopes()) || IsViewer(legacy) {
		t.Fatalf("legacy co-manager = %+v", legacy)
	}
	explicit := ResolveMachineAccess(doc, "u-explicit")
	if !explicit.OK || explicit.Role != MachineRoleCoManager || !reflect.DeepEqual(explicit.Scopes, ComanagerGrantableScopes()) {
		t.Fatalf("explicit co-manager = %+v", explicit)
	}
	owner := ResolveMachineAccess(doc, "u-owner")
	if !owner.OK || owner.Role != MachineRoleOwner || IsViewer(owner) {
		t.Fatalf("owner = %+v", owner)
	}
}

func TestUnknownGrantRoleIsDenied(t *testing.T) {
	doc := &store.MachineDoc{ID: "m1", UnionID: "u-owner", CoManagers: []store.MachineCoManager{
		{UnionID: "u-x", Role: "admin", Scopes: ComanagerGrantableScopes()},
		{UnionID: "u-y", Role: "Viewer", Scopes: ComanagerDefaultScopes()},
	}}
	for _, id := range []string{"u-x", "u-y"} {
		if access := ResolveMachineAccess(doc, id); access.OK {
			t.Fatalf("%s unknown role allowed: %+v", id, access)
		}
	}
}

func TestViewerDashboardAllowlist(t *testing.T) {
	allowed := []string{
		"/", "/favicon.ico", "/favicon.png", "/apple-touch-icon.png", "/workbench.webmanifest",
		"/workbench", "/workbench/dock", "/assets/index-abc.js", "/events", "/api/sessions",
		"/api/workbench/h5-context", "/api/workbench/capabilities",
		"/api/sessions/0b5c6f1e-1111-2222-3333-444455556666/view-link",
		"/api/sessions/0b5c6f1e-1111-2222-3333-444455556666/control",
	}
	for _, path := range allowed {
		for _, method := range []string{"GET", "HEAD"} {
			if !ViewerDashboardRequestAllowed(method, path) {
				t.Fatalf("%s %s refused", method, path)
			}
		}
	}

	refused := []string{
		// configuration
		"/api/settings", "/api/schedules", "/api/groups", "/api/bots", "/api/bots/cli_x/env",
		"/api/bots/cli_x/startup-commands", "/api/bots/cli_x/sandbox", "/api/plugins", "/api/skills",
		"/api/cli-options", "/api/connectors", "/api/webhook-secrets", "/api/owner-profile",
		// credentials / host takeover
		"/api/sessions/s1/write-link", "/api/sessions/s1/spawn-command", "/api/debug-terminal",
		"/host-terminal/x", "/api/terminal", "/api/pty",
		// sessions beyond the board
		"/api/sessions/s1", "/api/sessions/s1/history", "/api/sessions/s1/control/takeover",
		"/api/sessions/s1/preview", "/api/sessions/s1/preview-interaction",
		// daemon internals, workflows, ingress
		"/__cli/current", "/__daemon/x", "/api/workflow", "/api/workflows/x", "/api/v3/runs",
		"/api/internal/x", "/api/update/run", "/webhook/x", "/s/s1",
		// shape tricks: an encoded slash cannot move a route into the id slot,
		// and near-miss spellings are simply not listed
		"/api/sessions/x%2F..%2Fsettings/view-link", "/api/sessions//view-link",
		"/api/sessions/", "/API/sessions", "/api/sessions/s1/view-link/", "/eventsx", "/assets",
	}
	for _, path := range refused {
		if ViewerDashboardRequestAllowed("GET", path) {
			t.Fatalf("GET %s allowed", path)
		}
	}
	// Every non-read method is refused, even on allowlisted paths.
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE", "get", ""} {
		for _, path := range allowed {
			if ViewerDashboardRequestAllowed(method, path) {
				t.Fatalf("%s %s allowed", method, path)
			}
		}
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if ViewerTerminalRequestAllowed(method) {
			t.Fatalf("terminal %s allowed", method)
		}
	}
	if !ViewerTerminalRequestAllowed("GET") || !ViewerTerminalRequestAllowed("HEAD") {
		t.Fatal("terminal reads refused")
	}
}

func TestBotmuxVersionSupportsViewer(t *testing.T) {
	for version, want := range map[string]bool{
		"3.16.0": true, "v3.16.0": true, "3.16.1": true, "3.57.1": true, "3.58.0-canary.2": true, "4.0.0": true, " 3.20.0 ": true,
		"3.16.0-canary.1": false, "3.15.9": false, "3.15.0": false, "2.99.99": false,
		"0.0.0": false, "": false, "unknown": false, "test": false, "3.16": false, "3.16.0.1": false,
		"99999999.0.0": false,
	} {
		if got := BotmuxVersionSupportsViewer(version); got != want {
			t.Fatalf("BotmuxVersionSupportsViewer(%q) = %v, want %v", version, got, want)
		}
	}
}
