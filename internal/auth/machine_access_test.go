package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Ports of test/auth-machine-access.test.ts plus LookupMachineAccess.

const (
	accessOwner    = "ou_owner"
	accessCo       = "ou_comanager"
	accessStranger = "ou_stranger"
)

func testCoManager(edit func(*store.MachineCoManager)) store.MachineCoManager {
	cm := store.MachineCoManager{UnionID: accessCo, Name: "协管者", Scopes: ComanagerDefaultScopes(), GrantedAt: 1_700_000_000_000, GrantedBy: accessOwner}
	if edit != nil {
		edit(&cm)
	}
	return cm
}

func testMachine(status string, coManagers ...store.MachineCoManager) *store.MachineDoc {
	return &store.MachineDoc{
		ID: "m1", UnionID: accessOwner, OwnerName: "Owner", Name: "workstation", BotmuxVersion: "3.18.14", DashboardPort: 7777,
		LastSeen: time.Now().UnixMilli(), Status: status, CoManagers: coManagers,
	}
}

func withScopes(scopes ...string) func(*store.MachineCoManager) {
	return func(cm *store.MachineCoManager) { cm.Scopes = scopes }
}

func TestOwnerAlwaysHasFullAccess(t *testing.T) {
	t.Parallel()
	a := ResolveMachineAccess(testMachine("ACTIVE"), accessOwner)
	if !a.OK || a.Role != MachineRoleOwner || !AccessCanControlTerminal(a) || !AccessHasScope(a, "dashboard:manage") || a.Entry != nil {
		t.Fatalf("owner access = %+v", a)
	}
	// An owner wrongly listed as co-manager is not downgraded by that entry.
	weird := ResolveMachineAccess(testMachine("ACTIVE", testCoManager(func(cm *store.MachineCoManager) {
		cm.UnionID = accessOwner
		cm.Scopes = []string{"machines:read"}
	})), accessOwner)
	if weird.Role != MachineRoleOwner || !AccessCanControlTerminal(weird) {
		t.Fatalf("owner downgraded: %+v", weird)
	}
}

func TestCoManagerGetsListedScopesWithoutManage(t *testing.T) {
	t.Parallel()
	a := ResolveMachineAccess(testMachine("ACTIVE", testCoManager(nil)), accessCo)
	if !a.OK || a.Role != MachineRoleCoManager || !AccessCanControlTerminal(a) || AccessHasScope(a, "dashboard:manage") || a.Entry == nil || a.Entry.UnionID != accessCo {
		t.Fatalf("co-manager access = %+v", a)
	}
}

func TestMachineAccessDeniesOthersAndInvalidInput(t *testing.T) {
	t.Parallel()
	cases := map[string]MachineAccess{
		"stranger":         ResolveMachineAccess(testMachine("ACTIVE", testCoManager(nil)), accessStranger),
		"no co-managers":   ResolveMachineAccess(testMachine("ACTIVE"), accessCo),
		"empty list":       ResolveMachineAccess(testMachine("ACTIVE", []store.MachineCoManager{}...), accessCo),
		"retired owner":    ResolveMachineAccess(testMachine("RETIRED", testCoManager(nil)), accessOwner),
		"retired co":       ResolveMachineAccess(testMachine("RETIRED", testCoManager(nil)), accessCo),
		"nil doc":          ResolveMachineAccess(nil, accessOwner),
		"empty union":      ResolveMachineAccess(testMachine("ACTIVE"), ""),
		"empty scopes":     ResolveMachineAccess(testMachine("ACTIVE", testCoManager(withScopes())), accessCo),
		"only ungrantable": ResolveMachineAccess(testMachine("ACTIVE", testCoManager(withScopes("self:refresh"))), accessCo),
	}
	for name, a := range cases {
		if a.OK {
			t.Errorf("%s: access granted: %+v", name, a)
		}
	}
	if !ResolveMachineAccess(testMachine("ACTIVE"), accessOwner).OK {
		t.Fatal("owner denied on a machine without co-managers")
	}
}

func TestMissingStatusIsLegacyActive(t *testing.T) {
	t.Parallel()
	legacy := testMachine("", testCoManager(nil))
	if !ResolveMachineAccess(legacy, accessOwner).OK || !ResolveMachineAccess(legacy, accessCo).OK {
		t.Fatal("pre-migration document without status must count as ACTIVE")
	}
}

func TestUngrantableScopesAreFiltered(t *testing.T) {
	t.Parallel()
	a := ResolveMachineAccess(testMachine("ACTIVE", testCoManager(withScopes("machines:read", "self:refresh"))), accessCo)
	if !a.OK || AccessHasScope(a, "self:refresh") || !AccessHasScope(a, "machines:read") {
		t.Fatalf("access = %+v", a)
	}
	manage := ResolveMachineAccess(testMachine("ACTIVE", testCoManager(withScopes(append(ComanagerDefaultScopes(), "dashboard:manage")...))), accessCo)
	if !AccessHasScope(manage, "dashboard:manage") || !AccessCanControlTerminal(manage) || !AccessCanUseDaemonAPI(manage) {
		t.Fatalf("manage access = %+v", manage)
	}
	readOnly := ResolveMachineAccess(testMachine("ACTIVE", testCoManager(withScopes("machines:read"))), accessCo)
	if !readOnly.OK || AccessCanControlTerminal(readOnly) || AccessCanUseDaemonAPI(readOnly) {
		t.Fatalf("read-only access = %+v", readOnly)
	}
}

func TestEachCoManagerUsesOwnEntry(t *testing.T) {
	t.Parallel()
	second := "ou_second"
	doc := testMachine("ACTIVE",
		testCoManager(withScopes("machines:read")),
		testCoManager(func(cm *store.MachineCoManager) { cm.UnionID = second; cm.Name = "第二人" }),
	)
	if AccessCanControlTerminal(ResolveMachineAccess(doc, accessCo)) || !AccessCanControlTerminal(ResolveMachineAccess(doc, second)) {
		t.Fatal("co-managers did not get their own entries")
	}
}

func TestResolveMachineAccessReturnsDetachedSlices(t *testing.T) {
	t.Parallel()
	doc := testMachine("ACTIVE", testCoManager(nil))
	a := ResolveMachineAccess(doc, accessCo)
	a.Scopes[0] = "mutated"
	a.Entry.Scopes[0] = "mutated"
	if doc.CoManagers[0].Scopes[0] != "machines:read" || ComanagerDefaultScopes()[0] != "machines:read" {
		t.Fatal("access result aliases the document or package scopes")
	}
}

type fakeMachineLookup struct {
	doc store.MachineDoc
	err error
}

func (f fakeMachineLookup) LookupMachine(context.Context, string, store.AuthorityCacheOptions) (store.MachineDoc, error) {
	return f.doc, f.err
}

func TestLookupMachineAccessSeparatesUnavailableFromDenied(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	opts := store.AuthorityCacheOptions{PositiveTTL: store.DesktopDashboardAuthCacheTTL}
	if _, _, err := LookupMachineAccess(ctx, fakeMachineLookup{err: store.ErrUnavailable}, "m1", accessOwner, opts); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("unavailable = %v", err)
	}
	if _, _, err := LookupMachineAccess(ctx, fakeMachineLookup{err: errors.New("socket closed")}, "m1", accessOwner, opts); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("raw store error = %v", err)
	}
	if _, _, err := LookupMachineAccess(ctx, fakeMachineLookup{err: store.ErrNotFound}, "m1", accessOwner, opts); !errors.Is(err, ErrMachineAccessDenied) {
		t.Fatalf("missing = %v", err)
	}
	if _, _, err := LookupMachineAccess(ctx, fakeMachineLookup{doc: *testMachine("ACTIVE")}, "m1", accessStranger, opts); !errors.Is(err, ErrMachineAccessDenied) {
		t.Fatalf("stranger = %v", err)
	}
	if _, _, err := LookupMachineAccess(ctx, nil, "m1", accessOwner, opts); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("nil lookup = %v", err)
	}
	access, doc, err := LookupMachineAccess(ctx, fakeMachineLookup{doc: *testMachine("ACTIVE", testCoManager(nil))}, "m1", accessCo, opts)
	if err != nil || access.Role != MachineRoleCoManager || doc.ID != "m1" {
		t.Fatalf("co-manager lookup = %+v %+v %v", access, doc, err)
	}
}

func TestLookupMachineAccessAgainstRepository(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo := store.NewDocumentRepository(store.NewMemoryDatabaseProvider())
	if _, err := repo.BindMachineCAS(ctx, "deadbeef00000001", accessOwner, "Owner"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LookupMachineAccess(ctx, repo, "deadbeef00000001", accessOwner, store.AuthorityCacheOptions{}); err != nil {
		t.Fatalf("owner = %v", err)
	}
	if err := repo.RetireMachine(ctx, "deadbeef00000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LookupMachineAccess(ctx, repo, "deadbeef00000001", accessOwner, store.AuthorityCacheOptions{}); !errors.Is(err, ErrMachineAccessDenied) {
		t.Fatalf("retired = %v", err)
	}
}
