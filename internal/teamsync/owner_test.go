package teamsync

import (
	"testing"

	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Ports test/team-sync-owner.test.ts. Revision goldens come from the
// TypeScript teamSyncRev.

func ownerTeam(owner string) []Team {
	return []Team{{
		TeamID: "team-1", TeamName: "Team", GroupChatIDs: []string{"oc_hall"},
		Bots:           []Bot{{AppID: "cli_bot", UnionID: "on_bot", Name: "Bot", OwnerUnionID: owner}},
		MemberUnionIDs: []string{"on_owner_a", "on_owner_b"},
	}}
}

func TestRevisionChangesWhenBotOwnerChanges(t *testing.T) {
	a, b := Revision(ownerTeam("on_owner_a")), Revision(ownerTeam("on_owner_b"))
	if a == b {
		t.Fatalf("owner change kept revision %q", a)
	}
	if a != "1d245b0449316330" || b != "ba444f4c0698342d" {
		t.Fatalf("revisions = %q, %q; want TS goldens", a, b)
	}
}

func TestRevisionDistinguishesLegacyMissingOwner(t *testing.T) {
	legacy := Revision(ownerTeam(""))
	if legacy == Revision(ownerTeam("on_owner_a")) {
		t.Fatal("missing owner and attributed owner share a revision")
	}
	if legacy != "2f20b9fb70ecca5f" {
		t.Fatalf("legacy revision = %q, want TS golden", legacy)
	}
}

func TestRevisionWithOwnerGolden(t *testing.T) {
	teams := []Team{
		{
			TeamID: "bbbbbbbb", TeamName: "Beta",
			GroupChatIDs:   []string{"oc_2", "oc_1"},
			Bots:           []Bot{{AppID: "cli_z", Name: "Zed", OwnerUnionID: "on_owner"}, {AppID: "cli_a", UnionID: "on_a"}},
			MemberUnionIDs: []string{"on_2", "on_1"},
		},
		{TeamID: "aaaaaaaa", TeamName: "Alpha"},
	}
	if got := Revision(teams); got != "0aae0839facfff18" {
		t.Fatalf("revision = %q, want TS golden", got)
	}
}

func TestResolveBotInfoLiveOwnerComesFromMachineDoc(t *testing.T) {
	live := tunnel.MachineConn{
		MachineID: "machine-1",
		UnionID:   "on_stale_connection_owner",
		Bots:      []tunnel.BotInfo{{AppID: "cli_bot", UnionID: "on_bot", Name: "Bot"}},
	}
	doc := &store.MachineDoc{
		ID:      "machine-1",
		UnionID: "on_current_machine_owner",
		Bots:    []store.BotInfo{{AppID: "cli_bot", UnionID: "on_persisted_bot", Name: "Persisted Bot"}},
	}
	got := ResolveBotInfo(store.TeamBotRef{MachineID: "machine-1", AppID: "cli_bot"}, live, true, doc)
	want := Bot{AppID: "cli_bot", UnionID: "on_bot", Name: "Bot", OwnerUnionID: "on_current_machine_owner"}
	if got != want {
		t.Fatalf("live bot info = %+v, want %+v", got, want)
	}
}

func TestResolveBotInfoOfflineFallsBackToMachineDoc(t *testing.T) {
	doc := &store.MachineDoc{
		ID: "machine-1", UnionID: "on_owner",
		Bots: []store.BotInfo{{AppID: "cli_bot", UnionID: "on_persisted_bot", Name: "Persisted Bot"}},
	}
	ref := store.TeamBotRef{MachineID: "machine-1", AppID: "cli_bot"}
	got := ResolveBotInfo(ref, tunnel.MachineConn{}, false, doc)
	want := Bot{AppID: "cli_bot", UnionID: "on_persisted_bot", Name: "Persisted Bot", OwnerUnionID: "on_owner"}
	if got != want {
		t.Fatalf("offline bot info = %+v, want %+v", got, want)
	}
	// Live machine without that bot also falls back to the document.
	live := tunnel.MachineConn{MachineID: "machine-1", Bots: []tunnel.BotInfo{{AppID: "cli_other", Name: "Other"}}}
	if got := ResolveBotInfo(ref, live, true, doc); got != want {
		t.Fatalf("live-without-bot info = %+v, want %+v", got, want)
	}
	// A live bot whose union is still unknown keeps it empty (no doc mixing).
	live = tunnel.MachineConn{MachineID: "machine-1", Bots: []tunnel.BotInfo{{AppID: "cli_bot", Name: "Live"}}}
	if got := ResolveBotInfo(ref, live, true, doc); got != (Bot{AppID: "cli_bot", Name: "Live", OwnerUnionID: "on_owner"}) {
		t.Fatalf("live unlearned bot info = %+v", got)
	}
	// Missing/unreadable document: no owner attribution at all.
	if got := ResolveBotInfo(ref, tunnel.MachineConn{}, false, nil); got != (Bot{AppID: "cli_bot"}) {
		t.Fatalf("missing doc bot info = %+v", got)
	}
}
