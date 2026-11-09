package teamsync

import (
	"encoding/json"
	"reflect"
	"testing"
)

// The daemon-bound message keeps the TS literal key order, and a cached
// empty team still carries [] (not null) for every array.
func TestMessageWireShape(t *testing.T) {
	cached := cloneTeam(Team{TeamID: "aaaaaaaa", TeamName: "A", GroupChatIDs: []string{}, Bots: []Bot{}, MemberUnionIDs: []string{}})
	owned := Team{TeamID: "bbbbbbbb", TeamName: "B", GroupChatIDs: []string{"oc_1"}, Bots: []Bot{{AppID: "cli_a", UnionID: "on_a", Name: "A", OwnerUnionID: "on_o"}}, MemberUnionIDs: []string{"on_o"}}
	raw, err := json.Marshal(Message{Type: "team-sync", Rev: "r1", Teams: []Team{cached, cloneTeam(owned)}})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"type":"team-sync","rev":"r1","teams":[{"teamId":"aaaaaaaa","teamName":"A","groupChatIds":[],"bots":[],"memberUnionIds":[]},{"teamId":"bbbbbbbb","teamName":"B","groupChatIds":["oc_1"],"bots":[{"appId":"cli_a","unionId":"on_a","name":"A","ownerUnionId":"on_o"}],"memberUnionIds":["on_o"]}]}`
	if string(raw) != want {
		t.Fatalf("message:\n got %s\nwant %s", raw, want)
	}
}

func TestTypeScriptCanonicalGoldenAndRevision(t *testing.T) {
	teams := []Team{
		{
			TeamID: "bbbbbbbb", TeamName: "Beta",
			GroupChatIDs:   []string{"oc_2", "oc_1"},
			Bots:           []Bot{{AppID: "cli_z", Name: "Zed"}, {AppID: "cli_a", UnionID: "on_a"}},
			MemberUnionIDs: []string{"on_2", "on_1"},
		},
		{TeamID: "aaaaaaaa", TeamName: "Alpha"},
	}
	original := deepCopy(teams)

	const wantJSON = `[{"teamId":"aaaaaaaa","teamName":"Alpha","groupChatIds":[],"bots":[],"memberUnionIds":[]},{"teamId":"bbbbbbbb","teamName":"Beta","groupChatIds":["oc_1","oc_2"],"bots":[{"appId":"cli_a","unionId":"on_a","name":"","ownerUnionId":""},{"appId":"cli_z","unionId":"","name":"Zed","ownerUnionId":""}],"memberUnionIds":["on_1","on_2"]}]`
	if got := string(CanonicalJSON(teams)); got != wantJSON {
		t.Fatalf("canonical JSON mismatch\n got: %s\nwant: %s", got, wantJSON)
	}
	// Golden from the TypeScript teamSyncRev (dist/server/team-sync.js).
	if got, want := Revision(teams), "5c84a16612407b79"; got != want {
		t.Fatalf("revision = %q, want %q", got, want)
	}
	if !reflect.DeepEqual(teams, original) {
		t.Fatalf("CanonicalJSON mutated input\n got: %#v\nwant: %#v", teams, original)
	}
}

func TestEmptyRevisionGolden(t *testing.T) {
	if got := string(CanonicalJSON(nil)); got != "[]" {
		t.Fatalf("empty canonical JSON = %q", got)
	}
	if got, want := Revision(nil), "97d170e1550eee4a"; got != want {
		t.Fatalf("empty revision = %q, want %q", got, want)
	}
}

func TestCanonicalJSONUsesJSONStringifyEscaping(t *testing.T) {
	teams := []Team{{TeamID: "aaaaaaaa", TeamName: "<>&\u2028\u2029"}}
	const want = "[{\"teamId\":\"aaaaaaaa\",\"teamName\":\"<>&\u2028\u2029\",\"groupChatIds\":[],\"bots\":[],\"memberUnionIds\":[]}]"
	if got := string(CanonicalJSON(teams)); got != want {
		t.Fatalf("Unicode canonical JSON\n got: %q\nwant: %q", got, want)
	}
}

func deepCopy(teams []Team) []Team {
	out := make([]Team, len(teams))
	for i, team := range teams {
		out[i] = team
		out[i].GroupChatIDs = append([]string(nil), team.GroupChatIDs...)
		out[i].Bots = append([]Bot(nil), team.Bots...)
		out[i].MemberUnionIDs = append([]string(nil), team.MemberUnionIDs...)
	}
	return out
}
