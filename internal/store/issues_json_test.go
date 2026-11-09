package store

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func mustBSON(t *testing.T, doc bson.D) []byte {
	t.Helper()
	raw, err := bson.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A document's physical order (fields appended by later $set operations, in
// Mongo's lexicographic append order) must survive into the API JSON, as the
// TS service returns the raw driver result.
func TestIssueDocJSONFollowsStoredFieldOrder(t *testing.T) {
	raw := mustBSON(t, bson.D{
		{Key: "_id", Value: "iss_1"}, {Key: "teamId", Value: "t1"}, {Key: "title", Value: "T"},
		{Key: "body", Value: ""}, {Key: "status", Value: "needs_attention"},
		{Key: "createdBy", Value: "u"}, {Key: "createdByName", Value: "U"},
		{Key: "createdAt", Value: float64(1760000000000)}, {Key: "updatedAt", Value: float64(1760000000001)},
		{Key: "rev", Value: int32(1)}, {Key: "stateRev", Value: int32(4)},
		{Key: "claimEpochCounter", Value: int32(1)}, {Key: "eventSeq", Value: int32(4)},
		{Key: "claim", Value: bson.D{
			{Key: "claimId", Value: "c1"}, {Key: "claimEpoch", Value: int32(1)}, {Key: "unionId", Value: "u"},
			{Key: "name", Value: "U"}, {Key: "machineId", Value: "m1"},
			{Key: "agent", Value: bson.D{{Key: "appId", Value: "cli_x"}, {Key: "name", Value: "Bot"}}},
			{Key: "claimedAt", Value: float64(1760000000000)}, {Key: "leaseExpiresAt", Value: float64(1760000300000)},
			{Key: "bound", Value: true}, {Key: "lastSourceSeq", Value: int32(0)},
			{Key: "localTaskLabel", Value: "Task"}, {Key: "localTaskRef", Value: "r::1"},
		}},
		{Key: "attentionReason", Value: "claim_activate_timeout"},
		{Key: "attentionSince", Value: float64(1760000400000)},
	})
	var doc IssueDoc
	if err := bson.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Claim == nil || doc.Claim.LocalTaskRef != "r::1" || doc.AttentionSince != 1760000400000 || doc.StateRev != 4 {
		t.Fatalf("struct view: %+v", doc)
	}
	want := `{"_id":"iss_1","teamId":"t1","title":"T","body":"","status":"needs_attention","createdBy":"u",` +
		`"createdByName":"U","createdAt":1760000000000,"updatedAt":1760000000001,"rev":1,"stateRev":4,` +
		`"claimEpochCounter":1,"eventSeq":4,"claim":{"claimId":"c1","claimEpoch":1,"unionId":"u","name":"U",` +
		`"machineId":"m1","agent":{"appId":"cli_x","name":"Bot"},"claimedAt":1760000000000,` +
		`"leaseExpiresAt":1760000300000,"bound":true,"lastSourceSeq":0,"localTaskLabel":"Task",` +
		`"localTaskRef":"r::1"},"attentionReason":"claim_activate_timeout","attentionSince":1760000400000}`
	if got := marshalNoEscape(t, doc); got != want {
		t.Fatalf("issue JSON:\n got %s\nwant %s", got, want)
	}
	wantClaim := want[strings.Index(want, `"claim":`)+len(`"claim":`) : strings.Index(want, `,"attentionReason"`)]
	if got := marshalNoEscape(t, doc.Claim); got != wantClaim {
		t.Fatalf("claim JSON:\n got %s\nwant %s", got, wantClaim)
	}

	// Slice elements (cursor.All) take the same path.
	var list struct {
		Docs []IssueDoc `bson:"docs"`
	}
	if err := bson.Unmarshal(mustBSON(t, bson.D{{Key: "docs", Value: bson.A{bson.Raw(raw)}}}), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Docs) != 1 || marshalNoEscape(t, list.Docs[0]) != want {
		t.Fatalf("slice element JSON: %+v", list.Docs)
	}
}

func TestIssueEventDocJSONFollowsStoredFieldOrder(t *testing.T) {
	raw := mustBSON(t, bson.D{
		{Key: "_id", Value: "iev_1"}, {Key: "issueId", Value: "iss_1"}, {Key: "teamId", Value: "t1"},
		{Key: "seq", Value: int32(2)}, {Key: "at", Value: float64(1760000000000)},
		{Key: "kind", Value: "lease_expired"}, {Key: "toStatus", Value: "open"},
		{Key: "actorUnionId", Value: "system"}, {Key: "detail", Value: "x"},
	})
	var ev IssueEventDoc
	if err := bson.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	want := `{"_id":"iev_1","issueId":"iss_1","teamId":"t1","seq":2,"at":1760000000000,"kind":"lease_expired",` +
		`"toStatus":"open","actorUnionId":"system","detail":"x"}`
	if got := marshalNoEscape(t, ev); got != want || ev.Seq != 2 {
		t.Fatalf("event JSON:\n got %s\nwant %s", got, want)
	}
}

// TS persists some client values verbatim; such a document must still be
// readable, and the JSON must show what is stored.
func TestIssueDocDecodeToleratesForeignFieldTypes(t *testing.T) {
	raw := mustBSON(t, bson.D{
		{Key: "_id", Value: "iss_1"}, {Key: "teamId", Value: "t1"}, {Key: "title", Value: bson.A{"a"}},
		{Key: "status", Value: "open"}, {Key: "labels", Value: bson.A{int32(1), "x"}},
		{Key: "suggestedAssigneeUnionId", Value: nil},
		{Key: "rev", Value: int32(3)},
		{Key: "claim", Value: bson.D{{Key: "claimId", Value: int32(7)}, {Key: "machineId", Value: "m1"}}},
	})
	var doc IssueDoc
	if err := bson.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("lenient decode failed: %v", err)
	}
	if doc.ID != "iss_1" || doc.Rev != 3 || doc.Title != "" || doc.Labels != nil || doc.Claim == nil || doc.Claim.MachineID != "m1" {
		t.Fatalf("decoded: %+v claim=%+v", doc, doc.Claim)
	}
	want := `{"_id":"iss_1","teamId":"t1","title":["a"],"status":"open","labels":[1,"x"],` +
		`"suggestedAssigneeUnionId":null,"rev":3,"claim":{"claimId":7,"machineId":"m1"}}`
	if got := marshalNoEscape(t, doc); got != want {
		t.Fatalf("JSON:\n got %s\nwant %s", got, want)
	}
}

func TestJSJSONFromBSONMatchesJSONStringify(t *testing.T) {
	ms := time.Date(2025, 1, 2, 3, 4, 5, 6_000_000, time.UTC).UnixMilli()
	oid, _ := primitive.ObjectIDFromHex("0123456789abcdef01234567")
	raw := mustBSON(t, bson.D{
		{Key: "b", Value: int32(1)},
		{Key: "10", Value: "ten"},
		{Key: "a", Value: float64(1.5)},
		{Key: "2", Value: "two"},
		{Key: "b", Value: "dup"}, // last value, first position
		{Key: "u", Value: primitive.Undefined{}},
		{Key: "nums", Value: bson.A{float64(1e21), float64(1e-7), math.Copysign(0, -1), math.NaN(), math.Inf(1), int64(1 << 40), int64(1<<62 + 1), primitive.Undefined{}}},
		{Key: "s", Value: "q\"\\\b\f\n\r\t\x01 <&>é"},
		{Key: "d", Value: primitive.DateTime(ms)},
		{Key: "o", Value: oid},
		{Key: "n", Value: nil},
		{Key: "t", Value: true},
		{Key: "007", Value: "not an index"},
	})
	got, err := jsJSONFromBSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"2":"two","10":"ten","b":"dup","a":1.5,"nums":[1e+21,1e-7,0,null,null,1099511627776,"4611686018427387905",null],` +
		`"s":"q\"\\\b\f\n\r\t\u0001` + " " + `<&>é","d":"2025-01-02T03:04:05.006Z","o":"0123456789abcdef01234567",` +
		`"n":null,"t":true,"007":"not an index"}`
	if string(got) != want {
		t.Fatalf("JSON:\n got %s\nwant %s", got, want)
	}
	if !json.Valid(got) {
		t.Fatalf("invalid JSON: %s", got)
	}
	// writeJSON embeds Marshaler output without re-escaping when HTML
	// escaping is off.
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		Issue IssueEventDoc `json:"issue"`
	}{IssueEventDoc{raw: raw}}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSuffix(out.String(), "\n") != `{"issue":`+want+`}` {
		t.Fatalf("embedded: %s", out.String())
	}
}

func TestJSArrayIndex(t *testing.T) {
	for key, want := range map[string]bool{
		"0": true, "1": true, "4294967294": true, "4294967295": false, "01": false, "": false, "-1": false, "1.0": false, "a": false,
	} {
		if _, ok := JSArrayIndex(key); ok != want {
			t.Errorf("JSArrayIndex(%q) = %v, want %v", key, ok, want)
		}
	}
}

func TestIssueClaimPersistsTruthyAgentVerbatim(t *testing.T) {
	f := newIssueFixture(t)
	issue := f.seedOpen()
	agent := bson.D{{Key: "appId", Value: "cli_x"}, {Key: "n", Value: int32(2)}}
	claimed, err := f.store.Claim(f.ctx, issue.ID, ClaimIssueInput{
		ClaimID: "c1", UnionID: "u-a", Name: "A", MachineID: "m1", Agent: agent, RepoLabel: "",
		ExpectedStateRev: float64(issue.StateRev),
	})
	if err != nil {
		t.Fatal(err)
	}
	// MemoryDatabase keeps no field order, so compare the decoded JSON.
	encoded := marshalNoEscape(t, claimed.Claim)
	var view map[string]any
	if err := json.Unmarshal([]byte(encoded), &view); err != nil {
		t.Fatal(err)
	}
	if got, _ := view["agent"].(map[string]any); got["appId"] != "cli_x" || got["n"] != float64(2) || view["repoLabel"] != nil {
		t.Fatalf("claim JSON: %s", encoded)
	}
	other := f.seedOpen()
	claimed, err = f.store.Claim(f.ctx, other.ID, ClaimIssueInput{
		ClaimID: "c2", UnionID: "u-a", Name: "A", MachineID: "m1", Agent: int32(0), RepoLabel: "platform",
		ExpectedStateRev: float64(other.StateRev),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded = marshalNoEscape(t, claimed.Claim)
	if strings.Contains(encoded, "agent") || !strings.Contains(encoded, `"repoLabel":"platform"`) {
		t.Fatalf("falsy agent must be omitted: %s", encoded)
	}
}
