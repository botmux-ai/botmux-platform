package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/store"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type rowBot struct {
	AppID string `bson:"appId"`
	Name  string `bson:"name,omitempty"`
}

type rowClaim struct {
	ClaimID        string `bson:"claimId"`
	Bound          bool   `bson:"bound"`
	LeaseExpiresAt int64  `bson:"leaseExpiresAt,truncate"`
}

// row covers the document shapes the repositories use: strings with
// omitempty, numbers of several BSON types, string arrays, arrays of
// subdocuments and an optional subdocument.
type row struct {
	ID     string    `bson:"_id"`
	Owner  string    `bson:"owner"`
	Status string    `bson:"status,omitempty"`
	Seq    int64     `bson:"seq,truncate"`
	Score  float64   `bson:"score"`
	Tags   []string  `bson:"tags,omitempty"`
	Bots   []rowBot  `bson:"bots,omitempty"`
	Claim  *rowClaim `bson:"claim,omitempty"`
	Hall   string    `bson:"hall,omitempty"`
}

var seedRows = []row{
	{ID: "a", Owner: "u1", Status: "ACTIVE", Seq: 3, Score: 1.5, Tags: []string{"x", "y"},
		Bots: []rowBot{{AppID: "cli_1", Name: "One"}}, Claim: &rowClaim{ClaimID: "c1", LeaseExpiresAt: 100}},
	{ID: "b", Owner: "u2", Status: "RETIRED", Seq: 1, Score: 2.5,
		Bots: []rowBot{{AppID: "cli_2"}, {AppID: "cli_3", Name: "Three"}}},
	{ID: "c", Owner: "u1", Seq: 2, Score: 0.5, Tags: []string{"y"},
		Claim: &rowClaim{ClaimID: "c3", Bound: true, LeaseExpiresAt: 300}, Hall: "chat-c"},
}

// seedCollection inserts rows a, b, c (structs) and d (a Document with an
// int32 seq and an explicit null hall).
func seedCollection(t *testing.T, db store.DocumentDatabase, name string) store.DocumentCollection {
	t.Helper()
	ctx := testContext(t)
	c := db.Collection(name)
	for _, r := range seedRows {
		must(t, c.InsertOne(ctx, r), "insert "+r.ID)
	}
	must(t, c.InsertOne(ctx, store.Document{"_id": "d", "owner": "u3", "status": "ACTIVE", "seq": int32(4), "score": 2.5, "hall": nil}), "insert d")
	return c
}

func findIDs(t *testing.T, c store.DocumentCollection, filter store.Document, opts store.FindOptions) []string {
	t.Helper()
	var rows []row
	must(t, c.FindManyOptions(testContext(t), filter, opts, &rows), "find "+describe(filter))
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids
}

func rawDoc(t *testing.T, c store.DocumentCollection, id string) bson.Raw {
	t.Helper()
	var raw bson.Raw
	must(t, c.FindOne(testContext(t), store.Document{"_id": id}, &raw), "raw find "+id)
	return raw
}

func wantType(t *testing.T, raw bson.Raw, key string, want bsontype.Type) bson.RawValue {
	t.Helper()
	value, err := raw.LookupErr(key)
	if err != nil {
		t.Fatalf("%s missing in %s: %v", key, raw, err)
	}
	if value.Type != want {
		t.Fatalf("%s has BSON type %s, want %s (doc %s)", key, value.Type, want, raw)
	}
	return value
}

func wantMissing(t *testing.T, raw bson.Raw, key string) {
	t.Helper()
	if _, err := raw.LookupErr(key); err == nil {
		t.Fatalf("%s must be absent in %s", key, raw)
	}
}

// RunCollection exercises every store.DocumentCollection method directly.
func RunCollection(t *testing.T, newDB NewDatabase, opts ...Option) {
	cfg := newConfig(opts)
	t.Run("InsertFindAndErrors", func(t *testing.T) { testInsertFind(t, newDB(t)) })
	t.Run("Filters", func(t *testing.T) { testFilters(t, newDB(t)) })
	t.Run("SortAndLimit", func(t *testing.T) { testSortLimit(t, newDB(t)) })
	t.Run("DecodeTargets", func(t *testing.T) { testDecodeTargets(t, newDB(t)) })
	t.Run("NumericTypesAndDates", func(t *testing.T) { testNumericTypes(t, newDB(t)) })
	t.Run("ArrayOperators", func(t *testing.T) { testArrayOperators(t, newDB(t)) })
	t.Run("SetUnsetAndResults", func(t *testing.T) { testSetUnset(t, newDB(t)) })
	t.Run("Upsert", func(t *testing.T) { testUpsert(t, newDB(t)) })
	t.Run("FindOneAndUpdate", func(t *testing.T) { testFindOneAndUpdate(t, newDB(t)) })
	t.Run("Delete", func(t *testing.T) { testDelete(t, newDB(t)) })
	t.Run("Indexes", func(t *testing.T) { testIndexes(t, newDB(t)) })
	t.Run("CustomBSONTypes", func(t *testing.T) { testCustomTypes(t, newDB(t), cfg) })
	t.Run("CanceledContext", func(t *testing.T) { testCanceledContext(t, newDB(t)) })
}

func testInsertFind(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	c := seedCollection(t, db, "rows")

	var got row
	must(t, c.FindOne(ctx, store.Document{"_id": "a"}, &got), "find a")
	wantEqual(t, got, seedRows[0], "decoded row a")

	var missing row
	wantErr(t, c.FindOne(ctx, store.Document{"_id": "nope"}, &missing), store.ErrNotFound, "find missing")
	wantErr(t, c.InsertOne(ctx, row{ID: "a", Owner: "dup"}), store.ErrConflict, "duplicate _id insert")
	must(t, c.FindOne(ctx, store.Document{"_id": "a"}, &got), "find a after dup")
	if got.Owner != "u1" {
		t.Fatalf("duplicate insert overwrote a: %+v", got)
	}

	// A document without _id gets a generated ObjectID.
	must(t, c.InsertOne(ctx, store.Document{"owner": "generated"}), "insert without _id")
	var generated bson.M
	must(t, c.FindOne(ctx, store.Document{"owner": "generated"}, &generated), "find generated")
	if _, ok := generated["_id"].(primitive.ObjectID); !ok {
		t.Fatalf("generated _id = %T %v", generated["_id"], generated["_id"])
	}

	// Nested Documents and []Document are converted at every depth.
	must(t, c.InsertOne(ctx, store.Document{
		"_id": "nested", "sub": store.Document{"k": store.Document{"deep": "v"}},
		"list": []store.Document{{"x": int32(1)}, {"x": int32(2), "y": store.Document{"z": "w"}}},
	}), "insert nested")
	for _, filter := range []store.Document{
		{"sub.k.deep": "v"}, {"list.x": int32(2)}, {"list.y.z": "w"},
		{"sub": store.Document{"k": store.Document{"deep": "v"}}},
	} {
		var doc bson.M
		must(t, c.FindOne(ctx, filter, &doc), "nested filter "+describe(filter))
		if doc["_id"] != "nested" {
			t.Fatalf("nested filter %v matched %v", filter, doc["_id"])
		}
	}
}

func testFilters(t *testing.T, db store.DocumentDatabase) {
	c := seedCollection(t, db, "rows")
	cases := []struct {
		name   string
		filter store.Document
		want   []string
	}{
		{"equality", store.Document{"owner": "u1"}, []string{"a", "c"}},
		{"ne matches missing", store.Document{"status": store.Document{"$ne": "RETIRED"}}, []string{"a", "c", "d"}},
		{"in", store.Document{"owner": store.Document{"$in": []string{"u1", "u3"}}}, []string{"a", "c", "d"}},
		{"in empty", store.Document{"_id": store.Document{"$in": []string{}}}, []string{}},
		{"nin", store.Document{"owner": store.Document{"$nin": []string{"u1"}}}, []string{"b", "d"}},
		{"array contains scalar", store.Document{"tags": "y"}, []string{"a", "c"}},
		{"exists false", store.Document{"tags": store.Document{"$exists": false}}, []string{"b", "d"}},
		{"exists true", store.Document{"status": store.Document{"$exists": true}}, []string{"a", "b", "d"}},
		{"nil matches missing and null", store.Document{"hall": nil}, []string{"a", "b", "d"}},
		{"dotted array path", store.Document{"bots.appId": "cli_3"}, []string{"b"}},
		{"elemMatch", store.Document{"bots": store.Document{"$elemMatch": store.Document{"appId": "cli_3", "name": "Three"}}}, []string{"b"}},
		{"elemMatch needs one element", store.Document{"bots": store.Document{"$elemMatch": store.Document{"appId": "cli_2", "name": "Three"}}}, []string{}},
		{"dotted subdocument bool", store.Document{"claim.bound": false}, []string{"a"}},
		{"subdocument lte across int64/double", store.Document{"claim.leaseExpiresAt": store.Document{"$lte": float64(100)}}, []string{"a"}},
		{"range across types", store.Document{"seq": store.Document{"$gt": int32(1), "$lt": 4.0}}, []string{"a", "c"}},
		{"gte go int", store.Document{"seq": store.Document{"$gte": 3}}, []string{"a", "d"}},
		{"double equality", store.Document{"score": 2.5}, []string{"b", "d"}},
		{"numeric equality across types", store.Document{"seq": float64(4)}, []string{"d"}},
		{"int64 equals stored int64", store.Document{"seq": int64(3)}, []string{"a"}},
		{"or", store.Document{"$or": []store.Document{{"owner": "u2"}, {"hall": "chat-c"}}}, []string{"b", "c"}},
		{"and", store.Document{"$and": []store.Document{{"owner": "u1"}, {"seq": store.Document{"$gt": 2}}}}, []string{"a"}},
		{"nor", store.Document{"$nor": []store.Document{{"owner": "u1"}, {"owner": "u2"}}}, []string{"d"}},
		{"size", store.Document{"tags": store.Document{"$size": 2}}, []string{"a"}},
		{"not", store.Document{"seq": store.Document{"$not": store.Document{"$gt": 2}}}, []string{"b", "c"}},
		{"cas shape", store.Document{"_id": "c", "owner": "u1", "status": store.Document{"$ne": "RETIRED"}}, []string{"c"}},
		{"cas shape mismatch", store.Document{"_id": "b", "owner": "u2", "status": store.Document{"$ne": "RETIRED"}}, []string{}},
		{"empty filter", store.Document{}, []string{"a", "b", "c", "d"}},
		{"nil filter", nil, []string{"a", "b", "c", "d"}},
	}
	for _, tc := range cases {
		got := sortedStrings(findIDs(t, c, tc.filter, store.FindOptions{}))
		wantEqual(t, got, tc.want, tc.name)
	}
}

func testSortLimit(t *testing.T, db store.DocumentDatabase) {
	c := seedCollection(t, db, "rows")
	cases := []struct {
		name string
		opts store.FindOptions
		want []string
	}{
		{"compound desc/asc", store.FindOptions{Sort: []store.IndexKey{{Field: "score", Order: -1}, {Field: "_id", Order: 1}}}, []string{"b", "d", "a", "c"}},
		{"compound with limit", store.FindOptions{Sort: []store.IndexKey{{Field: "score", Order: -1}, {Field: "_id", Order: 1}}, Limit: 2}, []string{"b", "d"}},
		{"mixed numeric types asc", store.FindOptions{Sort: []store.IndexKey{{Field: "seq", Order: 1}}}, []string{"b", "c", "a", "d"}},
		{"mixed numeric types desc", store.FindOptions{Sort: []store.IndexKey{{Field: "seq", Order: -1}}, Limit: 3}, []string{"d", "a", "c"}},
		{"missing sorts first", store.FindOptions{Sort: []store.IndexKey{{Field: "status", Order: 1}, {Field: "_id", Order: 1}}}, []string{"c", "a", "d", "b"}},
		{"nested path", store.FindOptions{Sort: []store.IndexKey{{Field: "claim.leaseExpiresAt", Order: -1}, {Field: "_id", Order: 1}}, Limit: 2}, []string{"c", "a"}},
		{"limit larger than result", store.FindOptions{Sort: []store.IndexKey{{Field: "_id", Order: -1}}, Limit: 10}, []string{"d", "c", "b", "a"}},
	}
	for _, tc := range cases {
		wantEqual(t, findIDs(t, c, store.Document{}, tc.opts), tc.want, tc.name)
	}
	got := findIDs(t, c, store.Document{"owner": "u1"}, store.FindOptions{Sort: []store.IndexKey{{Field: "seq", Order: 1}}, Limit: 1})
	wantEqual(t, got, []string{"c"}, "filter + sort + limit")
}

func testDecodeTargets(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	c := seedCollection(t, db, "rows")
	none := store.Document{"owner": "nobody"}

	// Repositories initialize `out := []T{}` so an empty result renders as
	// JSON [] (not null); that must survive a no-match FindMany.
	empty := []row{}
	must(t, c.FindMany(ctx, none, &empty), "find none into empty slice")
	if empty == nil || len(empty) != 0 {
		t.Fatalf("pre-initialized empty slice became %#v", empty)
	}
	var nilRows []row
	must(t, c.FindMany(ctx, none, &nilRows), "find none into nil slice")
	if len(nilRows) != 0 {
		t.Fatalf("nil slice result = %#v", nilRows)
	}
	sorted := store.FindOptions{Sort: []store.IndexKey{{Field: "_id", Order: 1}}}
	var raws []bson.Raw
	must(t, c.FindManyOptions(ctx, store.Document{"owner": "u1"}, sorted, &raws), "find raw slice")
	if len(raws) != 2 || raws[0].Lookup("_id").StringValue() != "a" || raws[1].Lookup("_id").StringValue() != "c" {
		t.Fatalf("raw slice = %v", raws)
	}
	var maps []bson.M
	must(t, c.FindManyOptions(ctx, store.Document{"_id": "b"}, sorted, &maps), "find map slice")
	if len(maps) != 1 || maps[0]["owner"] != "u2" {
		t.Fatalf("map slice = %v", maps)
	}
	var one bson.M
	must(t, c.FindOne(ctx, store.Document{"_id": "d"}, &one), "find map")
	if v, ok := one["hall"]; !ok || v != nil {
		t.Fatalf("explicit null decoded as %#v (present=%v)", v, ok)
	}
	var d row
	must(t, c.FindOne(ctx, store.Document{"_id": "d"}, &d), "find d struct")
	wantEqual(t, d, row{ID: "d", Owner: "u3", Status: "ACTIVE", Seq: 4, Score: 2.5}, "row d (null string, int32 seq)")
	var projected struct {
		ID    string `bson:"_id"`
		Owner string `bson:"owner"`
	}
	must(t, c.FindOne(ctx, store.Document{"_id": "a"}, &projected), "decode into partial struct")
	if projected.ID != "a" || projected.Owner != "u1" {
		t.Fatalf("partial struct = %+v", projected)
	}
}

func testNumericTypes(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	c := db.Collection("numbers")
	at := time.UnixMilli(1_760_000_000_123).UTC()
	must(t, c.InsertOne(ctx, store.Document{
		"_id": "n", "i32": int32(7), "i64": int64(7), "f": 7.0, "big": int64(1) << 40, "expireAt": at,
	}), "insert numbers")
	raw := rawDoc(t, c, "n")
	wantType(t, raw, "i32", bsontype.Int32)
	wantType(t, raw, "i64", bsontype.Int64)
	wantType(t, raw, "f", bsontype.Double)
	wantType(t, raw, "expireAt", bsontype.DateTime)

	r, err := c.UpdateOne(ctx, store.Document{"_id": "n"}, store.Document{
		"$inc": store.Document{"i32": int32(1), "f": int32(1), "created": int32(1)},
	}, false)
	must(t, err, "$inc")
	wantEqual(t, r, store.UpdateResult{Matched: 1, Modified: 1}, "$inc result")
	raw = rawDoc(t, c, "n")
	if v := wantType(t, raw, "i32", bsontype.Int32); v.Int32() != 8 {
		t.Fatalf("i32 = %v", v)
	}
	if v := wantType(t, raw, "f", bsontype.Double); v.Double() != 8 {
		t.Fatalf("f = %v", v)
	}
	if v := wantType(t, raw, "created", bsontype.Int32); v.Int32() != 1 {
		t.Fatalf("$inc on a missing field = %v", v)
	}

	// $max/$min (desktop session revocation fence) on numbers and dates.
	later := at.Add(time.Hour)
	_, err = c.UpdateOne(ctx, store.Document{"_id": "n"}, store.Document{
		"$max": store.Document{"f": 5.0, "hi": 9.0, "expireAt": later},
		"$min": store.Document{"i64": int64(3)},
	}, false)
	must(t, err, "$max/$min")
	raw = rawDoc(t, c, "n")
	if v := raw.Lookup("f"); v.Double() != 8 {
		t.Fatalf("$max lowered f: %v", v)
	}
	if v := wantType(t, raw, "hi", bsontype.Double); v.Double() != 9 {
		t.Fatalf("$max on a missing field = %v", v)
	}
	if v := raw.Lookup("i64"); v.Int64() != 3 {
		t.Fatalf("$min i64 = %v", v)
	}
	r, err = c.UpdateOne(ctx, store.Document{"_id": "n"}, store.Document{"$max": store.Document{"expireAt": at}}, false)
	must(t, err, "$max earlier date")
	if r.Modified != 0 {
		t.Fatalf("$max with an earlier date modified the document: %+v", r)
	}

	var decoded struct {
		I32      int64     `bson:"i32,truncate"`
		F        int64     `bson:"f,truncate"`
		Big      int64     `bson:"big"`
		ExpireAt time.Time `bson:"expireAt"`
	}
	must(t, c.FindOne(ctx, store.Document{"_id": "n"}, &decoded), "decode numbers")
	if decoded.I32 != 8 || decoded.F != 8 || decoded.Big != 1<<40 || !decoded.ExpireAt.Equal(later) {
		t.Fatalf("decoded numbers = %+v (want expireAt %v)", decoded, later)
	}
	var dates []struct {
		ExpireAt time.Time `bson:"expireAt"`
	}
	must(t, c.FindMany(ctx, store.Document{"expireAt": store.Document{"$gt": at}}, &dates), "date range filter")
	if len(dates) != 1 {
		t.Fatalf("date range matched %d", len(dates))
	}
}

func testArrayOperators(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	c := db.Collection("teams")
	must(t, c.InsertOne(ctx, store.Document{"_id": "t", "members": []string{"u1"}, "createdAt": 1.0}), "insert team")
	update := func(u store.Document) store.UpdateResult {
		t.Helper()
		r, err := c.UpdateOne(ctx, store.Document{"_id": "t"}, u, false)
		must(t, err, "update "+describe(u))
		return r
	}
	type ref struct {
		MachineID string `bson:"machineId"`
		AppID     string `bson:"appId"`
	}
	type invite struct {
		UnionID   string `bson:"unionId"`
		InvitedAt int64  `bson:"invitedAt,truncate"`
	}
	var team struct {
		Members []string `bson:"members"`
		Admins  []string `bson:"admins,omitempty"`
		Bots    []ref    `bson:"bots,omitempty"`
		Invites []invite `bson:"invites,omitempty"`
		Chats   []string `bson:"chats,omitempty"`
	}
	read := func() {
		t.Helper()
		team.Members, team.Admins, team.Bots, team.Invites, team.Chats = nil, nil, nil, nil, nil
		must(t, c.FindOne(ctx, store.Document{"_id": "t"}, &team), "read team")
	}

	wantEqual(t, update(store.Document{"$addToSet": store.Document{"members": "u2"}}), store.UpdateResult{Matched: 1, Modified: 1}, "$addToSet new")
	wantEqual(t, update(store.Document{"$addToSet": store.Document{"members": "u2"}}), store.UpdateResult{Matched: 1}, "$addToSet duplicate")
	update(store.Document{"$addToSet": store.Document{"bots": store.Document{"$each": []ref{{"m1", "a1"}, {"m2", "a2"}}}}})
	update(store.Document{"$addToSet": store.Document{"bots": store.Document{"$each": []ref{{"m1", "a1"}, {"m3", "a3"}}}}})
	update(store.Document{"$addToSet": store.Document{"chats": "c1"}})
	update(store.Document{"$addToSet": store.Document{"chats": "c1"}})
	read()
	wantEqual(t, team.Members, []string{"u1", "u2"}, "members")
	wantEqual(t, team.Bots, []ref{{"m1", "a1"}, {"m2", "a2"}, {"m3", "a3"}}, "bots after $addToSet $each")
	wantEqual(t, team.Chats, []string{"c1"}, "$addToSet creates the array once")

	update(store.Document{"$pull": store.Document{"bots": store.Document{"machineId": "m2", "appId": "a2"}}})
	update(store.Document{"$pull": store.Document{"bots": store.Document{"machineId": store.Document{"$in": []string{"m3"}}}}})
	read()
	wantEqual(t, team.Bots, []ref{{"m1", "a1"}}, "bots after $pull")
	// A partial subdocument condition removes every element it matches.
	update(store.Document{"$push": store.Document{"bots": ref{"m1", "a9"}}})
	update(store.Document{"$pull": store.Document{"bots": store.Document{"machineId": "m1"}}})
	read()
	if len(team.Bots) != 0 {
		t.Fatalf("partial $pull left %v", team.Bots)
	}

	update(store.Document{"$push": store.Document{"invites": store.Document{"unionId": "x", "invitedAt": 10.0}}})
	update(store.Document{"$push": store.Document{"invites": invite{UnionID: "y", InvitedAt: 20}}})
	update(store.Document{"$push": store.Document{"invites": store.Document{"$each": []store.Document{{"unionId": "z", "invitedAt": 30.0}}}}})
	update(store.Document{"$pull": store.Document{"invites": store.Document{"invitedAt": store.Document{"$lt": 15.0}}}})
	update(store.Document{"$pull": store.Document{"invites": store.Document{"unionId": store.Document{"$in": []string{"z"}}}}})
	read()
	wantEqual(t, team.Invites, []invite{{UnionID: "y", InvitedAt: 20}}, "invites after $push/$pull")

	// $pull of several fields at once, one of them missing (RemoveTeamMember).
	update(store.Document{"$pull": store.Document{"members": "u1", "admins": "u1"}})
	read()
	wantEqual(t, team.Members, []string{"u2"}, "members after multi-field $pull")
	if team.Admins != nil {
		t.Fatalf("$pull created admins: %v", team.Admins)
	}
	r := update(store.Document{"$pull": store.Document{"members": "nobody"}})
	wantEqual(t, r, store.UpdateResult{Matched: 1}, "$pull of an absent value")
}

func testSetUnset(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	c := seedCollection(t, db, "rows")

	r, err := c.UpdateOne(ctx, store.Document{"_id": "b"}, store.Document{"$set": store.Document{"claim.bound": true, "claim.claimId": "cb"}}, false)
	must(t, err, "$set dotted path on a missing subdocument")
	wantEqual(t, r, store.UpdateResult{Matched: 1, Modified: 1}, "dotted $set result")
	var b row
	must(t, c.FindOne(ctx, store.Document{"_id": "b"}, &b), "read b")
	wantEqual(t, b.Claim, &rowClaim{ClaimID: "cb", Bound: true}, "created subdocument")

	r, err = c.UpdateOne(ctx, store.Document{"_id": "b"}, store.Document{"$set": store.Document{"claim.bound": true}}, false)
	must(t, err, "no-op $set")
	wantEqual(t, r, store.UpdateResult{Matched: 1}, "no-op $set reports matched but not modified")

	r, err = c.UpdateOne(ctx, store.Document{"_id": "b"}, store.Document{"$unset": store.Document{"claim": "", "neverThere": ""}}, false)
	must(t, err, "$unset")
	wantEqual(t, r, store.UpdateResult{Matched: 1, Modified: 1}, "$unset result")
	wantMissing(t, rawDoc(t, c, "b"), "claim")

	// Mongo rejects $set of a path inside a field the same update $unsets
	// (the 4e52262 regression); the document must stay untouched.
	before := rawDoc(t, c, "a")
	_, err = c.UpdateOne(ctx, store.Document{"_id": "a"}, store.Document{
		"$set": store.Document{"claim.leaseExpiresAt": 5.0}, "$unset": store.Document{"claim": ""},
	}, false)
	if err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("conflicting update paths: err = %v, want a write error", err)
	}
	var claim struct {
		Claim rowClaim `bson:"claim"`
	}
	must(t, c.FindOne(ctx, store.Document{"_id": "a"}, &claim), "read a after conflict")
	if claim.Claim.LeaseExpiresAt != 100 || len(rawDoc(t, c, "a")) != len(before) {
		t.Fatalf("conflicting update changed the document: %v", rawDoc(t, c, "a"))
	}

	r, err = c.UpdateOne(ctx, store.Document{"_id": "nope"}, store.Document{"$set": store.Document{"owner": "x"}}, false)
	must(t, err, "update missing")
	wantEqual(t, r, store.UpdateResult{}, "update without match")

	// $setOnInsert is ignored when the filter matches.
	r, err = c.UpdateOne(ctx, store.Document{"_id": "c"}, store.Document{
		"$set": store.Document{"score": 9.5}, "$setOnInsert": store.Document{"owner": "inserted"},
	}, true)
	must(t, err, "upsert existing")
	wantEqual(t, r, store.UpdateResult{Matched: 1, Modified: 1}, "upsert on an existing document")
	var cRow row
	must(t, c.FindOne(ctx, store.Document{"_id": "c"}, &cRow), "read c")
	if cRow.Owner != "u1" || cRow.Score != 9.5 {
		t.Fatalf("$setOnInsert applied to an existing document: %+v", cRow)
	}

	r, err = c.UpdateMany(ctx, store.Document{"owner": "u1"}, store.Document{"$set": store.Document{"status": "X"}})
	must(t, err, "update many")
	wantEqual(t, r, store.UpdateResult{Matched: 2, Modified: 2}, "update many result")
	r, err = c.UpdateMany(ctx, store.Document{"owner": "u1"}, store.Document{"$set": store.Document{"status": "X"}})
	must(t, err, "update many again")
	wantEqual(t, r, store.UpdateResult{Matched: 2}, "update many no-op")
	r, err = c.UpdateMany(ctx, store.Document{"owner": "nobody"}, store.Document{"$set": store.Document{"status": "X"}})
	must(t, err, "update many none")
	wantEqual(t, r, store.UpdateResult{}, "update many without match")
	r, err = c.UpdateMany(ctx, store.Document{"tags": "y"}, store.Document{"$pull": store.Document{"tags": "y"}, "$inc": store.Document{"seq": int32(10)}})
	must(t, err, "update many $pull/$inc")
	wantEqual(t, r, store.UpdateResult{Matched: 2, Modified: 2}, "update many $pull/$inc result")
	wantEqual(t, sortedStrings(findIDs(t, c, store.Document{"seq": store.Document{"$gte": 12}}, store.FindOptions{})), []string{"a", "c"}, "update many $inc")
}

func testUpsert(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	c := db.Collection("upserts")
	r, err := c.UpdateOne(ctx,
		store.Document{"_id": "u-new", "owner": "o", "status": store.Document{"$ne": "RETIRED"}},
		store.Document{"$set": store.Document{"score": 1.0}, "$setOnInsert": store.Document{"createdAt": 5.0}, "$inc": store.Document{"version": int32(1)}},
		true)
	must(t, err, "upsert insert")
	wantEqual(t, r, store.UpdateResult{Upserted: 1}, "upsert insert result")
	raw := rawDoc(t, c, "u-new")
	if raw.Lookup("owner").StringValue() != "o" {
		t.Fatalf("upsert must seed equality fields from the filter: %v", raw)
	}
	wantMissing(t, raw, "status")
	wantType(t, raw, "createdAt", bsontype.Double)
	if v := wantType(t, raw, "version", bsontype.Int32); v.Int32() != 1 {
		t.Fatalf("version = %v", v)
	}

	r, err = c.UpdateOne(ctx, store.Document{"_id": "u-new"},
		store.Document{"$set": store.Document{"score": 2.0}, "$setOnInsert": store.Document{"createdAt": 99.0}, "$inc": store.Document{"version": int32(1)}},
		true)
	must(t, err, "upsert update")
	wantEqual(t, r, store.UpdateResult{Matched: 1, Modified: 1}, "upsert update result")
	raw = rawDoc(t, c, "u-new")
	if raw.Lookup("createdAt").Double() != 5 || raw.Lookup("version").Int32() != 2 {
		t.Fatalf("second upsert: %v", raw)
	}

	// Upsert of a filter without _id generates one.
	r, err = c.UpdateOne(ctx, store.Document{"owner": "no-id"}, store.Document{"$set": store.Document{"score": 3.0}}, true)
	must(t, err, "upsert without _id")
	wantEqual(t, r, store.UpdateResult{Upserted: 1}, "upsert without _id result")
	var generated bson.M
	must(t, c.FindOne(ctx, store.Document{"owner": "no-id"}, &generated), "find generated upsert")
	if _, ok := generated["_id"].(primitive.ObjectID); !ok {
		t.Fatalf("upserted _id = %T", generated["_id"])
	}

	// A CAS upsert whose _id already exists but whose other conditions fail
	// collides on _id (ConsumeOnce/Revoke fences rely on this).
	_, err = c.UpdateOne(ctx, store.Document{"_id": "u-new", "owner": "other"}, store.Document{"$set": store.Document{"score": 4.0}}, true)
	wantErr(t, err, store.ErrConflict, "upsert colliding with an existing _id")
}

func testFindOneAndUpdate(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	c := seedCollection(t, db, "rows")

	var before row
	must(t, c.FindOneAndUpdate(ctx, store.Document{"_id": "a", "seq": int64(3)},
		store.Document{"$set": store.Document{"owner": "u9"}, "$inc": store.Document{"seq": int32(1)}},
		store.FindOneAndUpdateOptions{}, &before), "find-and-update before")
	if before.Owner != "u1" || before.Seq != 3 {
		t.Fatalf("ReturnAfter=false returned %+v", before)
	}
	var after row
	must(t, c.FindOneAndUpdate(ctx, store.Document{"_id": "a", "seq": 4.0},
		store.Document{"$inc": store.Document{"seq": int32(1)}, "$unset": store.Document{"claim": ""}},
		store.FindOneAndUpdateOptions{ReturnAfter: true}, &after), "find-and-update after")
	if after.Owner != "u9" || after.Seq != 5 || after.Claim != nil {
		t.Fatalf("ReturnAfter=true returned %+v", after)
	}

	// Stale CAS precondition.
	var stale row
	wantErr(t, c.FindOneAndUpdate(ctx, store.Document{"_id": "a", "seq": 4.0}, store.Document{"$inc": store.Document{"seq": int32(1)}},
		store.FindOneAndUpdateOptions{ReturnAfter: true}, &stale), store.ErrNotFound, "stale CAS")
	wantErr(t, c.FindOneAndUpdate(ctx, store.Document{"_id": "zz"}, store.Document{"$set": store.Document{"owner": "x"}},
		store.FindOneAndUpdateOptions{ReturnAfter: true}, &stale), store.ErrNotFound, "missing without upsert")
	var missing row
	wantErr(t, c.FindOne(ctx, store.Document{"_id": "zz"}, &missing), store.ErrNotFound, "no document created without upsert")

	// nil dst discards the document but still reports a match / no match.
	must(t, c.FindOneAndUpdate(ctx, store.Document{"_id": "b"}, store.Document{"$set": store.Document{"hall": "h"}}, store.FindOneAndUpdateOptions{}, nil), "nil dst match")
	wantErr(t, c.FindOneAndUpdate(ctx, store.Document{"_id": "zz"}, store.Document{"$set": store.Document{"hall": "h"}}, store.FindOneAndUpdateOptions{}, nil), store.ErrNotFound, "nil dst no match")

	// Upsert returning the pre-image of an insert is ErrNotFound, but the
	// document is written.
	var pre row
	wantErr(t, c.FindOneAndUpdate(ctx, store.Document{"_id": "up1"}, store.Document{"$set": store.Document{"owner": "x"}},
		store.FindOneAndUpdateOptions{Upsert: true}, &pre), store.ErrNotFound, "upsert insert with ReturnAfter=false")
	var up1 row
	must(t, c.FindOne(ctx, store.Document{"_id": "up1"}, &up1), "upserted up1")
	if up1.Owner != "x" {
		t.Fatalf("up1 = %+v", up1)
	}

	// The credential vault upsert shape: $set + $unset + $inc + $setOnInsert.
	vault := func(updatedAt float64) bson.Raw {
		t.Helper()
		var raw bson.Raw
		must(t, c.FindOneAndUpdate(ctx, store.Document{"_id": "vault"}, store.Document{
			"$set":         store.Document{"owner": "v", "updatedAt": updatedAt},
			"$unset":       store.Document{"statusReason": ""},
			"$inc":         store.Document{"version": int32(1)},
			"$setOnInsert": store.Document{"createdAt": updatedAt, "consentTeams": "all"},
		}, store.FindOneAndUpdateOptions{Upsert: true, ReturnAfter: true}, &raw), "vault upsert")
		return raw
	}
	raw := vault(10)
	if raw.Lookup("version").Int32() != 1 || raw.Lookup("createdAt").Double() != 10 || raw.Lookup("consentTeams").StringValue() != "all" {
		t.Fatalf("vault insert = %v", raw)
	}
	_, err := c.UpdateOne(ctx, store.Document{"_id": "vault"}, store.Document{"$set": store.Document{"statusReason": "r", "consentTeams": []string{"t1"}}}, false)
	must(t, err, "vault mark")
	raw = vault(20)
	if raw.Lookup("version").Int32() != 2 || raw.Lookup("createdAt").Double() != 10 || raw.Lookup("updatedAt").Double() != 20 {
		t.Fatalf("vault update = %v", raw)
	}
	wantType(t, raw, "consentTeams", bsontype.Array)
	wantMissing(t, raw, "statusReason")
}

func testDelete(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	c := seedCollection(t, db, "rows")
	r, err := c.DeleteOne(ctx, store.Document{"owner": "u1"})
	must(t, err, "delete one")
	wantEqual(t, r, store.DeleteResult{Deleted: 1}, "delete one deletes exactly one")
	r, err = c.DeleteOne(ctx, store.Document{"_id": "nope"})
	must(t, err, "delete missing")
	wantEqual(t, r, store.DeleteResult{}, "delete missing result")
	r, err = c.DeleteMany(ctx, store.Document{"owner": store.Document{"$in": []string{"u1", "u2"}}})
	must(t, err, "delete many")
	wantEqual(t, r, store.DeleteResult{Deleted: 2}, "delete many result")
	wantEqual(t, findIDs(t, c, store.Document{}, store.FindOptions{}), []string{"d"}, "remaining after deletes")
	r, err = c.DeleteMany(ctx, store.Document{})
	must(t, err, "delete all")
	wantEqual(t, r, store.DeleteResult{Deleted: 1}, "delete all result")
	r, err = c.DeleteMany(ctx, store.Document{"owner": "u1"})
	must(t, err, "delete many on empty collection")
	wantEqual(t, r, store.DeleteResult{}, "delete many none")
}

func testIndexes(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	c := db.Collection("events")
	zero := int32(0)
	for i := 0; i < 2; i++ {
		must(t, c.CreateIndex(ctx, store.Document{"issueId": 1}), "plain index")
		must(t, c.CreateIndexSpec(ctx, store.IndexSpec{Keys: []store.IndexKey{{Field: "issueId", Order: 1}, {Field: "seq", Order: 1}}, Unique: true}), "unique compound index")
		must(t, c.CreateIndexSpec(ctx, store.IndexSpec{Keys: []store.IndexKey{{Field: "issueId", Order: 1}, {Field: "at", Order: -1}}}), "compound index")
		must(t, c.CreateIndexSpec(ctx, store.IndexSpec{Keys: []store.IndexKey{{Field: "expireAt", Order: 1}}, ExpireAfterSeconds: &zero}), "TTL index")
	}
	far := time.Now().Add(24 * time.Hour).UTC()
	insert := func(id, issue string, seq int32) error {
		return c.InsertOne(ctx, store.Document{"_id": id, "issueId": issue, "seq": seq, "expireAt": far})
	}
	must(t, insert("e1", "i1", 1), "e1")
	must(t, insert("e2", "i1", 2), "e2")
	must(t, insert("e3", "i2", 1), "e3")
	wantErr(t, insert("e4", "i1", 1), store.ErrConflict, "unique compound insert")
	// Numeric equality across BSON types counts for uniqueness.
	wantErr(t, c.InsertOne(ctx, store.Document{"_id": "e5", "issueId": "i1", "seq": 2.0}), store.ErrConflict, "unique across numeric types")
	_, err := c.UpdateOne(ctx, store.Document{"_id": "e3"}, store.Document{"$set": store.Document{"issueId": "i1"}}, false)
	wantErr(t, err, store.ErrConflict, "unique update")
	var out bson.M
	err = c.FindOneAndUpdate(ctx, store.Document{"_id": "e2"}, store.Document{"$set": store.Document{"seq": int32(1)}}, store.FindOneAndUpdateOptions{ReturnAfter: true}, &out)
	wantErr(t, err, store.ErrConflict, "unique find-and-update")
	var rows []bson.M
	must(t, c.FindMany(ctx, store.Document{}, &rows), "list events")
	if len(rows) != 3 {
		t.Fatalf("conflicting writes changed the collection: %v", rows)
	}
	// TTL index with a far expiry must not remove anything.
	var e1 bson.M
	must(t, c.FindOne(ctx, store.Document{"_id": "e1"}, &e1), "e1 survives")
}

func testCustomTypes(t *testing.T, db store.DocumentDatabase, cfg config) {
	ctx := testContext(t)
	c := db.Collection("custom")

	// BotSpecialties decodes leniently: only string elements, any other shape
	// is absent; an explicit [] is kept.
	must(t, c.InsertOne(ctx, store.Document{"_id": "bots", "bots": bson.A{
		bson.M{"appId": "x", "name": "X", "specialties": bson.A{"go", int32(1), "review", nil}},
		bson.M{"appId": "y", "name": "Y", "specialties": "not-an-array"},
		bson.M{"appId": "z", "name": "Z", "specialties": bson.A{}},
		bson.M{"appId": "w", "name": "W"},
	}}), "insert bots")
	var machine struct {
		Bots []store.BotInfo `bson:"bots"`
	}
	must(t, c.FindOne(ctx, store.Document{"_id": "bots"}, &machine), "decode bots")
	if len(machine.Bots) != 4 {
		t.Fatalf("bots = %+v", machine.Bots)
	}
	wantEqual(t, machine.Bots[0].Specialties, store.BotSpecialties{"go", "review"}, "mixed specialties")
	wantEqual(t, machine.Bots[1].Specialties, store.BotSpecialties(nil), "non-array specialties")
	wantEqual(t, machine.Bots[2].Specialties, store.BotSpecialties{}, "empty specialties")
	wantEqual(t, machine.Bots[3].Specialties, store.BotSpecialties(nil), "missing specialties")

	// Marshal side: an explicit empty BotSpecialties is written as [].
	showInTeam := true
	_, err := c.UpdateOne(ctx, store.Document{"_id": "bots"}, store.Document{"$set": store.Document{
		"bots": []store.BotInfo{{AppID: "e", Name: "E", Specialties: store.BotSpecialties{}, ShowInTeam: &showInTeam}},
	}}, false)
	must(t, err, "$set []BotInfo")
	raw := rawDoc(t, c, "bots")
	first := raw.Lookup("bots", "0")
	if first.Type != bsontype.EmbeddedDocument {
		t.Fatalf("bots.0 = %v", first)
	}
	if v := first.Document().Lookup("specialties"); v.Type != bsontype.Array {
		t.Fatalf("explicit empty specialties written as %v", v)
	}

	// ConsentTeams marshals as "all" or a string array and round-trips.
	_, err = c.UpdateOne(ctx, store.Document{"_id": "consent"}, store.Document{"$set": store.Document{
		"all": store.ConsentAll(), "teams": store.ConsentToTeams([]string{"t1", "t2"}), "none": store.ConsentToTeams(nil),
	}}, true)
	must(t, err, "upsert consent")
	raw = rawDoc(t, c, "consent")
	if raw.Lookup("all").StringValue() != "all" {
		t.Fatalf("ConsentAll stored as %v", raw.Lookup("all"))
	}
	wantType(t, raw, "teams", bsontype.Array)
	wantType(t, raw, "none", bsontype.Array)
	var consent struct {
		All   store.ConsentTeams `bson:"all"`
		Teams store.ConsentTeams `bson:"teams"`
		None  store.ConsentTeams `bson:"none"`
	}
	must(t, c.FindOne(ctx, store.Document{"_id": "consent"}, &consent), "decode consent")
	if !consent.All.All || consent.Teams.All || len(consent.None.Teams) != 0 || consent.None.All {
		t.Fatalf("consent = %+v", consent)
	}
	wantEqual(t, consent.Teams.Teams, []string{"t1", "t2"}, "consent teams")
	// The consentTeams filter used by queries compares against the marshalled value.
	var hit bson.M
	must(t, c.FindOne(ctx, store.Document{"all": "all", "teams": "t2"}, &hit), "filter on consent values")

	// IssueCustomFields keeps insertion order through the driver.
	fields := store.IssueCustomFields{{ID: "zeta", Value: "1"}, {ID: "alpha", Value: []string{"a", "b"}}, {ID: "mid", Value: []string{}}}
	must(t, c.InsertOne(ctx, store.Document{"_id": "fields", "customFields": fields}), "insert custom fields")
	var withFields struct {
		CustomFields store.IssueCustomFields `bson:"customFields"`
	}
	must(t, c.FindOne(ctx, store.Document{"_id": "fields"}, &withFields), "decode custom fields")
	if cfg.unorderedSubdocuments {
		byID := map[string]any{}
		for _, f := range withFields.CustomFields {
			byID[f.ID] = f.Value
		}
		wantEqual(t, byID, map[string]any{"zeta": "1", "alpha": []string{"a", "b"}, "mid": []string{}}, "custom field values")
	} else {
		wantEqual(t, withFields.CustomFields, fields, "custom fields order and values")
		keys := []string{}
		elements, err := rawDoc(t, c, "fields").Lookup("customFields").Document().Elements()
		must(t, err, "custom field elements")
		for _, e := range elements {
			keys = append(keys, e.Key())
		}
		wantEqual(t, keys, []string{"zeta", "alpha", "mid"}, "stored custom field order")
	}

	// IssueDoc/IssueClaim implement UnmarshalBSON and keep the raw bytes.
	must(t, c.InsertOne(ctx, store.Document{
		"_id": "issue", "teamId": "t", "title": "T", "body": "", "status": "claimed", "rev": int32(1), "stateRev": 2.0,
		"claimEpochCounter": int32(1), "eventSeq": int32(2), "createdAt": 1.0, "updatedAt": 2.0, "labels": bson.A{},
		"claim": bson.D{{Key: "claimId", Value: "c1"}, {Key: "claimEpoch", Value: int32(1)}, {Key: "unionId", Value: "u"},
			{Key: "name", Value: "U"}, {Key: "machineId", Value: "m"}, {Key: "agent", Value: bson.D{{Key: "kind", Value: "codex"}}},
			{Key: "claimedAt", Value: 1.0}, {Key: "leaseExpiresAt", Value: 5.0}, {Key: "bound", Value: false}, {Key: "lastSourceSeq", Value: 0.5}},
	}), "insert issue")
	var issues []store.IssueDoc
	must(t, c.FindMany(ctx, store.Document{"_id": "issue"}, &issues), "decode issues")
	if len(issues) != 1 {
		t.Fatalf("issues = %v", issues)
	}
	issue := issues[0]
	if issue.StateRev != 2 || issue.Rev != 1 || issue.Labels == nil || len(*issue.Labels) != 0 || issue.Claim == nil ||
		issue.Claim.ClaimID != "c1" || issue.Claim.LeaseExpiresAt != 5 || issue.Claim.LastSourceSeq != 0.5 {
		t.Fatalf("issue = %+v claim=%+v", issue, issue.Claim)
	}
	agent, err := bson.Marshal(bson.M{"agent": issue.Claim.Agent})
	must(t, err, "marshal agent")
	if kind := bson.Raw(agent).Lookup("agent", "kind"); kind.StringValue() != "codex" {
		t.Fatalf("claim.agent decoded as %#v", issue.Claim.Agent)
	}
}

func testCanceledContext(t *testing.T, db store.DocumentDatabase) {
	c := seedCollection(t, db, "rows")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out row
	err := c.FindOne(ctx, store.Document{"_id": "a"}, &out)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("FindOne with a canceled context: err = %v, want context.Canceled", err)
	}
	_, err = c.UpdateOne(ctx, store.Document{"_id": "a"}, store.Document{"$set": store.Document{"owner": "x"}}, false)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("UpdateOne with a canceled context: err = %v, want context.Canceled", err)
	}
	must(t, c.FindOne(testContext(t), store.Document{"_id": "a"}, &out), "find a")
	if out.Owner != "u1" {
		t.Fatalf("canceled update was applied: %+v", out)
	}
}
