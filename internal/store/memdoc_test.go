package store

import (
	"context"
	"errors"
	"testing"
)

type memdocBot struct {
	AppID string `bson:"appId"`
	Name  string `bson:"name,omitempty"`
}

type memdocRow struct {
	ID       string      `bson:"_id"`
	Owner    string      `bson:"owner"`
	Seq      int64       `bson:"seq"`
	Score    float64     `bson:"score"`
	Tags     []string    `bson:"tags,omitempty"`
	Bots     []memdocBot `bson:"bots,omitempty"`
	Claim    *memdocBot  `bson:"claim,omitempty"`
	LastSeen float64     `bson:"lastSeen,truncate"`
}

func newMemdocCollection(t *testing.T) DocumentCollection {
	t.Helper()
	c := NewMemoryDatabase().Collection("rows")
	ctx := context.Background()
	for _, row := range []memdocRow{
		{ID: "a", Owner: "u1", Seq: 3, Score: 1.5, Tags: []string{"x", "y"}, Bots: []memdocBot{{AppID: "cli_1"}}},
		{ID: "b", Owner: "u2", Seq: 1, Score: 2.5, Bots: []memdocBot{{AppID: "cli_2"}, {AppID: "cli_3"}}},
		{ID: "c", Owner: "u1", Seq: 2, Score: 0.5, Claim: &memdocBot{AppID: "cli_9"}},
	} {
		if err := c.InsertOne(ctx, row); err != nil {
			t.Fatalf("insert %s: %v", row.ID, err)
		}
	}
	return c
}

func memdocIDs(t *testing.T, c DocumentCollection, filter Document, opts FindOptions) []string {
	t.Helper()
	var rows []memdocRow
	if err := c.FindManyOptions(context.Background(), filter, opts, &rows); err != nil {
		t.Fatalf("find %v: %v", filter, err)
	}
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	return ids
}

func TestMemdocFilterOperators(t *testing.T) {
	c := newMemdocCollection(t)
	cases := []struct {
		name   string
		filter Document
		want   string
	}{
		{"equality", Document{"owner": "u1"}, "a,c"},
		{"array element equality", Document{"tags": "y"}, "a"},
		{"dotted array traversal", Document{"bots.appId": "cli_3"}, "b"},
		{"nested document", Document{"claim.appId": "cli_9"}, "c"},
		{"gt numeric across types", Document{"seq": Document{"$gt": 1.5}}, "a,c"},
		{"lte", Document{"score": Document{"$lte": 1.5}}, "a,c"},
		{"in", Document{"_id": Document{"$in": []string{"a", "b", "zz"}}}, "a,b"},
		{"nin", Document{"owner": Document{"$nin": []string{"u1"}}}, "b"},
		{"ne missing matches", Document{"claim.appId": Document{"$ne": "cli_9"}}, "a,b"},
		{"exists false", Document{"claim": Document{"$exists": false}}, "a,b"},
		{"exists true", Document{"tags": Document{"$exists": true}}, "a"},
		{"null matches missing", Document{"claim": nil}, "a,b"},
		{"or", Document{"$or": []Document{{"owner": "u2"}, {"seq": 2}}}, "b,c"},
		{"elemMatch", Document{"bots": Document{"$elemMatch": Document{"appId": "cli_2"}}}, "b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := memdocIDs(t, c, tc.filter, FindOptions{Sort: []IndexKey{{Field: "_id", Order: 1}}})
			if joined := joinIDs(got); joined != tc.want {
				t.Fatalf("got %s want %s", joined, tc.want)
			}
		})
	}
}

func joinIDs(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ","
		}
		out += id
	}
	return out
}

func TestMemdocSortAndLimit(t *testing.T) {
	c := newMemdocCollection(t)
	if got := joinIDs(memdocIDs(t, c, Document{}, FindOptions{Sort: []IndexKey{{Field: "seq", Order: 1}}})); got != "b,c,a" {
		t.Fatalf("asc sort = %s", got)
	}
	if got := joinIDs(memdocIDs(t, c, Document{}, FindOptions{Sort: []IndexKey{{Field: "owner", Order: 1}, {Field: "seq", Order: -1}}, Limit: 2})); got != "a,c" {
		t.Fatalf("compound sort+limit = %s", got)
	}
}

func TestMemdocFindOneAndUpdateCAS(t *testing.T) {
	c := newMemdocCollection(t)
	ctx := context.Background()
	var after memdocRow
	err := c.FindOneAndUpdate(ctx,
		Document{"_id": "a", "seq": 3},
		Document{"$set": Document{"claim": memdocBot{AppID: "cli_7", Name: "n"}}, "$inc": Document{"seq": int64(1)}, "$push": Document{"tags": "z"}},
		FindOneAndUpdateOptions{ReturnAfter: true}, &after)
	if err != nil {
		t.Fatal(err)
	}
	if after.Seq != 4 || after.Claim == nil || after.Claim.AppID != "cli_7" || len(after.Tags) != 3 {
		t.Fatalf("after = %+v", after)
	}
	// The precondition no longer holds, so a second CAS loses.
	err = c.FindOneAndUpdate(ctx, Document{"_id": "a", "seq": 3}, Document{"$inc": Document{"seq": int64(1)}}, FindOneAndUpdateOptions{ReturnAfter: true}, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale CAS err = %v", err)
	}
	var before memdocRow
	if err := c.FindOneAndUpdate(ctx, Document{"_id": "a"}, Document{"$unset": Document{"claim": ""}}, FindOneAndUpdateOptions{}, &before); err != nil {
		t.Fatal(err)
	}
	if before.Claim == nil {
		t.Fatalf("ReturnAfter=false must return the pre-image")
	}
	var row memdocRow
	if err := c.FindOne(ctx, Document{"_id": "a"}, &row); err != nil || row.Claim != nil {
		t.Fatalf("unset failed: %+v %v", row, err)
	}
}

func TestMemdocUpsertSeedsFilterAndSetOnInsert(t *testing.T) {
	c := NewMemoryDatabase().Collection("rows")
	ctx := context.Background()
	update := Document{"$set": Document{"score": 1.0}, "$setOnInsert": Document{"seq": int64(7)}}
	result, err := c.UpdateOne(ctx, Document{"_id": "n", "owner": "u9"}, update, true)
	if err != nil || result.Upserted != 1 {
		t.Fatalf("upsert = %+v %v", result, err)
	}
	if _, err := c.UpdateOne(ctx, Document{"_id": "n"}, Document{"$set": Document{"score": 2.0}, "$setOnInsert": Document{"seq": int64(9)}}, true); err != nil {
		t.Fatal(err)
	}
	var row memdocRow
	if err := c.FindOne(ctx, Document{"_id": "n"}, &row); err != nil {
		t.Fatal(err)
	}
	if row.Owner != "u9" || row.Seq != 7 || row.Score != 2.0 {
		t.Fatalf("row = %+v", row)
	}
}

func TestMemdocArrayOperators(t *testing.T) {
	c := newMemdocCollection(t)
	ctx := context.Background()
	if _, err := c.UpdateOne(ctx, Document{"_id": "b"}, Document{"$pull": Document{"bots": Document{"appId": "cli_2"}}}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateOne(ctx, Document{"_id": "b"}, Document{"$addToSet": Document{"tags": Document{"$each": []string{"p", "p", "q"}}}}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateMany(ctx, Document{"owner": "u1"}, Document{"$pull": Document{"tags": Document{"$in": []string{"x"}}}}); err != nil {
		t.Fatal(err)
	}
	var b, a memdocRow
	_ = c.FindOne(ctx, Document{"_id": "b"}, &b)
	_ = c.FindOne(ctx, Document{"_id": "a"}, &a)
	if len(b.Bots) != 1 || b.Bots[0].AppID != "cli_3" || joinIDs(b.Tags) != "p,q" {
		t.Fatalf("b = %+v", b)
	}
	if joinIDs(a.Tags) != "y" {
		t.Fatalf("a tags = %v", a.Tags)
	}
}

func TestMemdocUniqueIndexesAndDelete(t *testing.T) {
	c := newMemdocCollection(t)
	ctx := context.Background()
	if err := c.InsertOne(ctx, memdocRow{ID: "a"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate _id err = %v", err)
	}
	if err := c.CreateIndexSpec(ctx, IndexSpec{Keys: []IndexKey{{Field: "owner", Order: 1}, {Field: "seq", Order: 1}}, Unique: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.InsertOne(ctx, memdocRow{ID: "d", Owner: "u1", Seq: 2}); !errors.Is(err, ErrConflict) {
		t.Fatalf("compound unique err = %v", err)
	}
	deleted, err := c.DeleteMany(ctx, Document{"owner": "u1"})
	if err != nil || deleted.Deleted != 2 {
		t.Fatalf("delete many = %+v %v", deleted, err)
	}
	if got := joinIDs(memdocIDs(t, c, Document{}, FindOptions{})); got != "b" {
		t.Fatalf("remaining = %s", got)
	}
}

func TestMemdocPreservesBSONNumericTypes(t *testing.T) {
	db := NewMemoryDatabase()
	c := db.Collection("rows")
	ctx := context.Background()
	if _, err := c.UpdateOne(ctx, Document{"_id": "x"}, Document{"$set": Document{"lastSeen": float64(1700000000123), "count": int32(1)}}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UpdateOne(ctx, Document{"_id": "x"}, Document{"$inc": Document{"count": int32(1)}}, false); err != nil {
		t.Fatal(err)
	}
	stored := db.MemoryCollection("rows").Documents()[0]
	if _, ok := stored["lastSeen"].(float64); !ok {
		t.Fatalf("lastSeen type = %T", stored["lastSeen"])
	}
	if v, ok := stored["count"].(int32); !ok || v != 2 {
		t.Fatalf("count = %T %v", stored["count"], stored["count"])
	}
	if err := c.FindOneAndUpdate(ctx, Document{"_id": "x"}, Document{"$set": Document{"a": 1}, "$unset": Document{"a.b": ""}}, FindOneAndUpdateOptions{}, nil); err == nil {
		t.Fatalf("conflicting update paths must be rejected")
	}
	// Like the server, the update document is validated before matching: a
	// conflicting update must fail even when the CAS filter matches nothing.
	conflict := Document{"$set": Document{"claim.lastSourceSeq": 1}, "$unset": Document{"claim": ""}}
	if err := c.FindOneAndUpdate(ctx, Document{"_id": "missing"}, conflict, FindOneAndUpdateOptions{}, nil); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("conflicting update on no match = %v, want conflict error", err)
	}
	if _, err := c.UpdateMany(ctx, Document{"_id": "missing"}, conflict); err == nil {
		t.Fatalf("UpdateMany must reject conflicting paths without a match")
	}
}
