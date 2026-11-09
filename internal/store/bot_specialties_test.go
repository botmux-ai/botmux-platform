package store

import (
	"encoding/json"
	"slices"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

type specialtiesHolder struct {
	S BotSpecialties `bson:"s,omitempty" json:"s,omitempty"`
}

func TestBotSpecialtiesBSONIsLenient(t *testing.T) {
	cases := []struct {
		name string
		doc  bson.M
		want BotSpecialties
	}{
		{"strings", bson.M{"s": bson.A{"code", "review"}}, BotSpecialties{"code", "review"}},
		{"mixed array keeps strings", bson.M{"s": bson.A{"code", 1, nil, bson.M{"x": 1}, "ops"}}, BotSpecialties{"code", "ops"}},
		{"empty array", bson.M{"s": bson.A{}}, BotSpecialties{}},
		{"string is absent", bson.M{"s": "code"}, nil},
		{"null is absent", bson.M{"s": nil}, nil},
		{"missing", bson.M{}, nil},
	}
	for _, c := range cases {
		raw, err := bson.Marshal(c.doc)
		if err != nil {
			t.Fatal(err)
		}
		var got specialtiesHolder
		if err := bson.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (got.S == nil) != (c.want == nil) || !slices.Equal(got.S, c.want) {
			t.Fatalf("%s: got %#v want %#v", c.name, got.S, c.want)
		}
	}
}

func TestBotSpecialtiesBSONKeepsEmptyArray(t *testing.T) {
	for _, c := range []struct {
		in   BotSpecialties
		want bool
	}{{nil, false}, {BotSpecialties{}, true}, {BotSpecialties{"a"}, true}} {
		raw, err := bson.Marshal(specialtiesHolder{S: c.in})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bson.Raw(raw).LookupErr("s"); (err == nil) != c.want {
			t.Fatalf("%#v: present=%v", c.in, err == nil)
		}
	}
}

func TestBotSpecialtiesJSONIsLenient(t *testing.T) {
	for in, want := range map[string]BotSpecialties{
		`{"s":["a",1,"b",null]}`: {"a", "b"},
		`{"s":"a"}`:              nil,
		`{"s":{"a":1}}`:          nil,
		`{"s":null}`:             nil,
		`{"s":[]}`:               {},
	} {
		var got specialtiesHolder
		if err := json.Unmarshal([]byte(in), &got); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if (got.S == nil) != (want == nil) || !slices.Equal(got.S, want) {
			t.Fatalf("%s: got %#v want %#v", in, got.S, want)
		}
	}
	if got := (BotSpecialties)(nil).Strings(); got == nil || len(got) != 0 {
		t.Fatalf("Strings(nil) = %#v", got)
	}
}
