package store

import (
	"encoding/json"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

// BotSpecialties is BotInfo.specialties. Node persists whatever the daemon
// reported and filters at read time (`Array.isArray(v) ? v.filter(string) :
// []`), so decoding is lenient: an array keeps only its string elements and
// any other shape decodes as absent. A malformed self-reported label must
// never make the whole machine document (or register message) unreadable.
type BotSpecialties []string

// IsZero keeps an explicit empty array on write (bson omitempty consults
// Zeroer); only an absent value is omitted.
func (s BotSpecialties) IsZero() bool { return s == nil }

// Strings returns the TS read projection: the reported labels or [].
func (s BotSpecialties) Strings() []string {
	if s == nil {
		return []string{}
	}
	return append([]string{}, s...)
}

func (s *BotSpecialties) UnmarshalBSONValue(t bsontype.Type, data []byte) error {
	*s = nil
	if t != bsontype.Array {
		return nil
	}
	values, err := bson.Raw(data).Values()
	if err != nil {
		return nil
	}
	out := make(BotSpecialties, 0, len(values))
	for _, value := range values {
		if text, ok := value.StringValueOK(); ok {
			out = append(out, text)
		}
	}
	*s = out
	return nil
}

func (s *BotSpecialties) UnmarshalJSON(data []byte) error {
	*s = nil
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil || values == nil {
		return nil
	}
	out := make(BotSpecialties, 0, len(values))
	for _, value := range values {
		var text string
		if len(value) > 0 && value[0] == '"' && json.Unmarshal(value, &text) == nil {
			out = append(out, text)
		}
	}
	*s = out
	return nil
}
