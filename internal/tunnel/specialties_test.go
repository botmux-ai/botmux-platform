package tunnel

import (
	"encoding/json"
	"slices"
	"testing"
)

// A malformed self-reported label must never fail a register message.
func TestBotInfoSpecialtiesAreLenient(t *testing.T) {
	for in, want := range map[string]Specialties{
		`{"type":"register","bots":[{"appId":"cli_a","name":"A","specialties":["code",7,"review"],"mentionable":false}]}`: {"code", "review"},
		`{"type":"register","bots":[{"appId":"cli_a","name":"A","specialties":"code"}]}`:                                  nil,
		`{"type":"register","bots":[{"appId":"cli_a","name":"A"}]}`:                                                       nil,
	} {
		var message DaemonMessage
		if err := json.Unmarshal([]byte(in), &message); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		bot := message.Bots[0]
		if bot.AppID != "cli_a" || (bot.Specialties == nil) != (want == nil) || !slices.Equal(bot.Specialties, want) {
			t.Fatalf("%s: %+v", in, bot)
		}
	}
	var message DaemonMessage
	_ = json.Unmarshal([]byte(`{"type":"register","bots":[{"appId":"a","mentionable":false}]}`), &message)
	if m := message.Bots[0].Mentionable; m == nil || *m {
		t.Fatalf("mentionable = %v", m)
	}
}
