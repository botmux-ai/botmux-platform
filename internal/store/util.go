package store

import (
	"context"
	"time"
)

func checkContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func truncateRunes(value string, limit int) string {
	if limit < 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

// msTime converts Unix milliseconds to the BSON Date used by TTL indexes.
func msTime(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

func cloneBots(in []BotInfo) []BotInfo {
	if in == nil {
		return nil
	}
	out := append([]BotInfo(nil), in...)
	for i := range out {
		if out[i].OpenID != nil {
			value := *out[i].OpenID
			out[i].OpenID = &value
		}
		if out[i].ShowInTeam != nil {
			value := *out[i].ShowInTeam
			out[i].ShowInTeam = &value
		}
		if out[i].Specialties != nil {
			out[i].Specialties = append(BotSpecialties{}, out[i].Specialties...)
		}
		if out[i].Mentionable != nil {
			value := *out[i].Mentionable
			out[i].Mentionable = &value
		}
	}
	return out
}

func cloneCoManagers(in []MachineCoManager) []MachineCoManager {
	if in == nil {
		return nil
	}
	out := append([]MachineCoManager(nil), in...)
	for i := range out {
		out[i].Scopes = append([]string(nil), out[i].Scopes...)
	}
	return out
}

// cloneMachine deep-copies the slices of a cached document so callers can
// never mutate a shared cache entry.
func cloneMachine(m MachineDoc) MachineDoc {
	if m.Memberships != nil {
		m.Memberships = append([]MembershipInfo(nil), m.Memberships...)
	}
	m.Bots = cloneBots(m.Bots)
	m.CoManagers = cloneCoManagers(m.CoManagers)
	return m
}
