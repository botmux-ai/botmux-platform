package store

import (
	"context"
	"time"
)

// RuntimeRouteAdapter presents KVStore with the TTL-at-call-site method
// signatures used by the tunnel registry/server and support server. Keeping
// this adapter explicit preserves KVStore's legacy-default convenience API
// while allowing one production client to back all three runtime components.
type RuntimeRouteAdapter struct{ store *KVStore }

func NewRuntimeRouteAdapter(store *KVStore) *RuntimeRouteAdapter {
	return &RuntimeRouteAdapter{store: store}
}

func (a *RuntimeRouteAdapter) client() (*KVStore, KVClient, error) {
	if a == nil || a.store == nil {
		return nil, nil, ErrUnavailable
	}
	c, err := a.store.requireClient()
	return a.store, c, err
}

// SetMachineRoute writes the route with the caller's TTL; repeated writes of
// the same owner inside the throttle window are skipped.
func (a *RuntimeRouteAdapter) SetMachineRoute(ctx context.Context, machineID, owner string, ttl time.Duration) error {
	s, _, err := a.client()
	if err != nil {
		return err
	}
	return s.setMachineRoute(ctx, machineID, owner, ttl)
}

// GetMachineRoute reads the route straight from Redis ("" when absent).
func (a *RuntimeRouteAdapter) GetMachineRoute(ctx context.Context, machineID string) (string, error) {
	s, _, err := a.client()
	if err != nil {
		return "", err
	}
	return s.readMachineRoute(ctx, machineID)
}

// GetMachineRouteCached is GetMachineRoute through the opt-in positive cache
// (see KVStore.GetMachineRouteCached).
func (a *RuntimeRouteAdapter) GetMachineRouteCached(ctx context.Context, machineID string, opts RouteCacheOptions) (string, error) {
	s, _, err := a.client()
	if err != nil {
		return "", err
	}
	return s.GetMachineRouteCached(ctx, machineID, opts)
}

// DeleteMachineRoute deletes the route (conditionally when expectedOwner is
// set) after dropping the local read cache and write throttle entries.
func (a *RuntimeRouteAdapter) DeleteMachineRoute(ctx context.Context, machineID, expectedOwner string) error {
	s, _, err := a.client()
	if err != nil {
		return err
	}
	_, err = s.deleteMachineRoute(ctx, machineID, expectedOwner)
	return err
}

func (a *RuntimeRouteAdapter) SetStreamOwner(ctx context.Context, streamID, owner string, ttl time.Duration) error {
	s, c, err := a.client()
	if err != nil {
		return err
	}
	return c.Set(ctx, s.StreamKey(streamID), owner, ttl)
}

func (a *RuntimeRouteAdapter) GetStreamOwner(ctx context.Context, streamID string) (string, error) {
	s, c, err := a.client()
	if err != nil {
		return "", err
	}
	return getOptional(ctx, c, s.StreamKey(streamID))
}

func (a *RuntimeRouteAdapter) SetSupportRoute(ctx context.Context, sessionID, owner string, ttl time.Duration) error {
	s, c, err := a.client()
	if err != nil {
		return err
	}
	return c.Set(ctx, s.SupportKey(sessionID), owner, ttl)
}

func (a *RuntimeRouteAdapter) GetSupportRoute(ctx context.Context, sessionID string) (string, error) {
	s, c, err := a.client()
	if err != nil {
		return "", err
	}
	return getOptional(ctx, c, s.SupportKey(sessionID))
}

func (a *RuntimeRouteAdapter) DeleteSupportRoute(ctx context.Context, sessionID, expectedOwner string) error {
	s, c, err := a.client()
	if err != nil {
		return err
	}
	if expectedOwner == "" {
		return c.Delete(ctx, s.SupportKey(sessionID))
	}
	_, err = c.CompareAndDelete(ctx, s.SupportKey(sessionID), expectedOwner)
	return err
}

func (a *RuntimeRouteAdapter) IsMachineTokenRevoked(ctx context.Context, machineID string, issuedAtMS int64) (bool, error) {
	if a == nil || a.store == nil {
		return false, ErrUnavailable
	}
	if issuedAtMS <= 0 {
		return a.store.IsMachineTokenRevoked(ctx, machineID, nil)
	}
	return a.store.IsMachineTokenRevoked(ctx, machineID, &issuedAtMS)
}
