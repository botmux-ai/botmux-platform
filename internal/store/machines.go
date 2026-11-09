package store

import (
	"context"
	"errors"
)

// BindResult classifies a BindMachineCAS outcome. Store degradation is
// reported as ErrUnavailable instead, and callers must then refuse to mint a
// machine token.
type BindResult string

const (
	// BindCreated: a new ACTIVE document was inserted for the machineId.
	BindCreated BindResult = "created"
	// BindRebound: idempotent re-bind by the same owner (ownerName refreshed).
	BindRebound BindResult = "rebound"
	// BindConflictOwner: the machine is ACTIVE and owned by someone else; the
	// ownership is never overwritten.
	BindConflictOwner BindResult = "conflict_owner"
	// BindRetired: the machineId is a tombstone and is never reused; callers
	// retry with a fresh random id.
	BindRetired BindResult = "retired"
)

// machineInsertDocument keeps the TS field order and the Node driver's BSON
// types (integers that fit int32 are int32, Date.now() values are doubles).
type machineInsertDocument struct {
	ID            string           `bson:"_id"`
	UnionID       string           `bson:"unionId"`
	OwnerName     string           `bson:"ownerName"`
	Name          string           `bson:"name"`
	BotmuxVersion string           `bson:"botmuxVersion"`
	DashboardPort int32            `bson:"dashboardPort"`
	Memberships   []MembershipInfo `bson:"memberships"`
	BoundAt       float64          `bson:"boundAt"`
	LastSeen      int32            `bson:"lastSeen"`
	Status        string           `bson:"status"`
}

type coManagerDocument struct {
	UnionID   string   `bson:"unionId"`
	Name      string   `bson:"name"`
	Scopes    []string `bson:"scopes"`
	GrantedAt float64  `bson:"grantedAt"`
	GrantedBy string   `bson:"grantedBy"`
	ViaTeamID string   `bson:"viaTeamId,omitempty"`
	Role      string   `bson:"role,omitempty"`
}

func coManagerDocuments(in []MachineCoManager) []coManagerDocument {
	out := make([]coManagerDocument, 0, len(in))
	for _, c := range in {
		scopes := c.Scopes
		if scopes == nil {
			scopes = []string{}
		}
		out = append(out, coManagerDocument{UnionID: c.UnionID, Name: c.Name, Scopes: scopes,
			GrantedAt: bsonNumber(c.GrantedAt), GrantedBy: c.GrantedBy, ViaTeamID: c.ViaTeamID, Role: c.Role})
	}
	return out
}

func (s *DocumentRepository) invalidateMachine(machineID string) {
	if s != nil && s.machineCache != nil {
		s.machineCache.invalidate(machineID)
	}
}

// BindMachineCAS is the ownership compare-and-set for /api/bind and desktop
// machine enrollment. It replaces the old "mint first, persist later" bind:
//   - missing document: insert a fresh ACTIVE document (BindCreated); a lost
//     insert race re-reads and classifies the winner;
//   - RETIRED: BindRetired (never reuse the id);
//   - ACTIVE and owned by someone else: BindConflictOwner;
//   - same owner: CAS {_id, unionId, status != RETIRED} refreshing ownerName
//     (BindRebound); losing that CAS re-reads and reports BindRetired or
//     BindConflictOwner.
//
// Any store failure is ErrUnavailable; the caller must answer 503 and must
// not mint a machine token.
func (s *DocumentRepository) BindMachineCAS(ctx context.Context, machineID, unionID, ownerName string) (BindResult, error) {
	s.invalidateMachine(machineID)
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return "", err
	}
	unavailable := func(err error) (BindResult, error) {
		err = normalizeDBError(err)
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
			err = ErrUnavailable
		}
		return "", err
	}
	var doc MachineDoc
	err = c.FindOne(ctx, Document{"_id": machineID}, &doc)
	switch {
	case errors.Is(err, ErrNotFound):
		insertErr := c.InsertOne(ctx, machineInsertDocument{
			ID: machineID, UnionID: unionID, OwnerName: ownerName, Name: "", BotmuxVersion: "unknown",
			DashboardPort: 0, Memberships: []MembershipInfo{}, BoundAt: bsonNumber(s.nowMS()), LastSeen: 0,
			Status: MachineStatusActive,
		})
		if insertErr == nil {
			s.invalidateMachine(machineID)
			return BindCreated, nil
		}
		// Concurrent insert (or a failed write): re-read and classify.
		doc = MachineDoc{}
		if err := c.FindOne(ctx, Document{"_id": machineID}, &doc); err != nil {
			return unavailable(err)
		}
	case err != nil:
		return unavailable(err)
	}
	if doc.Retired() {
		return BindRetired, nil
	}
	if doc.UnionID != unionID {
		return BindConflictOwner, nil
	}
	r, err := c.UpdateOne(ctx, Document{"_id": machineID, "unionId": unionID, "status": notRetired()},
		Document{"$set": Document{"ownerName": ownerName}}, false)
	if err != nil {
		return unavailable(err)
	}
	if r.Matched > 0 {
		s.invalidateMachine(machineID)
		return BindRebound, nil
	}
	var again MachineDoc
	err = c.FindOne(ctx, Document{"_id": machineID}, &again)
	switch {
	case err == nil && again.Retired():
		return BindRetired, nil
	case err != nil && !errors.Is(err, ErrNotFound):
		return unavailable(err)
	}
	return BindConflictOwner, nil
}

// RetireMachine turns the machine document into a RETIRED tombstone (unbind).
// The machineId is never reused and every list excludes it. It succeeds even
// if no document matched; ErrUnavailable means the tombstone was not written
// and the caller must not report the unbind as successful.
func (s *DocumentRepository) RetireMachine(ctx context.Context, machineID string) error {
	s.invalidateMachine(machineID)
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return err
	}
	if _, err := c.UpdateOne(ctx, Document{"_id": machineID}, Document{"$set": Document{"status": MachineStatusRetired}}, false); err != nil {
		return normalizeDBError(err)
	}
	s.invalidateMachine(machineID)
	return nil
}

// LookupMachine is the authorization read of one machine document:
// ErrNotFound when it does not exist, ErrUnavailable when the store is
// degraded (callers answer 503). RETIRED documents are returned as-is.
// With opts.PositiveTTL > 0 the result goes through the pod-local positive
// cache (see AuthorityCacheOptions); only existing non-RETIRED documents are
// cached. The returned document is always a private copy.
func (s *DocumentRepository) LookupMachine(ctx context.Context, machineID string, opts AuthorityCacheOptions) (MachineDoc, error) {
	read := func(ctx context.Context) (MachineDoc, error) {
		s.machineReads.Add(1)
		return s.GetMachine(ctx, machineID)
	}
	ttl := opts.ttl(desktopDashboardAuthCacheHardMax)
	if ttl <= 0 {
		return read(ctx)
	}
	doc, err := s.machineCache.get(ctx, machineID, ttl, s.now, read, func(doc MachineDoc, err error) bool {
		return err == nil && !doc.Retired()
	})
	if err != nil {
		return MachineDoc{}, err
	}
	return cloneMachine(doc), nil
}

// ListMachinesForUsers returns all non-RETIRED machines owned by any of the
// given people. This is the person-level authority for team agent discovery:
// team membership comes from teams.members and ownership from the
// token-stamped machines.unionId, never from forgeable daemon memberships.
// An empty input returns an empty list without touching the store.
func (s *DocumentRepository) ListMachinesForUsers(ctx context.Context, unionIDs []string) ([]MachineDoc, error) {
	if len(unionIDs) == 0 {
		return []MachineDoc{}, nil
	}
	return s.findMachines(ctx, Document{"unionId": Document{"$in": unionIDs}, "status": notRetired()})
}

// ListMachinesCoManagedBy lists non-RETIRED machines on which unionID is a
// co-manager, excluding machines unionID owns (served by the
// coManagers.unionId index).
func (s *DocumentRepository) ListMachinesCoManagedBy(ctx context.Context, unionID string) ([]MachineDoc, error) {
	return s.findMachines(ctx, Document{
		"coManagers.unionId": unionID,
		"status":             notRetired(),
		"unionId":            Document{"$ne": unionID},
	})
}

// ListMachineVersionSamples returns version samples of every non-RETIRED
// machine for the version dashboard.
func (s *DocumentRepository) ListMachineVersionSamples(ctx context.Context) ([]MachineVersionSample, error) {
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return nil, err
	}
	var docs []struct {
		ID            string `bson:"_id"`
		UnionID       string `bson:"unionId"`
		BotmuxVersion string `bson:"botmuxVersion"`
		LastSeen      int64  `bson:"lastSeen,truncate"`
	}
	if err := c.FindMany(ctx, Document{"status": notRetired()}, &docs); err != nil {
		return nil, normalizeDBError(err)
	}
	out := make([]MachineVersionSample, 0, len(docs))
	for _, d := range docs {
		out = append(out, MachineVersionSample{MachineID: d.ID, UnionID: d.UnionID, BotmuxVersion: d.BotmuxVersion, LastSeen: d.LastSeen})
	}
	return out, nil
}

// SetMachineCoManagers replaces the co-manager list (owner operation). The CAS
// re-checks ownership and non-tombstone status: ErrNotFound means the machine
// is gone, retired or owned by someone else, and nothing was written. A
// successful write invalidates the positive cache so a removed co-manager
// loses access immediately on this pod.
func (s *DocumentRepository) SetMachineCoManagers(ctx context.Context, machineID, ownerUnionID string, coManagers []MachineCoManager) error {
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return err
	}
	r, err := c.UpdateOne(ctx, Document{"_id": machineID, "unionId": ownerUnionID, "status": notRetired()},
		Document{"$set": Document{"coManagers": coManagerDocuments(coManagers)}}, false)
	if err != nil {
		return normalizeDBError(err)
	}
	if r.Matched == 0 {
		return ErrNotFound
	}
	s.invalidateMachine(machineID)
	return nil
}

// DropCoManagerFromTeamMachines removes unionID's co-manager grants that were
// made via teamID from every machine owned by someone else, when unionID
// leaves (or is removed from) the team. Grants via another shared team and
// legacy grants without viaTeamId are kept on purpose (the owner sees a
// leftTeam hint instead of a silent wrong removal).
//
// Machines and teams live in different collections without transactions, so
// this is best effort: it returns the machine ids it changed, plus an error
// (ErrUnavailable) if it had to stop early. Callers normally log and continue.
func (s *DocumentRepository) DropCoManagerFromTeamMachines(ctx context.Context, teamID, unionID string) ([]string, error) {
	affected := []string{}
	c, err := s.collection(ctx, collectionMachines)
	if err != nil {
		return affected, err
	}
	var docs []MachineDoc
	if err := c.FindMany(ctx, Document{"coManagers.unionId": unionID, "status": notRetired()}, &docs); err != nil {
		return affected, normalizeDBError(err)
	}
	for _, d := range docs {
		if d.UnionID == unionID {
			continue
		}
		next := make([]MachineCoManager, 0, len(d.CoManagers))
		drop := false
		for _, cm := range d.CoManagers {
			if cm.UnionID == unionID && cm.ViaTeamID != "" && cm.ViaTeamID == teamID {
				drop = true
				continue
			}
			next = append(next, cm)
		}
		if !drop {
			continue
		}
		r, err := c.UpdateOne(ctx, Document{"_id": d.ID, "unionId": d.UnionID},
			Document{"$set": Document{"coManagers": coManagerDocuments(next)}}, false)
		if err != nil {
			return affected, normalizeDBError(err)
		}
		if r.Matched > 0 {
			s.invalidateMachine(d.ID)
			affected = append(affected, d.ID)
		}
	}
	return affected, nil
}
