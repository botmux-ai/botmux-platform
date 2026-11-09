package server

import (
	"context"

	"github.com/botmux-ai/botmux-platform/internal/store"
)

// newMemoryRepository is the local-mode repository: DocumentRepository on the
// Mongo-semantics in-memory database.
func newMemoryRepository() *store.DocumentRepository {
	return store.NewDocumentRepository(store.NewMemoryDatabaseProvider())
}

// seedMachine binds the machine to its owner (register never creates
// documents) and then persists the register metadata.
func seedMachine(repository store.Repository, machine store.RegisterMachine) error {
	ctx := context.Background()
	if _, err := repository.BindMachineCAS(ctx, machine.MachineID, machine.UnionID, machine.OwnerName); err != nil {
		return err
	}
	return repository.PersistRegister(ctx, machine)
}
