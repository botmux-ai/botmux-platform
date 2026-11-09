package store_test

import (
	"testing"

	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/store/storetest"
)

// The conformance suite always runs against the in-memory reference, so the
// suite itself is checked in CI and every network adapter is held to the
// semantics local development and the unit tests rely on.
func TestMemoryDatabaseConformance(t *testing.T) {
	t.Parallel()
	storetest.RunDocumentDatabase(t, func(t *testing.T) store.DocumentDatabase {
		return store.NewMemoryDatabase()
	}, storetest.UnorderedSubdocuments())
}
