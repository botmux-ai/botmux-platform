// Package storetest is a conformance suite for store.DocumentDatabase
// implementations. It pins the Mongo semantics the platform repositories rely
// on (filters, update operators, CAS/upsert results, unique indexes, error
// normalization and decoding into the custom BSON types) and then drives the
// real repositories (DocumentRepository, CredentialStore, IssueStore) on top of
// the database under test.
//
// The suite runs against store.NewMemoryDatabase in every `go test` run, so a
// network adapter that passes it behaves like the in-memory reference used by
// local development and the unit tests:
//
//	storetest.RunDocumentDatabase(t, func(t *testing.T) store.DocumentDatabase {
//		return newIsolatedDatabase(t) // empty, cleaned up via t.Cleanup
//	})
package storetest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/store"
)

// NewDatabase returns an empty, isolated database for one subtest. It must
// register its own cleanup (drop/close) with t.Cleanup.
type NewDatabase func(t *testing.T) store.DocumentDatabase

// RunDocumentDatabase runs the whole conformance suite. Every subtest gets a
// fresh database from newDB.
func RunDocumentDatabase(t *testing.T, newDB NewDatabase, opts ...Option) {
	t.Helper()
	t.Run("Collection", func(t *testing.T) { RunCollection(t, newDB, opts...) })
	t.Run("Repository", func(t *testing.T) { RunRepository(t, newDB, opts...) })
}

// Option relaxes a check for a reference implementation.
type Option func(*config)

type config struct{ unorderedSubdocuments bool }

// UnorderedSubdocuments skips the stored field-order assertions. Only
// store.MemoryDatabase needs it: it keeps documents as Go maps, so embedded
// document field order (e.g. IssueCustomFields) is not preserved. Real
// MongoDB adapters must not use it.
func UnorderedSubdocuments() Option { return func(c *config) { c.unorderedSubdocuments = true } }

func newConfig(opts []Option) config {
	var c config
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// provider is a plain always-available provider over the database under
// test. Unlike store.StaticDatabaseProvider it is never classified as memory
// mode, so the credential/issue stores behave as in production.
type provider struct{ db store.DocumentDatabase }

func (p provider) Database(context.Context) (store.DocumentDatabase, error) { return p.db, nil }

// clock is a settable test clock.
type clock struct{ now time.Time }

func newClock() *clock                   { return &clock{now: time.UnixMilli(1_760_000_000_000).UTC()} }
func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }
func (c *clock) ms() int64               { return c.now.UnixMilli() }
func testContext(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func must(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func wantErr(t *testing.T, err, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: err = %v, want %v", what, err, want)
	}
}

func wantEqual(t *testing.T, got, want any, what string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s:\n got  %#v\n want %#v", what, got, want)
	}
}

func sortedStrings(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

func describe(v any) string { return fmt.Sprintf("%+v", v) }
