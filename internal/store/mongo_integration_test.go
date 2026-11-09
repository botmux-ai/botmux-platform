package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/store/storetest"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Integration tests against a real MongoDB through the official driver
// adapter (store.NewMongoDatabaseProvider). They run only when
// BOTMUX_TEST_MONGODB_URI is set, e.g.
//
//	BOTMUX_TEST_MONGODB_URI=mongodb://127.0.0.1:27017 go test ./internal/store/ -run Mongo
//
// Every subtest uses its own database, dropped afterwards.

func mongoTestURI(t *testing.T) string {
	t.Helper()
	uri := os.Getenv("BOTMUX_TEST_MONGODB_URI")
	if uri == "" {
		t.Skip("BOTMUX_TEST_MONGODB_URI not set")
	}
	return uri
}

func uniqueTestName(prefix string) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}

// newMongoTestDatabase connects a fresh provider to a unique database and,
// when the test ends, closes it and drops the database with a separate
// client.
func newMongoTestDatabase(t *testing.T, uri string) store.DocumentDatabase {
	t.Helper()
	name := uniqueTestName("botmux_it")
	provider := store.NewMongoDatabaseProvider(uri, name)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	db, err := provider.Database(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		if err := provider.Close(); err != nil {
			t.Errorf("close provider: %v", err)
		}
		dropMongoDatabase(t, uri, name)
	})
	return db
}

func dropMongoDatabase(t *testing.T, uri, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Errorf("connect for cleanup: %v", err)
		return
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	if err := client.Database(name).Drop(ctx); err != nil {
		t.Errorf("drop %s: %v", name, err)
	}
}

func TestMongoDatabaseConformance(t *testing.T) {
	uri := mongoTestURI(t)
	newMongoTestDatabase(t, uri) // fail once, fast, when the server is unreachable
	storetest.RunDocumentDatabase(t, func(t *testing.T) store.DocumentDatabase {
		return newMongoTestDatabase(t, uri)
	})
}

func TestMongoDatabaseSharedAcrossRepositories(t *testing.T) {
	uri := mongoTestURI(t)
	db := newMongoTestDatabase(t, uri)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Two repositories (two pods) over one database observe each other's
	// writes: the cross-pod authority is the database, not process memory.
	podA := store.NewDocumentRepository(store.StaticDatabaseProvider{DB: db})
	podB := store.NewDocumentRepository(store.StaticDatabaseProvider{DB: db})
	if got, err := podA.BindMachineCAS(ctx, "m-shared", "u1", "Alice"); err != nil || got != store.BindCreated {
		t.Fatalf("pod A bind = %s %v", got, err)
	}
	if got, err := podB.BindMachineCAS(ctx, "m-shared", "u2", "Bob"); err != nil || got != store.BindConflictOwner {
		t.Fatalf("pod B bind = %s %v", got, err)
	}
	if err := podB.RetireMachine(ctx, "m-shared"); err != nil {
		t.Fatal(err)
	}
	if doc, err := podA.LookupMachine(ctx, "m-shared", store.AuthorityCacheOptions{}); err != nil || !doc.Retired() {
		t.Fatalf("pod A sees %+v %v", doc, err)
	}
}
