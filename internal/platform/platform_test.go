package platform

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/botmux-ai/botmux-platform/internal/store"
)

func TestEnvironmentEnabledIsFailClosed(t *testing.T) {
	const key = "BOTMUX_TEST_ENVIRONMENT_ENABLED"

	t.Setenv(key, "")
	if environmentEnabled(key, false) {
		t.Fatal("empty value should use false fallback")
	}
	if !environmentEnabled(key, true) {
		t.Fatal("empty value should use true fallback")
	}

	for _, value := range []string{"1", "true", "ON", " yes "} {
		t.Setenv(key, value)
		if !environmentEnabled(key, false) {
			t.Fatalf("%q should explicitly enable", value)
		}
	}
	for _, value := range []string{"0", "false", "OFF", "no", "enabled", "typo"} {
		t.Setenv(key, value)
		if environmentEnabled(key, true) {
			t.Fatalf("%q should fail closed", value)
		}
	}
}

func TestNewFromEnvironmentRejectsIncompleteProductionConfiguration(t *testing.T) {
	t.Setenv("NODE_ENV", "production")
	for _, key := range []string{
		"SIGNING_SECRET", "PUBLIC_BASE_URL", "PORT0", "MY_HOST_IP", "MY_HOST_IPV6",
		"FEISHU_APP_ID", "FEISHU_APP_SECRET",
	} {
		t.Setenv(key, "")
	}
	_, err := NewFromEnvironment(Drivers{})
	if err == nil || !strings.Contains(err.Error(), "validate production configuration") || !strings.Contains(err.Error(), "SIGNING_SECRET") {
		t.Fatalf("NewFromEnvironment() error = %v", err)
	}
}

func TestInitializeDocumentRepositoryFailsClosed(t *testing.T) {
	repository, err := initializeDocumentRepository(context.Background(), store.StaticDatabaseProvider{})
	if repository != nil || !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("initializeDocumentRepository() = (%v, %v)", repository, err)
	}
}

func TestStatusWriteFailureIsReturned(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("file"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &App{statusPath: filepath.Join(blocker, "status")}
	if err := app.MarkReady(); err == nil || !strings.Contains(err.Error(), "create status directory") {
		t.Fatalf("MarkReady() error = %v", err)
	}
}

func TestStatusTransitionsArePersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "statusz", "botmux-platform")
	app := &App{statusPath: path}
	if err := app.MarkNotReady(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "not_ready" {
		t.Fatalf("not-ready status = %q, %v", got, err)
	}
	if err := app.MarkReady(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "ready" {
		t.Fatalf("ready status = %q, %v", got, err)
	}
}
