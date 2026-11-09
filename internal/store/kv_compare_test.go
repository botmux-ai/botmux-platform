package store

import (
	"context"
	"errors"
	"testing"
)

func TestCompareThenDelete(t *testing.T) {
	t.Parallel()
	boom := errors.New("boom")
	cases := []struct {
		name       string
		stored     string
		getErr     error
		delErr     error
		wantOK     bool
		wantErr    error
		wantDelete bool
	}{
		{name: "match deletes", stored: "pod-a", wantOK: true, wantDelete: true},
		{name: "mismatch keeps", stored: "pod-b"},
		{name: "missing key", getErr: ErrKeyNotFound},
		{name: "get error", getErr: boom, wantErr: boom},
		{name: "delete error", stored: "pod-a", delErr: boom, wantErr: boom, wantDelete: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			deleted := false
			get := func(_ context.Context, key string) (string, error) {
				if key != "k" {
					t.Fatalf("get key %q", key)
				}
				return tc.stored, tc.getErr
			}
			del := func(_ context.Context, key string) error {
				if key != "k" {
					t.Fatalf("delete key %q", key)
				}
				deleted = true
				return tc.delErr
			}
			ok, err := CompareThenDelete(context.Background(), "k", "pod-a", get, del)
			if ok != tc.wantOK || !errors.Is(err, tc.wantErr) || deleted != tc.wantDelete {
				t.Fatalf("ok=%v err=%v deleted=%v; want ok=%v err=%v deleted=%v", ok, err, deleted, tc.wantOK, tc.wantErr, tc.wantDelete)
			}
		})
	}
}
