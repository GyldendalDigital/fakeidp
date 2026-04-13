package main

import (
	"path/filepath"
	"testing"
)

func TestDistributeCount(t *testing.T) {
	t.Parallel()

	counts := distributeCount(10, 3)
	want := []int{4, 3, 3}
	if len(counts) != len(want) {
		t.Fatalf("len(counts)=%d want %d", len(counts), len(want))
	}
	total := 0
	for i := range counts {
		total += counts[i]
		if counts[i] != want[i] {
			t.Fatalf("counts[%d]=%d want %d", i, counts[i], want[i])
		}
	}
	if total != 10 {
		t.Fatalf("total=%d want 10", total)
	}
}

func TestSaveAndLoadUserState(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "users.json")
	users := map[string]map[string]any{
		"user-1": {
			"sub":                "user-1",
			"name":               "Alice Example",
			"email":              "alice@example.test",
			"email_verified":     true,
			"preferred_username": "alice",
		},
		"user-2": {
			"name":  "Bob Example",
			"email": "bob@example.test",
		},
	}

	if err := saveUserState(path, users); err != nil {
		t.Fatalf("saveUserState: %v", err)
	}

	loaded, err := loadUserState(path)
	if err != nil {
		t.Fatalf("loadUserState: %v", err)
	}

	if len(loaded) != len(users) {
		t.Fatalf("len(loaded)=%d want %d", len(loaded), len(users))
	}
	if got := loaded["user-1"]["email"]; got != "alice@example.test" {
		t.Fatalf("user-1 email=%v want %q", got, "alice@example.test")
	}
	if got := loaded["user-2"]["sub"]; got != "user-2" {
		t.Fatalf("user-2 sub=%v want %q", got, "user-2")
	}
}
