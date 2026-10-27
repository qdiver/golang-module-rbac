package auth

import (
	"sync"
	"testing"
)

func replaceTable(t *testing.T, m map[Role][]Permission) *PermissionTable {
	t.Helper()
	tb, err := NewPermissionTable(m, "users:manage", "boss")
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

func TestReplaceIsSeenByExistingHolders(t *testing.T) {
	live := replaceTable(t, map[Role][]Permission{
		"boss": {"users:manage"},
		"a":    {"x"},
	})
	id := Identity{UserID: "u", Role: "a"}.WithPermissions(live)
	if !id.Can("x") || id.Can("y") {
		t.Fatal("precondition")
	}

	next := replaceTable(t, map[Role][]Permission{
		"boss": {"users:manage"},
		"a":    {"y"},
		"b":    {"x"},
	})
	guarded, err := next.WithRoleGuards(map[Role]Permission{"a": "users:manage", "b": "users:manage", "boss": "users:manage"})
	if err != nil {
		t.Fatal(err)
	}
	if err := live.Replace(guarded); err != nil {
		t.Fatal(err)
	}
	if id.Can("x") || !id.Can("y") {
		t.Fatal("identity resolved before Replace must see the new rules")
	}
	if !live.Valid("b") || !live.Privileged("a") {
		t.Fatal("roles and guards must be replaced too")
	}
}

func TestReplaceRefusesDifferentAnchors(t *testing.T) {
	live := replaceTable(t, map[Role][]Permission{"boss": {"users:manage"}})
	other, err := NewPermissionTable(map[Role][]Permission{"boss": {"users:manage"}, "x": {"m2", "users:manage"}}, "m2", "x")
	if err != nil {
		t.Fatal(err)
	}
	if live.Replace(other) == nil {
		t.Fatal("changing ManageUsers/AdminRole must be refused")
	}
	if live.Replace(nil) == nil || (*PermissionTable)(nil).Replace(live) == nil {
		t.Fatal("nil must be refused")
	}
}

func TestWithOptionsDoNotMutateReceiver(t *testing.T) {
	base := replaceTable(t, map[Role][]Permission{"boss": {"users:manage"}})
	if _, err := base.WithProtectedRoles("boss"); err != nil {
		t.Fatal(err)
	}
	if _, err := base.WithRoleGuards(map[Role]Permission{"boss": "users:manage"}); err != nil {
		t.Fatal(err)
	}
	if base.Privileged("boss") {
		t.Fatal("receiver was modified")
	}
}

func TestReplaceConcurrent(t *testing.T) {
	live := replaceTable(t, map[Role][]Permission{"boss": {"users:manage"}, "a": {"x"}})
	alt := replaceTable(t, map[Role][]Permission{"boss": {"users:manage"}, "a": {"y"}})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				_ = live.Replace(alt)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				live.Can("a", "x")
				live.Roles()
				live.AtMost("a", "boss")
			}
		}()
	}
	wg.Wait()
}
