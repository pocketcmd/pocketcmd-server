package datasync

import "testing"

func TestListVaults_CountsMembersPerVault(t *testing.T) {
	s := NewSyncStoreAt(t.TempDir())
	if got, err := s.ListVaults(); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	for _, g := range []struct {
		vault, user string
	}{{"v-b", "u1"}, {"v-a", "u1"}, {"v-a", "u2"}, {"v-a", "u3"}} {
		if err := s.GrantVault(g.vault, g.user, LevelView); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListVaults()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].VaultID != "v-a" || got[0].Members != 3 || got[1].VaultID != "v-b" || got[1].Members != 1 {
		t.Fatalf("got %+v", got)
	}
	if err := s.RevokeVault("v-b", "u1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListVaults(); len(got) != 1 {
		t.Fatalf("a vault without members disappears: %+v", got)
	}
}
