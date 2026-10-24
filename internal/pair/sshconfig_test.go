package pair

import (
	"os"
	"path/filepath"
	"testing"
)

func sshFixture(t *testing.T, files map[string]string) sshConfigEnv {
	t.Helper()
	home := t.TempDir()
	for name, content := range files {
		p := filepath.Join(home, ".ssh", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return sshConfigEnv{home: home, localUser: "alice"}
}

func hostByName(t *testing.T, hosts []ParsedHost, name string) ParsedHost {
	t.Helper()
	for _, h := range hosts {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("host %q not exported; got %+v", name, hosts)
	return ParsedHost{}
}

func TestSSHConfig_HostStarFillsUnsetValues(t *testing.T) {
	env := sshFixture(t, map[string]string{"id_test": "KEY"})
	raw := "Host web\n  HostName 10.0.0.5\n\nHost *\n  User deploy\n  Port 2200\n  IdentityFile ~/.ssh/id_test\n"
	hosts, keys := parseSSHConfig(raw, env)

	h := hostByName(t, hosts, "web")
	if h.Hostname != "10.0.0.5" || h.Username != "deploy" || h.Port != 2200 {
		t.Fatalf("Host * defaults not applied: %+v", h)
	}
	want := filepath.Join(env.home, ".ssh", "id_test")
	if h.KeyRef != want {
		t.Fatalf("KeyRef = %q, want %q", h.KeyRef, want)
	}
	if len(keys) != 1 || keys[0].Content != "KEY" {
		t.Fatalf("expected the key file to be exported once, got %+v", keys)
	}
}

func TestSSHConfig_FirstValueWins(t *testing.T) {
	env := sshFixture(t, nil)
	hosts, _ := parseSSHConfig("Host *\n  User first\nHost web\n  User second\n", env)
	if h := hostByName(t, hosts, "web"); h.Username != "first" {
		t.Fatalf("Username = %q, want the first obtained value %q", h.Username, "first")
	}
}

func TestSSHConfig_Defaults(t *testing.T) {
	env := sshFixture(t, nil)
	hosts, _ := parseSSHConfig("Host db\n  HostName %h.internal\nHost cache\n", env)

	db := hostByName(t, hosts, "db")
	if db.Hostname != "db.internal" {
		t.Fatalf("%%h not expanded: %q", db.Hostname)
	}
	cache := hostByName(t, hosts, "cache")
	if cache.Hostname != "cache" || cache.Username != "alice" || cache.Port != 22 {
		t.Fatalf("defaults not applied (HostName=alias, User=local user, Port=22): %+v", cache)
	}
}

func TestSSHConfig_IncludeRelativeGlob(t *testing.T) {
	env := sshFixture(t, map[string]string{
		"config.d/a.conf": "Host a\n  HostName a.example\n",
		"config.d/b.conf": "Host b\n  HostName b.example\n",
	})
	hosts, _ := parseSSHConfig("Include config.d/*.conf\nHost c\n", env)
	if len(hosts) != 3 {
		t.Fatalf("expected hosts a, b, c, got %+v", hosts)
	}
	for i, name := range []string{"a", "b", "c"} {
		if hosts[i].Name != name {
			t.Fatalf("hosts[%d] = %q, want %q (glob order, then the main file)", i, hosts[i].Name, name)
		}
	}
	if hostByName(t, hosts, "a").Hostname != "a.example" {
		t.Fatalf("included HostName not applied")
	}
}

func TestSSHConfig_IncludeInsideHostBlockAppliesOnlyThere(t *testing.T) {
	env := sshFixture(t, map[string]string{"extra.conf": "User fromextra\n"})
	hosts, _ := parseSSHConfig("Host x\n  Include extra.conf\nHost y\n", env)
	if h := hostByName(t, hosts, "x"); h.Username != "fromextra" {
		t.Fatalf("include inside Host x not applied to x: %+v", h)
	}
	if h := hostByName(t, hosts, "y"); h.Username != "alice" {
		t.Fatalf("include inside Host x leaked into y: %+v", h)
	}
}

func TestSSHConfig_IncludeFromInactiveBlockNeverMatches(t *testing.T) {
	env := sshFixture(t, map[string]string{"other.conf": "Host *\n  Port 2022\n"})
	hosts, _ := parseSSHConfig("Host x\n  Include other.conf\nHost y\n", env)
	if h := hostByName(t, hosts, "y"); h.Port != 22 {
		t.Fatalf("Host * inside an include under Host x applied to y: %+v", h)
	}
	if h := hostByName(t, hosts, "x"); h.Port != 2022 {
		t.Fatalf("Host * inside an include under Host x should apply to x: %+v", h)
	}
}

func TestSSHConfig_SelfIncludeTerminates(t *testing.T) {
	env := sshFixture(t, map[string]string{"loop.conf": "Include loop.conf\nHost looped\n"})
	hosts, _ := parseSSHConfig("Include loop.conf\n", env)
	if len(hosts) != 1 || hosts[0].Name != "looped" {
		t.Fatalf("expected the looped host once, got %+v", hosts)
	}
}

func TestSSHConfig_PatternListsAndNegation(t *testing.T) {
	env := sshFixture(t, nil)
	raw := "Host web1 web2\n  User team\nHost * !web2\n  Port 2222\nHost !nobody\n"
	hosts, _ := parseSSHConfig(raw, env)
	if len(hosts) != 2 {
		t.Fatalf("only web1 and web2 are concrete aliases, got %+v", hosts)
	}
	if h := hostByName(t, hosts, "web1"); h.Username != "team" || h.Port != 2222 {
		t.Fatalf("web1: %+v", h)
	}
	if h := hostByName(t, hosts, "web2"); h.Username != "team" || h.Port != 22 {
		t.Fatalf("web2 is negated out of the Port block: %+v", h)
	}
}

func TestSSHConfig_WildcardPatterns(t *testing.T) {
	env := sshFixture(t, nil)
	hosts, _ := parseSSHConfig("Host prod-?? \n  User ops\nHost prod-01 prod-100\n", env)
	if h := hostByName(t, hosts, "prod-01"); h.Username != "ops" {
		t.Fatalf("prod-01 should match prod-??: %+v", h)
	}
	if h := hostByName(t, hosts, "prod-100"); h.Username != "alice" {
		t.Fatalf("prod-100 must not match prod-??: %+v", h)
	}
}

func TestSSHConfig_MatchBlocksAreSkipped(t *testing.T) {
	env := sshFixture(t, nil)
	hosts, _ := parseSSHConfig("Match host web\n  User matched\nHost web\n", env)
	if h := hostByName(t, hosts, "web"); h.Username != "alice" {
		t.Fatalf("Match block keywords must not apply: %+v", h)
	}
}

func TestSSHConfig_EqualsQuotesAndComments(t *testing.T) {
	env := sshFixture(t, map[string]string{"my key": "SPACEKEY"})
	raw := "Host q # trailing comment\n  HostName=\"q.example\"\n  Port = 2201\n  IdentityFile \"~/.ssh/my key\"\n"
	hosts, keys := parseSSHConfig(raw, env)
	h := hostByName(t, hosts, "q")
	if h.Hostname != "q.example" || h.Port != 2201 {
		t.Fatalf("key=value / quoted values not parsed: %+v", h)
	}
	if h.KeyRef != filepath.Join(env.home, ".ssh", "my key") || len(keys) != 1 {
		t.Fatalf("quoted IdentityFile with a space not resolved: %+v %+v", h, keys)
	}
}

func TestSSHConfig_IdentityFileTokensAndFirstExisting(t *testing.T) {
	env := sshFixture(t, map[string]string{"bob_t.example": "TOKENKEY"})
	raw := "Host t\n  HostName t.example\n  User bob\n  IdentityFile ~/.ssh/missing\n  IdentityFile %d/.ssh/%r_%h\n"
	hosts, keys := parseSSHConfig(raw, env)
	h := hostByName(t, hosts, "t")
	want := filepath.Join(env.home, ".ssh", "bob_t.example")
	if h.KeyRef != want || len(keys) != 1 || keys[0].Content != "TOKENKEY" {
		t.Fatalf("expected the first existing IdentityFile %q, got %+v %+v", want, h, keys)
	}
}

func TestSSHConfig_NoUserAnywhereSkipsHost(t *testing.T) {
	env := sshFixture(t, nil)
	env.localUser = ""
	hosts, _ := parseSSHConfig("Host a\nHost b\n  User bob\n", env)
	if len(hosts) != 1 || hosts[0].Name != "b" {
		t.Fatalf("a host without any user must not be exported with an empty username: %+v", hosts)
	}
}

func TestSSHPatternMatch(t *testing.T) {
	cases := []struct {
		s, p string
		want bool
	}{
		{"web", "*", true},
		{"web", "w?b", true},
		{"web", "w*", true},
		{"web", "*b", true},
		{"web", "*x*", false},
		{"db.internal", "*.internal", true},
		{"", "*", true},
		{"a", "", false},
	}
	for _, c := range cases {
		if got := sshPatternMatch(c.s, c.p); got != c.want {
			t.Errorf("sshPatternMatch(%q, %q) = %v, want %v", c.s, c.p, got, c.want)
		}
	}
}
