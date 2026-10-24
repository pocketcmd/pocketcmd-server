package pair

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

type ParsedHost struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Username string `json:"username,omitempty"`
	Port     int    `json:"port"`
	KeyRef   string `json:"keyRef,omitempty"`
}

type ParsedKey struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// maxSSHIncludeDepth matches OpenSSH's READCONF_MAX_DEPTH.
const maxSSHIncludeDepth = 16

type sshConfigEnv struct {
	home      string
	localUser string
}

func defaultSSHConfigEnv() sshConfigEnv {
	home, _ := os.UserHomeDir()
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	if name == "" {
		name = os.Getenv("USER")
	}
	if name == "" {
		name = os.Getenv("LOGNAME")
	}
	return sshConfigEnv{home: home, localUser: name}
}

type sshConfigLine struct {
	keyword  string // lower-cased
	args     []string
	included [][]sshConfigLine
}

// First value wins for every option except IdentityFile, which accumulates.
type sshHostOptions struct {
	hostname      string
	user          string
	port          int
	identityFiles []string
}

func ParseSSHConfig() ([]ParsedHost, []ParsedKey) {
	env := defaultSSHConfigEnv()
	data, err := os.ReadFile(filepath.Join(env.home, ".ssh", "config"))
	if err != nil {
		return nil, nil
	}
	return parseSSHConfig(string(data), env)
}

func parseSSHConfig(raw string, env sshConfigEnv) ([]ParsedHost, []ParsedKey) {
	lines := loadSSHConfigLines(raw, env, 0)

	var hosts []ParsedHost
	var keys []ParsedKey
	keySet := make(map[string]bool)
	for _, alias := range collectSSHAliases(lines, nil, make(map[string]bool)) {
		var opts sshHostOptions
		applySSHConfig(lines, alias, true, false, &opts)

		h := ParsedHost{
			Name:     alias,
			Hostname: expandSSHTokens(opts.hostname, map[byte]string{'h': alias}),
			Username: opts.user,
			Port:     opts.port,
		}
		if h.Hostname == "" {
			h.Hostname = alias
		}
		if h.Username == "" {
			h.Username = env.localUser
		}
		if h.Username == "" {
			continue
		}
		if h.Port == 0 {
			h.Port = 22
		}

		for _, f := range opts.identityFiles {
			path := expandSSHPath(f, env, map[byte]string{
				'd': env.home,
				'u': env.localUser,
				'h': h.Hostname,
				'n': alias,
				'r': h.Username,
				'p': strconv.Itoa(h.Port),
			})
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			h.KeyRef = path
			if !keySet[path] {
				keySet[path] = true
				keys = append(keys, ParsedKey{Path: path, Content: string(content)})
			}
			break
		}
		hosts = append(hosts, h)
	}
	return hosts, keys
}

func loadSSHConfigLines(raw string, env sshConfigEnv, depth int) []sshConfigLine {
	var lines []sshConfigLine
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		keyword, args, ok := splitSSHConfigLine(scanner.Text())
		if !ok {
			continue
		}
		line := sshConfigLine{keyword: keyword, args: args}
		if keyword == "include" && depth < maxSSHIncludeDepth {
			for _, arg := range args {
				pattern := expandSSHPath(arg, env, nil)
				if !filepath.IsAbs(pattern) {
					pattern = filepath.Join(env.home, ".ssh", pattern)
				}
				matches, _ := filepath.Glob(pattern)
				for _, m := range matches {
					data, err := os.ReadFile(m)
					if err != nil {
						continue
					}
					line.included = append(line.included, loadSSHConfigLines(string(data), env, depth+1))
				}
			}
		}
		lines = append(lines, line)
	}
	return lines
}

func splitSSHConfigLine(raw string) (keyword string, args []string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s[0] == '#' {
		return "", nil, false
	}
	end := strings.IndexAny(s, " \t=")
	if end < 0 {
		return strings.ToLower(s), nil, true
	}
	keyword = strings.ToLower(s[:end])
	rest := strings.TrimLeft(s[end:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}

	var cur strings.Builder
	inArg := false
	var quote byte
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
			inArg = true
		case c == ' ' || c == '\t':
			if inArg {
				args = append(args, cur.String())
				cur.Reset()
				inArg = false
			}
		case c == '#' && !inArg:
			return keyword, args, true
		default:
			cur.WriteByte(c)
			inArg = true
		}
	}
	if inArg {
		args = append(args, cur.String())
	}
	return keyword, args, true
}

func collectSSHAliases(lines []sshConfigLine, aliases []string, seen map[string]bool) []string {
	for _, l := range lines {
		switch l.keyword {
		case "host":
			for _, p := range l.args {
				if p == "" || strings.HasPrefix(p, "!") || strings.ContainsAny(p, "*?") {
					continue
				}
				if key := strings.ToLower(p); !seen[key] {
					seen[key] = true
					aliases = append(aliases, p)
				}
			}
		case "include":
			for _, inc := range l.included {
				aliases = collectSSHAliases(inc, aliases, seen)
			}
		}
	}
	return aliases
}

// never marks an Include reached from an inactive block, whose Host lines can never apply either.
func applySSHConfig(lines []sshConfigLine, alias string, active, never bool, opts *sshHostOptions) {
	for _, l := range lines {
		switch l.keyword {
		case "host":
			active = !never && sshHostMatches(alias, l.args)
		case "match":
			active = false
		case "include":
			for _, inc := range l.included {
				applySSHConfig(inc, alias, active, never || !active, opts)
			}
		default:
			if active && len(l.args) > 0 {
				opts.set(l.keyword, l.args[0])
			}
		}
	}
}

func (o *sshHostOptions) set(keyword, value string) {
	switch keyword {
	case "hostname":
		if o.hostname == "" {
			o.hostname = value
		}
	case "user":
		if o.user == "" {
			o.user = value
		}
	case "port":
		if o.port == 0 {
			if p, err := strconv.Atoi(value); err == nil && p > 0 && p <= 65535 {
				o.port = p
			}
		}
	case "identityfile":
		o.identityFiles = append(o.identityFiles, value)
	}
}

func sshHostMatches(alias string, patterns []string) bool {
	alias = strings.ToLower(alias)
	matched := false
	for _, p := range patterns {
		negated := strings.HasPrefix(p, "!")
		if negated {
			p = p[1:]
		}
		if sshPatternMatch(alias, strings.ToLower(p)) {
			if negated {
				return false
			}
			matched = true
		}
	}
	return matched
}

func sshPatternMatch(s, pattern string) bool {
	si, pi := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			si++
			pi++
		case pi < len(pattern) && pattern[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func expandSSHPath(path string, env sshConfigEnv, tokens map[byte]string) string {
	if path == "~" {
		path = env.home
	} else if strings.HasPrefix(path, "~/") {
		path = filepath.Join(env.home, path[2:])
	}
	return expandSSHTokens(path, tokens)
}

func expandSSHTokens(s string, tokens map[byte]string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		next := s[i+1]
		if next == '%' {
			b.WriteByte('%')
			i++
			continue
		}
		if v, ok := tokens[next]; ok {
			b.WriteString(v)
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
