package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func walkCommands(cmd *cobra.Command, visit func(*cobra.Command)) {
	visit(cmd)
	for _, sub := range cmd.Commands() {
		if sub.Name() == "help" || sub.Name() == "completion" {
			continue
		}
		walkCommands(sub, visit)
	}
}

func TestEveryCommandHasLongAndExample(t *testing.T) {
	walkCommands(newRootCmd(), func(c *cobra.Command) {
		if strings.TrimSpace(c.Long) == "" {
			t.Errorf("%s: missing Long help", c.CommandPath())
		}
		if !strings.Contains(c.Example, "pcmd") {
			t.Errorf("%s: missing Example", c.CommandPath())
		}
	})
}

func docSection(doc, path string) string {
	marker := "### `" + path
	for from := 0; ; {
		i := strings.Index(doc[from:], marker)
		if i < 0 {
			return ""
		}
		i += from
		rest := doc[i+len(marker):]
		if rest == "" || (rest[0] != '`' && rest[0] != ' ' && rest[0] != '\n') {
			from = i + len(marker)
			continue
		}
		if j := strings.Index(rest, "\n### "); j >= 0 {
			rest = rest[:j]
		}
		return rest
	}
}

func TestCLIReferenceCoversEveryCommandAndFlag(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "cli-reference.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	root := newRootCmd()

	globals := docSection(doc, "pcmd` global flags")
	if globals == "" {
		t.Fatal("docs: missing the global flags section (### `pcmd` global flags)")
	}
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if !strings.Contains(globals, "`--"+f.Name) {
			t.Errorf("docs: global flag --%s is not in the global flags section", f.Name)
		}
	})

	walkCommands(root, func(c *cobra.Command) {
		path := c.CommandPath()
		section := docSection(doc, path)
		if section == "" {
			t.Errorf("docs: no section for `%s`", path)
			return
		}
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if f.Name == "help" || root.PersistentFlags().Lookup(f.Name) != nil {
				return
			}
			if !strings.Contains(section, "`--"+f.Name) && !strings.Contains(section, "--"+f.Name) {
				t.Errorf("docs: flag --%s of `%s` is not in its section", f.Name, path)
			}
			if f.Shorthand != "" && !strings.Contains(section, "-"+f.Shorthand+"`") && !strings.Contains(section, "`-"+f.Shorthand) {
				t.Errorf("docs: shorthand -%s of --%s (`%s`) is not in its section", f.Shorthand, f.Name, path)
			}
		})
		for _, alias := range c.Aliases {
			if !strings.Contains(section, "`"+alias+"`") {
				t.Errorf("docs: alias %q of `%s` is not mentioned in its section", alias, path)
			}
		}
	})

	known := map[string]bool{"pcmd` global flags": true}
	walkCommands(root, func(c *cobra.Command) { known[c.CommandPath()] = true })
	for _, line := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(line, "### `pcmd") {
			continue
		}
		heading := strings.TrimPrefix(line, "### `")
		if k := strings.Index(heading, "`"); k >= 0 && !strings.HasPrefix(heading, "pcmd` global") {
			heading = heading[:k]
		}
		matched := false
		for path := range known {
			if heading == path || strings.HasPrefix(heading, path+" ") {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("docs: section %q does not match any command", line)
		}
	}
}

func TestCommandAliases(t *testing.T) {
	root := newRootCmd()
	for alias, want := range map[string]string{"invites": "list-invites"} {
		c, _, err := root.Find([]string{alias})
		if err != nil || c.Name() != want {
			t.Errorf("alias %q: got %v (%v), want %s", alias, c, err, want)
		}
	}
}
