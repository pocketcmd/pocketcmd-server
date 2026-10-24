package pair

func ParseSSHConfigString(raw string) ([]ParsedHost, []ParsedKey) {
	return parseSSHConfig(raw, defaultSSHConfigEnv())
}
