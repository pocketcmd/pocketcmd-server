package main

import "fmt"

func pairURL(host string, port int, token, serverFP string) string {
	return fmt.Sprintf("pocketcmd://%s/%s#%s", hostPort(host, port), token, serverFP)
}

func syncURL(host string, port int, token, serverFP string) string {
	return fmt.Sprintf("pocketcmd://ssh-sync?host=%s&port=%d&token=%s#%s", queryHost(host), port, token, serverFP)
}

func inviteURL(host string, port int, code, serverFP string) string {
	return fmt.Sprintf("pocketcmd://invite?host=%s&port=%d&code=%s#%s", queryHost(host), port, code, serverFP)
}

func shortFP(fp string) string {
	if len(fp) > 12 {
		return fp[:12] + "..."
	}
	return fp
}
