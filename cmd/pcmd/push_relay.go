package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
)

// The relay is deliberately not a setting: the app registers with the hosted relay, so no other relay could deliver.
const pushRelayEnv = "PCMD_PUSH_RELAY_URL"

func pushRelayURL(logger *slog.Logger) string {
	raw, set := os.LookupEnv(pushRelayEnv)
	if !set || strings.TrimSpace(raw) == "" {
		return config.DefaultPushRelayURL
	}
	relay, err := validateRelayURL(raw)
	if err != nil {
		logger.Warn("[push] ignoring invalid "+pushRelayEnv+"; using the hosted relay",
			"err", err, "relay", config.DefaultPushRelayURL)
		return config.DefaultPushRelayURL
	}
	logger.Warn("[push] non-default push relay in use ("+pushRelayEnv+"); development only",
		"relay", relay)
	return relay
}

// Every /notify call carries bearer-equivalent push tokens, so plain http is allowed only for a loopback host.
func validateRelayURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("relay must be an absolute https URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("relay must not carry credentials, a query, or a fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", fmt.Errorf("relay must use https (http is allowed only for localhost)")
		}
	default:
		return "", fmt.Errorf("relay must use https")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
