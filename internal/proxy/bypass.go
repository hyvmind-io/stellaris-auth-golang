// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 HyvMind.io

package proxy

import (
	"net"
	"strings"
)

// Bypass matches CONNECT targets against NO_PROXY-style patterns. Bypassed
// hosts are always tunneled, never intercepted, even with a credential.
type Bypass struct {
	patterns []string
}

// NewBypass builds a matcher from patterns; each entry may itself be a
// comma-separated list. Entries are trimmed and lowercased; empty ones dropped.
func NewBypass(patterns []string) *Bypass {
	return &Bypass{patterns: SplitHostList(patterns)}
}

// Patterns returns the normalised pattern list.
func (b *Bypass) Patterns() []string {
	if b == nil {
		return nil
	}
	return b.patterns
}

// Match reports whether host ("hostname:port" or bare hostname) is bypassed.
// "*" matches everything; "host:port" matches only that port; ".example.com"
// matches subdomains of example.com; anything else is an exact hostname match.
func (b *Bypass) Match(host string) bool {
	if b == nil || len(b.patterns) == 0 {
		return false
	}
	host = strings.ToLower(host)
	hostname, port, err := net.SplitHostPort(host)
	if err != nil {
		hostname, port = host, ""
	}
	hostname = strings.TrimSuffix(hostname, ".")

	for _, p := range b.patterns {
		if p == "*" {
			return true
		}
		pHost, pPort, err := net.SplitHostPort(p)
		if err != nil {
			pHost, pPort = p, ""
		}
		if pPort != "" && pPort != port {
			continue
		}
		if strings.HasPrefix(pHost, ".") {
			if strings.HasSuffix(hostname, pHost) {
				return true
			}
			continue
		}
		if hostname == pHost {
			return true
		}
	}
	return false
}

// SplitHostList flattens comma-separated entries, trimming, lowercasing and
// dropping empties and duplicates while keeping first-seen order.
func SplitHostList(entries []string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, e := range entries {
		for _, p := range strings.Split(e, ",") {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}
