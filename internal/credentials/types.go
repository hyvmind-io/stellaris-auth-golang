package credentials

import (
	"sort"
	"strings"
)

// Credential holds a single registry host → token pair.
type Credential struct {
	Hostname string
	Token    string
}

// CredentialStore is a priority-merged map of hostname → token.
// The zero value is NOT usable; use New().
type CredentialStore struct {
	creds map[string]string
}

// New creates an empty CredentialStore.
func New() *CredentialStore {
	return &CredentialStore{creds: make(map[string]string)}
}

// Set adds or replaces the token for hostname.
// Hostname is normalized to lowercase for case-insensitive matching.
func (cs *CredentialStore) Set(hostname, token string) {
	cs.creds[strings.ToLower(hostname)] = token
}

// Lookup returns the token for hostname (case-insensitive).
// Returns ("", false) if not found.
func (cs *CredentialStore) Lookup(hostname string) (token string, found bool) {
	token, found = cs.creds[strings.ToLower(hostname)]
	return
}

// Hostnames returns a sorted slice of all configured hostnames.
func (cs *CredentialStore) Hostnames() []string {
	hosts := make([]string, 0, len(cs.creds))
	for h := range cs.creds {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// Len returns the number of credential entries.
func (cs *CredentialStore) Len() int {
	return len(cs.creds)
}
