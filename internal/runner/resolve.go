package runner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// shellNoise matches terminal escape sequences that an interactive shell's
// startup hooks (e.g. iTerm2 / VS Code shell integration) write to stdout
// alongside our command output. It covers OSC sequences (ESC ] … BEL|ST) and
// CSI sequences (ESC [ … final byte). Stripping these leaves only the real
// `alias` output for parsing.
var shellNoise = regexp.MustCompile("\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)?" +
	"|\x1b\\[[0-9;?]*[ -/]*[@-~]")

// aliasLookup resolves a name to its shell-alias definition (e.g. "tg" ->
// "terragrunt run --all"). It returns ok=false when the name is not a known
// alias. It is a package variable so tests can stub out the shell call.
var aliasLookup = shellAliasLookup

// resolveBinary turns the user-supplied command name into an executable path
// plus any leading arguments contributed by a shell alias.
//
// Resolution order:
//  1. exec.LookPath(name) — a real binary, symlink, or script on PATH
//     (terragrunt, terraform, tofu, or a wrapper the user dropped in PATH).
//  2. The user's interactive shell alias table, queried via $SHELL -ic
//     'alias <name>'. An alias like `tg='terragrunt run --all'` resolves to
//     binary "terragrunt" with prefix args ["run", "--all"], which are
//     prepended to the user's own args — matching real alias-expansion order.
//
// The returned prefixArgs is nil for a direct binary hit.
func resolveBinary(name string, logger *slog.Logger) (binPath string, prefixArgs []string, err error) {
	if p, lookErr := exec.LookPath(name); lookErr == nil {
		return p, nil, nil
	}

	def, ok := aliasLookup(name)
	if ok {
		tokens := splitArgs(def)
		if len(tokens) > 0 {
			if p, lookErr := exec.LookPath(tokens[0]); lookErr == nil {
				if logger != nil {
					logger.Debug("resolved shell alias",
						slog.String("alias", name),
						slog.String("expansion", def),
						slog.String("binary", p),
					)
				}
				return p, tokens[1:], nil
			}
			return "", nil, fmt.Errorf(
				"runner: alias %q expands to %q, but %q was not found in PATH",
				name, def, tokens[0])
		}
	}

	return "", nil, fmt.Errorf("runner: binary %q not found in PATH "+
		"(also checked for a matching shell alias)", name)
}

// shellAliasLookup asks the user's login shell to expand a single alias. It
// runs `$SHELL -ic 'alias <name>'` so the shell sources its rc files (where
// aliases live) before reporting. Supports bash- and zsh-style output:
//
//	zsh:  tg='terragrunt run --all'
//	bash: alias tg='terragrunt run --all'
//
// Returns ok=false when SHELL is unset, the shell errors, or the name is not an
// alias. A 3s timeout guards against an rc file that blocks on input.
func shellAliasLookup(name string) (definition string, ok bool) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		return "", false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Single-quote the name so shell metacharacters in it cannot break out of
	// the `alias` argument; embedded single quotes are escaped the POSIX way.
	cmd := exec.CommandContext(ctx, shell, "-i", "-c", "alias "+singleQuote(name))
	out, err := cmd.Output() // stdout only; most interactive noise goes to stderr
	if err != nil {
		return "", false
	}

	// Interactive shells may still emit terminal escape sequences to stdout
	// (shell-integration markers); strip them before parsing.
	clean := shellNoise.ReplaceAllString(string(out), "")
	return parseAliasDefinition(clean, name)
}

// parseAliasDefinition extracts an alias body from cleaned `alias <name>`
// output. It accepts both zsh (`tg=terragrunt`) and bash (`alias tg='...'`)
// formats by locating the `<name>=` assignment at a word boundary, then
// unquoting the remainder of that line.
func parseAliasDefinition(out, name string) (string, bool) {
	token := name + "="
	for raw := range strings.SplitSeq(out, "\n") {
		line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "alias "))
		idx := strings.Index(line, token)
		if idx < 0 {
			continue
		}
		// Require a word boundary before the name so "tf=" doesn't match
		// inside "setf=".
		if idx > 0 && isWordByte(line[idx-1]) {
			continue
		}
		if def := unquote(line[idx+len(token):]); def != "" {
			return def, true
		}
	}
	return "", false
}

// isWordByte reports whether b is an identifier character (alias names are
// drawn from this set).
func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9')
}

// singleQuote wraps s in single quotes for safe inclusion in a shell command,
// escaping any embedded single quotes via the '\'' idiom.
func singleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// unquote strips one layer of matching surrounding single or double quotes.
func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// splitArgs performs a minimal shell-style split of an alias body into tokens,
// honoring single- and double-quoted spans so that values like
// `terragrunt run "--working-dir=a b"` tokenize correctly. It does not attempt
// full POSIX word expansion — aliases used as command prefixes don't need it.
func splitArgs(s string) []string {
	var tokens []string
	var cur strings.Builder
	var quote rune // 0, '\'' or '"'
	inToken := false

	flush := func() {
		if inToken {
			tokens = append(tokens, cur.String())
			cur.Reset()
			inToken = false
		}
	}

	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inToken = true
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
			inToken = true
		}
	}
	flush()
	return tokens
}
