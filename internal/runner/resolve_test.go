package runner

import (
	"os/exec"
	"slices"
	"testing"
)

// stubAlias swaps the package-level aliasLookup for the duration of a test.
func stubAlias(t *testing.T, table map[string]string) {
	t.Helper()
	orig := aliasLookup
	aliasLookup = func(name string) (string, bool) {
		def, ok := table[name]
		return def, ok
	}
	t.Cleanup(func() { aliasLookup = orig })
}

func TestResolveBinary_directBinary(t *testing.T) {
	// A real binary must resolve via PATH and never consult the alias table.
	stubAlias(t, map[string]string{"sh": "should-not-be-used"})

	want, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not on PATH: %v", err)
	}

	got, prefix, err := resolveBinary("sh", nil)
	if err != nil {
		t.Fatalf("resolveBinary(sh) error: %v", err)
	}
	if got != want {
		t.Errorf("binPath = %q, want %q", got, want)
	}
	if prefix != nil {
		t.Errorf("prefixArgs = %v, want nil for a direct binary", prefix)
	}
}

func TestResolveBinary_simpleAlias(t *testing.T) {
	// "tgsh" is not a binary; alias expands to the real binary "sh".
	stubAlias(t, map[string]string{"tgsh": "sh"})

	want, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh not on PATH: %v", err)
	}

	got, prefix, err := resolveBinary("tgsh", nil)
	if err != nil {
		t.Fatalf("resolveBinary(tgsh) error: %v", err)
	}
	if got != want {
		t.Errorf("binPath = %q, want %q", got, want)
	}
	if len(prefix) != 0 {
		t.Errorf("prefixArgs = %v, want empty", prefix)
	}
}

func TestResolveBinary_aliasWithPrefixArgs(t *testing.T) {
	// alias body contributes leading args that must be returned as the prefix.
	stubAlias(t, map[string]string{"tgsh": "sh -c"})

	_, prefix, err := resolveBinary("tgsh", nil)
	if err != nil {
		t.Fatalf("resolveBinary(tgsh) error: %v", err)
	}
	if want := []string{"-c"}; !slices.Equal(prefix, want) {
		t.Errorf("prefixArgs = %v, want %v", prefix, want)
	}
}

func TestResolveBinary_notFound(t *testing.T) {
	stubAlias(t, map[string]string{}) // no aliases

	_, _, err := resolveBinary("definitely-not-a-real-cmd-xyz", nil)
	if err == nil {
		t.Fatal("resolveBinary: expected error for unknown name, got nil")
	}
}

func TestResolveBinary_aliasToMissingBinary(t *testing.T) {
	stubAlias(t, map[string]string{"tgx": "definitely-not-a-real-cmd-xyz --flag"})

	_, _, err := resolveBinary("tgx", nil)
	if err == nil {
		t.Fatal("resolveBinary: expected error when alias target is missing, got nil")
	}
}

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"terragrunt", []string{"terragrunt"}},
		{"terragrunt run --all", []string{"terragrunt", "run", "--all"}},
		{"  terraform   plan  ", []string{"terraform", "plan"}},
		{`terragrunt run "--working-dir=a b"`, []string{"terragrunt", "run", "--working-dir=a b"}},
		{`tofu 'plan -x'`, []string{"tofu", "plan -x"}},
	}
	for _, tt := range tests {
		if got := splitArgs(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("splitArgs(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseAliasOutputViaUnquote(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"terragrunt", "terragrunt"},
		{"'terragrunt run'", "terragrunt run"},
		{`"terragrunt run"`, "terragrunt run"},
		{"''", ""},
	}
	for _, tt := range tests {
		if got := unquote(tt.in); got != tt.want {
			t.Errorf("unquote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseAliasDefinition(t *testing.T) {
	// Real iTerm2 shell-integration noise captured from `zsh -ic 'alias tg'`:
	// three OSC sequences glued directly before the alias output.
	const osc = "\x1b]1337;RemoteHost=user@host\x07" +
		"\x1b]1337;CurrentDir=/x\x07" +
		"\x1b]1337;ShellIntegrationVersion=14;shell=zsh\x07"

	tests := []struct {
		name   string
		raw    string
		alias  string
		want   string
		wantOK bool
	}{
		{"zsh plain", "tg=terragrunt\n", "tg", "terragrunt", true},
		{"bash prefixed", "alias tg='terragrunt'\n", "tg", "terragrunt", true},
		{"zsh with shell-integration noise", osc + "tg=terragrunt\n", "tg", "terragrunt", true},
		{"alias with prefix args", "tgall='terragrunt run --all'\n", "tgall", "terragrunt run --all", true},
		{"word boundary: tf must not match setf", "setf=other\n", "tf", "", false},
		{"missing", "\n", "tg", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clean := shellNoise.ReplaceAllString(tt.raw, "")
			got, ok := parseAliasDefinition(clean, tt.alias)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("parseAliasDefinition(%q, %q) = (%q, %v), want (%q, %v)",
					tt.raw, tt.alias, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
