package configuration

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestCodexTOMLStringAndKeyForms(t *testing.T) {
	target := "http://127.0.0.1:18080/r/fixture"
	tests := []struct{ name, input, previous string }{
		{"literal", "openai_base_url = 'https://upstream.example/v1' # keep\nmodel = 'fixture'\n", "https://upstream.example/v1"},
		{"quoted key", "'openai_base_url' = 'https://upstream.example/v1'\r\n", "https://upstream.example/v1"},
		{"provider quoted section", "'model_provider' = 'foo.bar'\n[model_providers.'foo.bar']\n\"base_url\" = 'https://upstream.example/v1' # keep\napi_key='not-exported'\n", "https://upstream.example/v1"},
		{"dotted key", "model_provider='custom'\nmodel_providers.custom.base_url='https://upstream.example/v1'\n", "https://upstream.example/v1"},
		{"inline table", "model_provider='custom'\nmodel_providers={custom={base_url='https://upstream.example/v1', api_key='fixture'}}\n", "https://upstream.example/v1"},
		{"multiline", "openai_base_url = '''https://upstream.example/v1''' # keep\n", "https://upstream.example/v1"},
		{"escaped unicode", "openai_base_url = \"https://upstream.example/\\u0076\\u0031\"\n", "https://upstream.example/v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, e := Codex([]byte(tt.input), target, false)
			if e != nil || got.Previous != tt.previous {
				t.Fatal(got, e)
			}
			var parsed map[string]any
			if e = toml.Unmarshal(got.Content, &parsed); e != nil {
				t.Fatal(e)
			}
			if strings.Contains(tt.input, "# keep") && !bytes.Contains(got.Content, []byte("# keep")) {
				t.Fatal("comment lost")
			}
			again, e := Codex(got.Content, target, false)
			if e != nil || again.Changed || !bytes.Equal(again.Content, got.Content) {
				t.Fatal("not idempotent", e)
			}
			restored, e := Codex(got.Content, tt.previous, true)
			if e != nil || restored.Previous != target {
				t.Fatal("restore", e)
			}
		})
	}
}

func TestCodexRejectsInvalidBeforeWriting(t *testing.T) {
	inputs := []string{
		"openai_base_url='https://one.example'\nopenai_base_url=\"https://two.example\"\n",
		"openai_base_url=true\n", "model_provider=42\n",
		"openai_base_url = 'unterminated\n",
	}
	// Explicit provider forms ensure wrong field types cannot look absent.
	inputs = append(inputs, "model_provider='custom'\n[model_providers.custom]\nbase_url=123\n", "model_provider='custom'\nmodel_providers.custom=[]\n")
	for _, input := range inputs {
		if _, e := Codex([]byte(input), "http://127.0.0.1:18080/r/f", false); e == nil {
			t.Fatalf("accepted %q", input)
		}
	}
	m, p := fixtureManager(t)
	path := configPath(p, "codex")
	original := "openai_base_url='https://one.example'\nopenai_base_url='https://two.example'\n"
	writeFixture(t, path, original)
	if _, e := m.Reconcile(context.Background(), []Profile{p}); e == nil {
		t.Fatal("invalid config accepted")
	}
	got, e := os.ReadFile(path)
	if e != nil || string(got) != original {
		t.Fatal("file changed", e)
	}
	if backups, _ := filepath.Glob(filepath.Join(m.BackupRoot, "*")); len(backups) > 0 {
		t.Fatal("invalid config was written")
	}
}

func TestCodexModelDiscoveryUsesTOML(t *testing.T) {
	if got := inspectModel("codex", []byte("'model' = 'fixture-model'\n"), false); got != "fixture-model" {
		t.Fatal(got)
	}
}
