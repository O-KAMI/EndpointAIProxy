// Package configuration changes only documented agent BaseURL fields.
package configuration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
	"strings"
	"unicode/utf8"
)

type MutationError struct{ Code string }

func (e *MutationError) Error() string { return e.Code }
func problem(code string) error        { return &MutationError{Code: code} }

type Transform struct {
	Content            []byte
	Previous, Injected string
	Changed            bool
}

func validateTarget(target string, remote bool) error {
	u, e := url.Parse(target)
	if e != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return problem("INJECTED_BASE_URL_INVALID")
	}
	ip := net.ParseIP(u.Hostname())
	if !remote && (u.Scheme != "http" || !(strings.EqualFold(u.Hostname(), "localhost") || ip != nil && ip.IsLoopback())) {
		return problem("INJECTED_BASE_URL_INVALID")
	}
	return nil
}
func Claude(content []byte, target string, remote bool) (Transform, error) {
	if e := validateTarget(target, remote); e != nil {
		return Transform{}, e
	}
	target = strings.TrimRight(target, "/")
	root := map[string]json.RawMessage{}
	if len(content) > 0 {
		if e := json.Unmarshal(bytes.TrimPrefix(content, []byte{239, 187, 191}), &root); e != nil || root == nil {
			return Transform{}, problem("CLAUDE_SETTINGS_PARSE_FAILED")
		}
	}
	env := map[string]json.RawMessage{}
	if b, ok := root["env"]; ok && string(b) != "null" {
		if e := json.Unmarshal(b, &env); e != nil || env == nil {
			return Transform{}, problem("CLAUDE_SETTINGS_ENV_INVALID")
		}
	}
	previous := ""
	if b, ok := env["ANTHROPIC_BASE_URL"]; ok && string(b) != "null" {
		if e := json.Unmarshal(b, &previous); e != nil {
			return Transform{}, problem("CLAUDE_BASE_URL_TYPE_INVALID")
		}
	}
	if previous == target {
		return Transform{content, previous, target, false}, nil
	}
	env["ANTHROPIC_BASE_URL"], _ = json.Marshal(target)
	root["env"], _ = json.Marshal(env)
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if e := enc.Encode(root); e != nil {
		return Transform{}, e
	}
	return Transform{out.Bytes(), previous, target, true}, nil
}

// Codex validates the complete document before locating the selected URL. The
// parser's decoded key paths handle quoted/dotted keys and literal strings;
// only the selected value's byte range changes, preserving the user's layout.
func Codex(content []byte, target string, remote bool) (Transform, error) {
	if e := validateTarget(target, remote); e != nil {
		return Transform{}, e
	}
	if !utf8.Valid(content) {
		return Transform{}, problem("CODEX_CONFIG_ENCODING_INVALID")
	}
	var doc map[string]any
	if e := toml.Unmarshal(content, &doc); e != nil {
		return Transform{}, problem("CODEX_CONFIG_PARSE_FAILED")
	}
	target = strings.TrimRight(target, "/")
	provider := ""
	if v, ok := doc["model_provider"]; ok {
		var valid bool
		provider, valid = v.(string)
		if !valid {
			return Transform{}, problem("CODEX_PROVIDER_TYPE_INVALID")
		}
	}
	path := []string{"openai_base_url"}
	container := doc
	if provider != "" && provider != "openai" {
		providers, ok := doc["model_providers"].(map[string]any)
		if !ok {
			return Transform{}, problem("CODEX_PROVIDER_SECTION_MISSING")
		}
		container, ok = providers[provider].(map[string]any)
		if !ok {
			return Transform{}, problem("CODEX_PROVIDER_SECTION_MISSING")
		}
		path = []string{"model_providers", provider, "base_url"}
	}
	previous := ""
	value, exists := container[path[len(path)-1]]
	if exists {
		var ok bool
		previous, ok = value.(string)
		if !ok {
			return Transform{}, problem("CODEX_BASE_URL_TYPE_INVALID")
		}
	}
	if len(path) > 1 && strings.TrimSpace(previous) == "" {
		return Transform{}, problem("CODEX_PROVIDER_BASE_URL_MISSING")
	}
	if len(path) == 1 && strings.TrimSpace(previous) == "" {
		previous = "https://api.openai.com/v1"
	}
	if strings.TrimRight(previous, "/") == target {
		return Transform{content, previous, target, false}, nil
	}
	var parser unstable.Parser
	parser.Reset(content)
	var section []string
	var location unstable.Range
	located, firstTable := false, len(content)
	keys := func(n *unstable.Node) []string {
		var out []string
		it := n.Key()
		for it.Next() {
			out = append(out, string(it.Node().Data))
		}
		return out
	}
	same := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	var visit func(*unstable.Node, []string)
	visit = func(n *unstable.Node, parent []string) {
		full := append(append([]string{}, parent...), keys(n)...)
		v := n.Value()
		if same(full, path) && v.Kind == unstable.String {
			location, located = v.Raw, true
		}
		if v.Kind == unstable.InlineTable {
			it := v.Children()
			for it.Next() {
				visit(it.Node(), full)
			}
		}
	}
	for parser.NextExpression() {
		n := parser.Expression()
		switch n.Kind {
		case unstable.Table, unstable.ArrayTable:
			section = keys(n)
			// Table Raw may be unset; first key is inside the opening bracket.
			it := n.Key()
			it.Next()
			pos := int(it.Node().Raw.Offset)
			for pos > 0 && content[pos-1] != '\n' {
				pos--
			}
			if pos < firstTable {
				firstTable = pos
			}
		case unstable.KeyValue:
			visit(n, section)
		}
	}
	if parser.Error() != nil {
		return Transform{}, problem("CODEX_CONFIG_PARSE_FAILED")
	}
	var out []byte
	quoted := []byte(strconv.Quote(target))
	if exists {
		if !located {
			return Transform{}, problem("CODEX_CONFIG_LAYOUT_UNSUPPORTED")
		}
		start, end := int(location.Offset), int(location.Offset+location.Length)
		out = append(out, content[:start]...)
		out = append(out, quoted...)
		out = append(out, content[end:]...)
	} else {
		nl := "\n"
		if bytes.Contains(content, []byte("\r\n")) {
			nl = "\r\n"
		}
		out = append(out, content[:firstTable]...)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, nl...)
		}
		out = append(out, []byte("openai_base_url = "+string(quoted)+nl)...)
		out = append(out, content[firstTable:]...)
	}
	// Never return bytes that the same TOML decoder rejects, even for layouts
	// not supported by the range editor.
	var verified map[string]any
	if e := toml.Unmarshal(out, &verified); e != nil {
		return Transform{}, problem("CODEX_CONFIG_PARSE_FAILED")
	}
	return Transform{out, previous, target, true}, nil
}
func transform(app string, content []byte, target string, remote bool) (Transform, error) {
	switch app {
	case "claude":
		return Claude(content, target, remote)
	case "codex":
		return Codex(content, target, remote)
	}
	return Transform{}, problem("AGENT_UNSUPPORTED")
}
func ccTransform(app, settings, target string, remote bool) (Transform, error) {
	root := map[string]json.RawMessage{}
	if e := json.Unmarshal([]byte(settings), &root); e != nil || root == nil {
		return Transform{}, problem("CCSWITCH_SETTINGS_PARSE_FAILED")
	}
	if app == "claude" {
		if _, ok := root["env"]; !ok {
			return Transform{}, problem("CCSWITCH_CLAUDE_ENV_MISSING")
		}
		t, e := Claude([]byte(settings), target, remote)
		if e != nil {
			return t, e
		}
		if t.Previous == "" {
			return Transform{}, problem("CCSWITCH_CLAUDE_BASE_URL_MISSING")
		}
		return t, nil
	}
	if app == "codex" {
		var config string
		if e := json.Unmarshal(root["config"], &config); e != nil {
			return Transform{}, problem("CCSWITCH_CODEX_CONFIG_MISSING")
		}
		t, e := Codex([]byte(config), target, remote)
		if e != nil {
			return t, e
		}
		if !t.Changed {
			return Transform{[]byte(settings), t.Previous, t.Injected, false}, nil
		}
		root["config"], _ = json.Marshal(string(t.Content))
		b, e := json.Marshal(root)
		t.Content = b
		return t, e
	}
	return Transform{}, fmt.Errorf("unsupported CC Switch app %q", app)
}
