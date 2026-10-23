package configuration

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

const codexAPIOrigin = "https://api.openai.com/v1"
const codexChatGPTOrigin = "https://chatgpt.com/backend-api/codex"

// Only login-mode metadata is decoded. Credentials are never changed or returned.
func codexAuthOrigin(content []byte) (string, error) {
	if len(content) == 0 || bytes.Equal(bytes.TrimSpace(content), []byte("null")) {
		return codexAPIOrigin, nil
	}
	var auth struct {
		Mode string `json:"auth_mode"`
	}
	if err := json.Unmarshal(content, &auth); err != nil {
		return "", problem("CODEX_AUTH_METADATA_INVALID")
	}
	switch auth.Mode {
	case "chatgpt":
		return codexChatGPTOrigin, nil
	case "", "apikey":
		return codexAPIOrigin, nil
	default:
		return "", problem("CODEX_AUTH_MODE_UNSUPPORTED")
	}
}

func profileTransform(p Profile, app string, content []byte, target string, remote bool) (Transform, error) {
	if app != "codex" {
		return transform(app, content, target, remote)
	}
	// Reading is lazy: explicit provider URLs do not depend on auth.json.
	return codex(content, target, remote, func() (string, error) {
		path := filepath.Join(p.Home, ".codex", "auth.json")
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return codexAPIOrigin, nil
		}
		if err != nil || !info.Mode().IsRegular() {
			return "", problem("CODEX_AUTH_METADATA_UNREADABLE")
		}
		file, err := os.Open(path)
		if err != nil {
			return "", problem("CODEX_AUTH_METADATA_UNREADABLE")
		}
		defer file.Close()
		const limit = 1 << 20
		b, err := io.ReadAll(io.LimitReader(file, limit+1))
		if err != nil || len(b) > limit {
			return "", problem("CODEX_AUTH_METADATA_UNREADABLE")
		}
		return codexAuthOrigin(b)
	})
}
