package diagnostics

import (
	"os"
	"path/filepath"
)

// Metadata only: never read model settings, credentials or session content.
func dshMetadata(home string) []map[string]any {
	root := filepath.Join(home, ".dsh")
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	out := []map[string]any{}
	add := func(path, kind string) {
		if !safeFile(path) {
			return
		}
		if st, e := os.Stat(path); e == nil {
			out = append(out, map[string]any{"Kind": kind, "PathHash": hashIdentifier(path), "Length": st.Size(), "LastWriteTimeUtc": st.ModTime().UTC()})
		}
	}
	add(filepath.Join(root, "cordis.patch.yml"), "dshHomePatch")
	profiles := filepath.Join(root, "profiles")
	st, e := os.Lstat(profiles)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return out
	}
	dir, e := os.Open(profiles)
	if e != nil {
		return out
	}
	defer dir.Close()
	entries, _ := dir.ReadDir(64)
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		add(filepath.Join(profiles, entry.Name(), "cordis.patch.yml"), "dshProfilePatch")
	}
	return out
}
