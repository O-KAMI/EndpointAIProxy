package discovery

import (
	"encoding/binary"
	"encoding/json"
	"endpointai/client/internal/platform"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// Official pin 1517a4d supplies productName, but no fixed bundle ID: it is
// injected by the release environment. Verify the packed package identity in
// addition to the install layout; a directory name alone is weak evidence.
func dshDesktopSamples(p platform.Profile) []sample {
	resources := []string{filepath.Join("/Applications", "DeepSeek Harness.app", "Contents", "Resources"), filepath.Join(p.Home, "Applications", "DeepSeek Harness.app", "Contents", "Resources"), filepath.Join(p.Local, "Programs", "DeepSeek Harness", "resources"), filepath.Join(p.Local, "DeepSeek Harness", "resources")}
	out := []sample{}
	for _, root := range resources {
		path := filepath.Join(root, "app.asar")
		m, e := dshASARManifest(path)
		if e == nil && m["name"] == "@deepseek-ai/dsh-desktop" && exists(filepath.Join(root, "runtime", "primary-runtime")) {
			out = append(out, sample{sid: p.SID, kind: DeepSeekHarness, collector: "installed-application", path: path, version: m["version"], strength: 2, method: 1})
		}
	}
	return out
}

func dshASARManifest(path string) (map[string]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	var prefix [16]byte
	if _, e = io.ReadFull(f, prefix[:]); e != nil {
		return nil, e
	}
	headerSize := binary.LittleEndian.Uint32(prefix[4:8])
	jsonSize := binary.LittleEndian.Uint32(prefix[12:16])
	if headerSize < 8 || headerSize > 4<<20 || jsonSize > headerSize-8 {
		return nil, io.ErrUnexpectedEOF
	}
	header := make([]byte, jsonSize)
	if _, e = io.ReadFull(f, header); e != nil {
		return nil, e
	}
	var tree struct {
		Files map[string]struct {
			Size     int64  `json:"size"`
			Offset   string `json:"offset"`
			Unpacked bool   `json:"unpacked"`
		} `json:"files"`
	}
	if e = json.Unmarshal(header, &tree); e != nil {
		return nil, e
	}
	entry, ok := tree.Files["package.json"]
	if !ok || entry.Unpacked || entry.Size < 1 || entry.Size > 1<<20 {
		return nil, io.ErrUnexpectedEOF
	}
	offset, e := strconv.ParseInt(entry.Offset, 10, 64)
	if e != nil || offset < 0 || offset > 1<<40 {
		return nil, io.ErrUnexpectedEOF
	}
	stat, e := f.Stat()
	if e != nil {
		return nil, e
	}
	start := 8 + int64(headerSize) + offset
	if start > stat.Size() || entry.Size > stat.Size()-start {
		return nil, io.ErrUnexpectedEOF
	}
	var raw map[string]json.RawMessage
	if e = json.NewDecoder(io.NewSectionReader(f, start, entry.Size)).Decode(&raw); e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, key := range []string{"name", "version"} {
		var v string
		if json.Unmarshal(raw[key], &v) == nil {
			out[key] = v
		}
	}
	return out, nil
}

func dshDesktopProcess(path string) bool {
	resources := filepath.Join(filepath.Dir(path), "resources")
	if filepath.Base(filepath.Dir(path)) == "MacOS" {
		resources = filepath.Join(filepath.Dir(filepath.Dir(path)), "Resources")
	}
	m, e := dshASARManifest(filepath.Join(resources, "app.asar"))
	return e == nil && m["name"] == "@deepseek-ai/dsh-desktop" && exists(filepath.Join(resources, "runtime", "primary-runtime"))
}
