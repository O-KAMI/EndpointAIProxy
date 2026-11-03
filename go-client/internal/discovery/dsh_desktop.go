package discovery

import (
	"encoding/binary"
	"encoding/json"
	"endpointai/client/internal/contracts"
	"endpointai/client/internal/platform"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type desktopManifestStamp struct {
	size, modified int64
	name, version  string
}

var desktopManifests sync.Map
var desktopAccounts sync.Map

// Official pin 1517a4d supplies productName, but no fixed bundle ID: it is
// injected by the release environment. Verify the packed package identity in
// addition to the install layout; a directory name alone is weak evidence.
func dshDesktopSamples(p platform.Profile) []sample {
	resources := []string{filepath.Join("/Applications", "DeepSeek Harness.app", "Contents", "Resources"), filepath.Join(p.Home, "Applications", "DeepSeek Harness.app", "Contents", "Resources"), filepath.Join(p.Local, "Programs", "DeepSeek Harness", "resources"), filepath.Join(p.Local, "DeepSeek Harness", "resources")}
	resources = append(resources, dshInstalledResources(p)...)
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
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if cached, ok := desktopManifests.Load(path); ok {
		stamp := cached.(desktopManifestStamp)
		if stamp.size == info.Size() && stamp.modified == info.ModTime().UnixNano() {
			return map[string]string{"name": stamp.name, "version": stamp.version}, nil
		}
	}
	manifest, err := dshASARPackage(path, "package.json")
	if err == nil {
		desktopManifests.Store(path, desktopManifestStamp{info.Size(), info.ModTime().UnixNano(), manifest["name"], manifest["version"]})
	}
	return manifest, err
}

func dshASARPackage(path, packagePath string) (map[string]string, error) {
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
	if headerSize < 8 || headerSize > 8<<20 || jsonSize > headerSize-8 {
		return nil, io.ErrUnexpectedEOF
	}
	header := make([]byte, jsonSize)
	if _, e = io.ReadFull(f, header); e != nil {
		return nil, e
	}
	type asarEntry struct {
		Files    map[string]*asarEntry `json:"files"`
		Size     int64                 `json:"size"`
		Offset   string                `json:"offset"`
		Unpacked bool                  `json:"unpacked"`
	}
	var entry *asarEntry
	if packagePath == "package.json" {
		// Skip nested package indexes when only the root identity is needed.
		var flat struct {
			Files map[string]struct {
				Size     int64  `json:"size"`
				Offset   string `json:"offset"`
				Unpacked bool   `json:"unpacked"`
			} `json:"files"`
		}
		if e = json.Unmarshal(header, &flat); e != nil {
			return nil, e
		}
		file, ok := flat.Files[packagePath]
		if !ok {
			return nil, io.ErrUnexpectedEOF
		}
		entry = &asarEntry{Size: file.Size, Offset: file.Offset, Unpacked: file.Unpacked}
	} else {
		var tree asarEntry
		if e = json.Unmarshal(header, &tree); e != nil {
			return nil, e
		}
		entry = &tree
		for _, part := range strings.Split(packagePath, "/") {
			entry = entry.Files[part]
			if entry == nil {
				return nil, io.ErrUnexpectedEOF
			}
		}
	}
	if entry.Unpacked || entry.Size < 1 || entry.Size > 1<<20 {
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

func dshDesktopAccountRuntime(path string) (string, bool) {
	if !exists(filepath.Join(filepath.Dir(path), "resources", "runtime", "primary-runtime")) {
		return "", false
	}
	asar := filepath.Join(filepath.Dir(path), "resources", "app.asar")
	info, err := os.Stat(asar)
	if err != nil {
		return "", false
	}
	if cached, ok := desktopAccounts.Load(asar); ok {
		stamp := cached.(desktopManifestStamp)
		if stamp.size == info.Size() && stamp.modified == info.ModTime().UnixNano() {
			return stamp.version, true
		}
	}
	root, err := dshASARManifest(asar)
	if err != nil || root["name"] != "@deepseek-ai/dsh-desktop" || !contracts.DSHDesktopAccountVersionSupported(root["version"]) {
		return "", false
	}
	for _, name := range []string{"dsh-llm-deepseek-account", "dsh-deepseek-account-platform", "dsh-desktop-host", "dsh-app-boot"} {
		manifest, err := dshASARPackage(asar, "dsh/node_modules/@deepseek-ai/"+name+"/package.json")
		if err != nil || manifest["name"] != "@deepseek-ai/"+name || manifest["version"] != root["version"] {
			return "", false
		}
	}
	desktopAccounts.Store(asar, desktopManifestStamp{size: info.Size(), modified: info.ModTime().UnixNano(), version: root["version"]})
	return root["version"], true
}
