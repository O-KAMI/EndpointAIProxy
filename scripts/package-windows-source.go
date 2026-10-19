// Build a source-only Windows handoff with vendored, locked dependencies.
// Run from the repository root: go run scripts/package-windows-source.go -output artifacts/windows-source.zip
package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

func main() {
	root := flag.String("source-root", ".", "repository root")
	output := flag.String("output", "artifacts/EndpointAIProxy-Go-Windows-0.2.2-source.zip", "output ZIP")
	version := flag.String("version", "0.2.2", "candidate version")
	flag.Parse()
	if err := run(*root, *output, *version); err != nil {
		fmt.Fprintln(os.Stderr, "Windows source packaging failed:", err)
		os.Exit(1)
	}
}

func run(root, output, version string) error {
	for _, c := range version {
		if (c < '0' || c > '9') && c != '.' {
			return errors.New("invalid version")
		}
	}
	if version == "" {
		return errors.New("empty version")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	if _, err = os.Stat(output); err == nil {
		return errors.New("output already exists; choose a new path")
	}
	temporary, err := os.MkdirTemp("", "endpointai-windows-source-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	stage := filepath.Join(temporary, "EndpointAIProxy-Go-Windows-"+version)
	files := []string{
		"AGENTS.md", "CONTEXT.md", "docs/CLIENT-REVIEW.md", "docs/CLIENT-FIX-VERIFICATION-20261016.md", "go-client/README.md",
		"Build-MSI.cmd", "Upgrade-Client.cmd", "scripts/Upgrade-Client.ps1", "Directory.Build.props", "Directory.Packages.props", "global.json",
		"go-client/go.mod", "go-client/go.sum",
		"installer/Sf.EndpointAI.Go.Setup/Sf.EndpointAI.Go.Setup.wixproj",
		"installer/Sf.EndpointAI.Setup/Package.wxs",
		"installer/Sf.EndpointAI.Setup/Collect-Diagnostics.cmd",
		"installer/Sf.EndpointAI.Setup/Uninstall-EndpointAI.cmd",
		"scripts/Build-MSI.ps1", "scripts/Validate-MSI.ps1", "scripts/Test-Windows.ps1",
		"scripts/Windows-GoSupport.ps1", "scripts/Installer-BuildSupport.ps1",
		"scripts/Collect-InstallerLogs.ps1",
		"scripts/package-windows-source.go", "docs/WINDOWS-GO-DELIVERY.md",
		"artifacts/go-client/verification/client-validation-022-20261018-r3-verified.json", "docs/CLIENT-PERFORMANCE-022-R3.md", "artifacts/go-client/verification/performance-stable-022-20261018-r3.json", "artifacts/go-client/verification/soak-4h-022-20261018-r3.json", "artifacts/go-client/verification/resource-analysis-022-20261018-r3.json", "artifacts/go-client/verification/verification-pipeline-022-20261018-r3.json", "docs/DSH-INTEGRATION-20261017.md", "docs/CLIENT-SERVER-022-024-20261018.md",
		"artifacts/go-client/verification/dsh-soak-4h-r3-20261017.json", "artifacts/go-client/verification/dsh-soak-review-20261018.json", "docs/GO-CLIENT-PARITY.md", "docs/GO-CLIENT-VERIFICATION.md",
		"go-client/scripts/benchmark-stable.py", "go-client/scripts/followup-verification.py", "go-client/scripts/soak.py", "go-client/scripts/verify-dsh.py", "go-client/scripts/dsh-sdk-fixture.mjs", "go-client/scripts/benchmark.py",
		"go-client/testdata/dsh-runtime/package.json", "go-client/testdata/dsh-runtime/package-lock.json",
	}
	for _, relative := range files {
		if err = copyFile(filepath.Join(root, relative), filepath.Join(stage, relative)); err != nil {
			return err
		}
	}
	for _, directory := range []string{"go-client/cmd", "go-client/internal"} {
		base := filepath.Join(root, directory)
		err = filepath.WalkDir(base, func(path string, item fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if item.Type()&os.ModeSymlink != 0 {
				return errors.New("source tree contains a symlink")
			}
			if item.IsDir() {
				return nil
			}
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			if filepath.Ext(path) != ".go" && !strings.Contains(filepath.ToSlash(relative), "/testdata/") {
				return nil
			}
			if forbidden(relative) {
				return errors.New("forbidden source filename")
			}
			return copyFile(path, filepath.Join(stage, relative))
		})
		if err != nil {
			return err
		}
	}
	modBefore, _ := os.ReadFile(filepath.Join(stage, "go-client/go.mod"))
	sumBefore, _ := os.ReadFile(filepath.Join(stage, "go-client/go.sum"))
	command := exec.Command("go", "mod", "vendor")
	command.Dir = filepath.Join(stage, "go-client")
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "CGO_ENABLED=0", "GOFLAGS=-mod=readonly")
	if os.Getenv("GOPROXY") == "" {
		command.Env = append(command.Env, "GOPROXY=https://goproxy.cn,direct")
	}
	if data, cmdErr := command.CombinedOutput(); cmdErr != nil {
		return fmt.Errorf("vendor locked dependencies: %w (%s)", cmdErr, strings.TrimSpace(string(data)))
	}
	modAfter, _ := os.ReadFile(filepath.Join(stage, "go-client/go.mod"))
	sumAfter, _ := os.ReadFile(filepath.Join(stage, "go-client/go.sum"))
	if string(modBefore) != string(modAfter) || string(sumBefore) != string(sumAfter) {
		return errors.New("vendoring changed dependency locks; source archive was not produced")
	}
	licenses := []string{"Third-party license files are preserved at the following paths in this source archive:", ""}
	var inventory []entry
	err = filepath.WalkDir(stage, func(path string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if item.IsDir() {
			return nil
		}
		relative, _ := filepath.Rel(stage, path)
		relative = filepath.ToSlash(relative)
		if item.Type()&os.ModeSymlink != 0 || forbidden(relative) {
			return fmt.Errorf("forbidden file in staged source: %s", relative)
		}
		upper := strings.ToUpper(item.Name())
		if strings.HasPrefix(relative, "go-client/vendor/") && (strings.HasPrefix(upper, "LICENSE") || strings.HasPrefix(upper, "COPYING") || strings.HasPrefix(upper, "NOTICE")) {
			licenses = append(licenses, relative)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		digest := sha256.Sum256(data)
		inventory = append(inventory, entry{relative, hex.EncodeToString(digest[:]), int64(len(data))})
		return nil
	})
	if err != nil {
		return err
	}
	if len(licenses) == 2 {
		return errors.New("vendored license inventory is empty")
	}
	sort.Strings(licenses[2:])
	licenseData := []byte(strings.Join(licenses, "\n") + "\n")
	if err = os.WriteFile(filepath.Join(stage, "THIRD-PARTY-LICENSES.txt"), licenseData, 0600); err != nil {
		return err
	}
	licenseDigest := sha256.Sum256(licenseData)
	inventory = append(inventory, entry{"THIRD-PARTY-LICENSES.txt", hex.EncodeToString(licenseDigest[:]), int64(len(licenseData))})
	sort.Slice(inventory, func(i, j int) bool { return inventory[i].Path < inventory[j].Path })
	manifest, err := json.MarshalIndent(map[string]any{"productVersion": version, "purpose": "Windows Go source handoff; build only by default", "credentialsIncluded": false, "requires": []string{"Windows x64", "Windows PowerShell 5.1", "Go 1.27.x", ".NET SDK 10.0", "first-build NuGet access for WiX 6.0.2"}, "soakHoursRequired": 4, "files": inventory}, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(stage, "source-manifest.json"), append(manifest, '\n'), 0600); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(output), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		file.Close()
		if !completed {
			os.Remove(output)
		}
	}()
	archive := zip.NewWriter(file)
	err = filepath.WalkDir(stage, func(path string, item fs.DirEntry, walkErr error) error {
		if walkErr != nil || item.IsDir() {
			return walkErr
		}
		relative, _ := filepath.Rel(temporary, path)
		header := &zip.FileHeader{Name: filepath.ToSlash(relative), Method: zip.Deflate}
		header.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
		header.SetMode(0600)
		writer, createErr := archive.CreateHeader(header)
		if createErr != nil {
			return createErr
		}
		input, openErr := os.Open(path)
		if openErr != nil {
			return openErr
		}
		_, copyErr := io.Copy(writer, input)
		closeErr := input.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		archive.Close()
		return err
	}
	if err = archive.Close(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	data, err := os.ReadFile(output)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if err = os.WriteFile(output+".sha256", []byte(hex.EncodeToString(digest[:])+"  "+filepath.Base(output)+"\n"), 0600); err != nil {
		return err
	}
	completed = true
	fmt.Printf("Windows source archive: %s (%d bytes, %d source files; no credentials)\n", output, len(data), len(inventory)+1)
	return nil
}

func copyFile(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("only regular source files may be packaged")
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	return os.WriteFile(target, data, 0600)
}

func forbidden(relative string) bool {
	// Locked upstream test resources copied by go mod vendor, never client state.
	if relative == "go-client/vendor/modernc.org/sqlite/embed.db" || relative == "go-client/vendor/modernc.org/sqlite/embed2.db" {
		return false
	}
	name := strings.ToLower(filepath.Base(relative))
	if name == "client-credentials.json" || name == "machine.key" || name == "launch-env.json" || name == "rollback.json" || name == ".ds_store" {
		return true
	}
	for _, extension := range []string{".p12", ".pfx", ".key", ".pem", ".provisionprofile", ".mobileprovision", ".db", ".db-wal", ".db-shm", ".log", ".msi", ".pkg", ".exe", ".dll"} {
		if strings.HasSuffix(name, extension) {
			return true
		}
	}
	return strings.Contains(filepath.ToSlash(relative), "/.git/")
}
