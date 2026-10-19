package configuration

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsNativeReplaceFailureRestoresOriginalWithoutOverwritingUser(t *testing.T) {
	for _, scenario := range []string{"unchanged", "moved-original", "concurrent-user", "lost-original"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			target, source := filepath.Join(root, "settings.json"), filepath.Join(root, "staging")
			for path, data := range map[string]string{target: "before", source: "after"} {
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			targetUTF, _ := windows.UTF16PtrFromString(target)
			sourceUTF, _ := windows.UTF16PtrFromString(source)
			failure := windows.ERROR_UNABLE_TO_MOVE_REPLACEMENT_2
			err := replaceExistingFile(source, target, sourceUTF, targetUTF, func(_, _, backup *uint16) error {
				if scenario == "unchanged" {
					return failure
				}
				if scenario == "lost-original" {
					if e := os.Remove(target); e != nil {
						t.Fatal(e)
					}
					return failure
				}
				if e := os.Rename(target, windows.UTF16PtrToString(backup)); e != nil {
					t.Fatal(e)
				}
				if scenario == "concurrent-user" {
					if e := os.WriteFile(target, []byte("user"), 0600); e != nil {
						t.Fatal(e)
					}
				}
				return failure
			})
			if !errors.Is(err, failure) {
				t.Fatal("native failure lost", err)
			}
			uncertain := scenario == "concurrent-user" || scenario == "lost-original"
			if replacementMayHaveChanged(err) != uncertain {
				t.Fatal("unsafe changed state classification", err)
			}
			data, readErr := os.ReadFile(target)
			if scenario == "lost-original" {
				if !os.IsNotExist(readErr) {
					t.Fatal("unexpected replacement recovery")
				}
				return
			}
			want := "before"
			if scenario == "concurrent-user" {
				want = "user"
				if _, e := os.Stat(source + ".original"); e != nil {
					t.Fatal("original backup lost", e)
				}
			}
			if readErr != nil || string(data) != want {
				t.Fatal("unsafe recovery", string(data), readErr)
			}
		})
	}
}
