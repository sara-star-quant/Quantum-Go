package version

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionStrings(t *testing.T) {
	v := String()
	if v == "" {
		t.Fatal("version string is empty")
	}
	full := Full()
	if !strings.Contains(full, "Quantum-Go") {
		t.Errorf("full version should contain project name, got %s", full)
	}
	if !strings.Contains(full, v) {
		t.Errorf("full version should contain version string, got %s", full)
	}
}

func TestVersionFromBuildInfo(t *testing.T) {
	cases := []struct {
		name string
		info debug.BuildInfo
		want string
	}{
		{"a program that depends on the module", debug.BuildInfo{
			Main: debug.Module{Path: "example.com/app", Version: "v1.2.3"},
			Deps: []*debug.Module{{Path: modulePath, Version: "v0.0.27"}},
		}, "v0.0.27"},
		{"a replaced dependency with a version", debug.BuildInfo{
			Main: debug.Module{Path: "example.com/app", Version: "v1.2.3"},
			Deps: []*debug.Module{{Path: modulePath, Version: "v0.0.27", Replace: &debug.Module{Version: "v0.0.30"}}},
		}, "v0.0.30"},
		{"a local replacement is not a release", debug.BuildInfo{
			Main: debug.Module{Path: "example.com/app", Version: "v1.2.3"},
			Deps: []*debug.Module{{Path: modulePath, Version: "v0.0.27", Replace: &debug.Module{Path: "../quantum-go"}}},
		}, develVersion},
		{"installed with go install", debug.BuildInfo{
			Main: debug.Module{Path: modulePath, Version: "v0.0.27"},
		}, "v0.0.27"},
		{"built from a working tree", debug.BuildInfo{
			Main: debug.Module{Path: modulePath, Version: "(devel)"},
		}, develVersion},
		{"an unrelated program with no dependency", debug.BuildInfo{
			Main: debug.Module{Path: "example.com/app", Version: "v1.2.3"},
		}, develVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := versionFromBuildInfo(&tc.info); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
