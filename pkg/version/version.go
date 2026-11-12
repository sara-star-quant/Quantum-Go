package version

import (
	"fmt"
	"runtime/debug"
)

// modulePath is this module's import path, used to find its version in the build information.
const modulePath = "github.com/sara-star-quant/quantum-go"

// Semantic version components.
//
// Deprecated: these constants are not maintained and lag the released versions. Use String,
// which reads the version the Go toolchain recorded in the binary.
const (
	// Major is the major version (breaking changes).
	Major = 0
	// Minor is the minor version (new features).
	Minor = 0
	// Patch is the patch version (bug fixes).
	Patch = 14
	// Label is the optional pre-release label.
	Label = ""
)

// develVersion is reported when the binary carries no module version, such as a build from a
// working tree. It says so instead of naming a release the code may not match.
const develVersion = "devel"

// String returns the library version the Go toolchain recorded in this binary: the tag for a
// program that depends on Quantum-Go or was installed with `go install`. A build inside a git
// checkout can carry a pseudo-version or a +dirty suffix that the toolchain derives from the
// repository, and with no version information it is "devel". The command-line tool prefers the
// version stamped into its release binaries.
func String() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return develVersion
	}
	return versionFromBuildInfo(info)
}

// versionFromBuildInfo is String with its input passed in, so tests can cover each case.
func versionFromBuildInfo(info *debug.BuildInfo) string {
	for _, dep := range info.Deps {
		if dep.Path != modulePath {
			continue
		}
		if dep.Replace != nil {
			// A replacement with a version is a published fork; one without is a local path.
			if dep.Replace.Version != "" {
				return dep.Replace.Version
			}
			return develVersion
		}
		if dep.Version != "" && dep.Version != "(devel)" {
			return dep.Version
		}
		return develVersion
	}
	if info.Main.Path == modulePath && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return develVersion
}

// Full returns a descriptive version string.
func Full() string {
	return fmt.Sprintf("Quantum-Go %s", String())
}
