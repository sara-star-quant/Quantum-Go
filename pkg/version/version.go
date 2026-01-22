package version

import "fmt"

// Semantic version components.
const (
	// Major is the major version (breaking changes).
	Major = 0
	// Minor is the minor version (new features).
	Minor = 0
	// Patch is the patch version (bug fixes).
	Patch = 7
	// Label is the optional pre-release label.
	Label = ""
)

// String returns the full version string.
func String() string {
	v := fmt.Sprintf("v%d.%d.%d", Major, Minor, Patch)
	if Label != "" {
		v += "-" + Label
	}
	return v
}

// Full returns a descriptive version string.
func Full() string {
	return fmt.Sprintf("Quantum-Go %s", String())
}
