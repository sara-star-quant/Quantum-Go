package version

import "fmt"

const (
	Major = 0
	Minor = 0
	Patch = 6
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
