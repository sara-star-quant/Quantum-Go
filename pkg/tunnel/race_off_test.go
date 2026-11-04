//go:build !race

package tunnel

// The race detector adds allocations, so allocation assertions only run without it.
const raceEnabled = false
