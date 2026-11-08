//go:build !unix

package main

import "time"

// processCPUTime is unavailable on this platform; CPU figures are omitted.
func processCPUTime() time.Duration { return 0 }
