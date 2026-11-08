//go:build unix

package main

import (
	"syscall"
	"time"
)

// processCPUTime returns the user plus system CPU time this process has used.
func processCPUTime() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
