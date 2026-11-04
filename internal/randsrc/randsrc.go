// Package randsrc holds the entropy source the library draws from, so tests can swap in
// a failing or stuck reader and prove the library fails closed. Production code never
// replaces it.
package randsrc

import (
	"crypto/rand"
	"io"
	"sync/atomic"
)

type holder struct{ r io.Reader }

var current atomic.Pointer[holder]

func init() { current.Store(&holder{rand.Reader}) }

// Reader returns the active entropy source (crypto/rand.Reader unless a test replaced it).
func Reader() io.Reader { return current.Load().r }

// Set replaces the entropy source and returns a function that restores the previous one.
func Set(r io.Reader) (restore func()) {
	prev := current.Swap(&holder{r})
	return func() { current.Store(prev) }
}
