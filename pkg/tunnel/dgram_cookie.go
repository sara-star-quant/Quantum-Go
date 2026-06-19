// Package tunnel - dgram_cookie.go is the stateless return-routability cookie for
// the datagram handshake. Before the server commits per-session state or runs
// CH-KEM for an unverified source, it can demand that the source echo a cookie
// that the server alone could have minted for that exact address. An off-path
// attacker spoofing a victim's address never receives the RETRY carrying the
// cookie, so it cannot complete the round trip - this is what closes the
// residual spoofed-source state/CPU-exhaustion gap noted in datagram.go.
//
// The cookie holds no server-side state: it is an HMAC over the source address
// and an issue timestamp, keyed by a per-endpoint secret minted at startup. A
// process restart rotates the secret and invalidates outstanding cookies, which
// only costs an extra RETRY round trip on the next attempt.
package tunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"time"

	"github.com/sara-star-quant/quantum-go/pkg/crypto"
)

const (
	cookieSecretSize    = 32
	cookieTimestampSize = 8
	cookieMACSize       = sha256.Size
	// cookieSize is the on-the-wire cookie length: an 8-byte issue timestamp
	// followed by its address-bound MAC.
	cookieSize = cookieTimestampSize + cookieMACSize
	// cookieLifetime bounds how long an issued cookie stays valid, limiting the
	// window in which a captured cookie can be replayed from the same address.
	cookieLifetime = 10 * time.Second
)

// cookieSigner issues and verifies stateless return-routability cookies.
type cookieSigner struct {
	secret [cookieSecretSize]byte
	now    func() time.Time
}

// newCookieSigner mints a signer with a random per-endpoint secret.
func newCookieSigner(now func() time.Time) (*cookieSigner, error) {
	if now == nil {
		now = time.Now
	}
	cs := &cookieSigner{now: now}
	if err := crypto.SecureRandom(cs.secret[:]); err != nil {
		return nil, err
	}
	return cs, nil
}

// issue returns a fresh cookie bound to addr at the current time.
func (cs *cookieSigner) issue(addr net.Addr) []byte {
	cookie := make([]byte, cookieSize)
	binary.BigEndian.PutUint64(cookie[:cookieTimestampSize], uint64(cs.now().UnixNano())) // #nosec G115 -- UnixNano is positive through year 2262, fits uint64
	copy(cookie[cookieTimestampSize:], cs.mac(addr, cookie[:cookieTimestampSize]))
	return cookie
}

// verify reports whether cookie is a valid, unexpired cookie for addr. It is
// constant-time in the MAC comparison so a forged cookie leaks no timing signal.
func (cs *cookieSigner) verify(addr net.Addr, cookie []byte) bool {
	if len(cookie) != cookieSize {
		return false
	}
	if !hmac.Equal(cookie[cookieTimestampSize:], cs.mac(addr, cookie[:cookieTimestampSize])) {
		return false
	}
	issued := time.Unix(0, int64(binary.BigEndian.Uint64(cookie[:cookieTimestampSize]))) // #nosec G115 -- timestamp we issued is positive through year 2262, fits int64
	age := cs.now().Sub(issued)
	return age >= 0 && age <= cookieLifetime
}

// mac computes the address-bound MAC over the issue timestamp. Binding the
// stringified address is what ties a cookie to one source: a cookie minted for
// one peer fails verify for any other.
func (cs *cookieSigner) mac(addr net.Addr, tsBytes []byte) []byte {
	h := hmac.New(sha256.New, cs.secret[:])
	_, _ = h.Write([]byte(addr.String()))
	_, _ = h.Write(tsBytes)
	return h.Sum(nil)
}
