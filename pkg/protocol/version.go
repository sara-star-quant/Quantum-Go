// Package protocol defines the wire protocol for the CH-KEM tunnel.
//
// Protocol Version: 2.0
//
// The protocol provides:
//   - Authenticated key exchange using CH-KEM
//   - Forward secrecy through ephemeral keys
//   - Replay protection through sequence numbers
//   - Session rekeying for long-lived connections
package protocol

import "github.com/sara-star-quant/quantum-go/internal/constants"

// Version represents the protocol version.
type Version struct {
	Major uint8
	Minor uint8
}

// Current is the current protocol version. Major 3 came with the session-bound
// derived stream nonce: the stream data record no longer transmits the 12-byte
// AEAD nonce (both peers derive it from a session nonce prefix and the sequence),
// so a 3.0 record is wire-incompatible with a 2.x peer. IsCompatible is major-only,
// so the handshake rejects a mismatched peer cleanly rather than corrupting data.
var Current = Version{Major: 3, Minor: 0}

// Bytes returns the version as a 2-byte value.
func (v Version) Bytes() []byte {
	return []byte{v.Major, v.Minor}
}

// Uint16 returns the version as a 16-bit value (major << 8 | minor).
func (v Version) Uint16() uint16 {
	return uint16(v.Major)<<8 | uint16(v.Minor)
}

// ParseVersion parses a version from a 2-byte value.
func ParseVersion(data []byte) Version {
	if len(data) < 2 {
		return Version{}
	}
	return Version{Major: data[0], Minor: data[1]}
}

// IsCompatible returns true if this version is compatible with another version.
// Versions are compatible if they have the same major version.
func (v Version) IsCompatible(other Version) bool {
	return v.Major == other.Major
}

// String returns a string representation of the version.
func (v Version) String() string {
	return string('0'+v.Major) + "." + string('0'+v.Minor)
}

// ProtocolID is the protocol identifier used for domain separation.
const ProtocolID = constants.ProtocolName
