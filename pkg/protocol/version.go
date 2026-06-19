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

// Current is the current protocol version. Major 2 came with CH-KEM role +
// version binding (a v1 peer is incompatible). Minor 1 added the optional
// static-key authentication field in ClientHello; Minor 2 adds the optional PSK
// identity field for mutual authentication. Both are additive and
// major-compatible, so 2.0, 2.1, and 2.2 peers still interoperate (folding only
// the auth legs they share).
var Current = Version{Major: 2, Minor: 2}

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
