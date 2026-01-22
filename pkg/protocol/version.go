// Package protocol defines the wire protocol for the CH-KEM VPN tunnel.
//
// Protocol Version: 1.0
//
// The protocol provides:
//   - Authenticated key exchange using CH-KEM
//   - Forward secrecy through ephemeral keys
//   - Replay protection through sequence numbers
//   - Session rekeying for long-lived connections
package protocol

import "github.com/pzverkov/quantum-go/internal/constants"

// Version represents the protocol version.
type Version struct {
	Major uint8
	Minor uint8
}

// Current is the current protocol version.
var Current = Version{Major: 1, Minor: 0}

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
