package chkem

import (
	"encoding/binary"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// suiteTagSize is the byte length of the suite tag prefixed to a persisted static
// identity seed or public pin so it self-describes its KEM suite.
const suiteTagSize = 2

// TagSuite prefixes body with id's 2-byte big-endian wire tag. It is used to persist
// a suite-tagged static-identity seed or public pin so a loader can pick the right
// suite without out-of-band configuration.
func TagSuite(id SuiteID, body []byte) []byte {
	out := make([]byte, suiteTagSize+len(body))
	binary.BigEndian.PutUint16(out, uint16(id))
	copy(out[suiteTagSize:], body)
	return out
}

// splitSuiteTag reads the suite tag from a tagged seed or pin and returns the suite
// and the remaining body.
func splitSuiteTag(data []byte) (Suite, []byte, error) {
	if len(data) < suiteTagSize {
		return nil, nil, qerrors.ErrInvalidKeySize
	}
	suite, ok := GetSuite(SuiteID(binary.BigEndian.Uint16(data)))
	if !ok {
		return nil, nil, qerrors.ErrUnsupportedKEMSuite
	}
	return suite, data[suiteTagSize:], nil
}

// ParseTaggedKeyPair reconstructs a key pair from a suite-tagged static-identity
// seed produced by TagSuite over a suite's GenerateStaticKeyPair seed.
func ParseTaggedKeyPair(data []byte) (*KeyPair, error) {
	suite, body, err := splitSuiteTag(data)
	if err != nil {
		return nil, err
	}
	return suite.ParseKeyPair(body)
}

// ParseTaggedPublicKey parses a suite-tagged public pin.
func ParseTaggedPublicKey(data []byte) (*PublicKey, error) {
	suite, body, err := splitSuiteTag(data)
	if err != nil {
		return nil, err
	}
	return suite.ParsePublicKey(body)
}
