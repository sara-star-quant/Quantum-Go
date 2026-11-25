package tunnel

import (
	"math"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
)

// AES-GCM confidentiality advantage is at most (s + q + 1)^2 / 2^129, where s counts the 16-byte
// blocks of plaintext and associated data and q the messages sealed under one key (CFRG AEAD
// limits draft, section 5.1). TLS 1.3 aims for 2^-60, which holds while s + q + 1 <= 2^34.5.
// These constants decide when a key is retired, so a change that lets one key seal too much must
// fail here, not in a security review.
func TestRekeyLimitsKeepAESGCMConfidentialityWithinTheTLSTarget(t *testing.T) {
	budget := math.Pow(2, 34.5)

	// Datagram: the packet cap bounds a key, and a datagram holds at most MTU bytes plus one
	// associated-data block.
	blocksPerDatagram := float64((constants.DatagramMTU+15)/16 + 1)
	datagram := float64(constants.MaxPacketsBeforeRekey)*blocksPerDatagram + float64(constants.MaxPacketsBeforeRekey) + 1
	if datagram > budget {
		t.Errorf("datagram key can seal s+q+1 = 2^%.2f blocks and messages, over the 2^34.5 budget", math.Log2(datagram))
	}

	// Stream: the byte cap bounds the plaintext blocks, and each record adds an associated-data block.
	stream := float64(constants.MaxBytesBeforeRekey)/16 + 2*float64(constants.MaxPacketsBeforeRekey) + 1
	if stream > budget {
		t.Errorf("stream key can seal s+q+1 = 2^%.2f blocks and messages, over the 2^34.5 budget", math.Log2(stream))
	}
}
