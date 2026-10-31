package chkem_test

import (
	"bytes"
	"fmt"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
)

// Both sides derive the same secret from a hybrid ML-KEM-1024 and X25519 exchange.
func Example() {
	keyPair, _ := chkem.GenerateKeyPair()

	// The responder encapsulates to the initiator's public key.
	ciphertext, responderSecret, _ := chkem.Encapsulate(keyPair.PublicKey(), chkem.RoleResponder)

	// The initiator recovers the same secret with its private key.
	initiatorSecret, _ := chkem.Decapsulate(ciphertext, keyPair, chkem.RoleInitiator)

	fmt.Println(bytes.Equal(initiatorSecret, responderSecret))
	// Output: true
}
