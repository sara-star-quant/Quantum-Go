//go:build !fips

package crypto

import (
	"bytes"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// The default backend is cloudflare/circl: on x86-64 it is faster than the standard library
// (about 1.4 to 1.9x per operation on GitHub runners). Builds with -tags fips use crypto/mlkem
// instead (mlkem_stdlib.go). Both implement FIPS 203 and agree byte for byte.

type (
	mlkemEK = mlkem1024.PublicKey
	mlkemDK = mlkem1024.PrivateKey
)

// mlkemEncapsulationUsesLibraryEntropy reports whether encapsulation coins come from
// SecureRandom, so the entropy-failure tests can cover them.
const mlkemEncapsulationUsesLibraryEntropy = true

func mlkemKeyFromSeed(seed []byte) (*mlkemEK, *mlkemDK, error) {
	return mlkem1024.GenerateKeyPair(bytes.NewReader(seed))
}

func mlkemEncapsulate(ek *mlkemEK) (ciphertext, sharedSecret []byte, err error) {
	coins := make([]byte, mlkem1024.EncapsulationSeedSize)
	defer Zeroize(coins)
	if err := SecureRandom(coins); err != nil {
		return nil, nil, err
	}
	ciphertext = make([]byte, mlkem1024.CiphertextSize)
	sharedSecret = make([]byte, mlkem1024.SharedKeySize)
	ek.EncapsulateTo(ciphertext, sharedSecret, coins)
	return ciphertext, sharedSecret, nil
}

func mlkemDecapsulate(dk *mlkemDK, ciphertext []byte) ([]byte, error) {
	ss := make([]byte, mlkem1024.SharedKeySize)
	dk.DecapsulateTo(ss, ciphertext)
	return ss, nil
}

func mlkemPublicKeyBytes(ek *mlkemEK) []byte {
	buf := make([]byte, mlkem1024.PublicKeySize)
	ek.Pack(buf)
	return buf
}

func mlkemParsePublicKey(data []byte) (*mlkemEK, error) {
	pk := new(mlkemEK)
	if err := pk.Unpack(data); err != nil {
		return nil, err
	}
	return pk, nil
}
