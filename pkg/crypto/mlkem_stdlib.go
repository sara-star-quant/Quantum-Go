//go:build fips

package crypto

import "crypto/mlkem"

// The FIPS backend is Go's crypto/mlkem, which runs inside Go's FIPS 140-3 module when the
// binary is built with GOFIPS140. It agrees byte for byte with the default circl backend
// (mlkem_circl.go), which is faster on x86-64.

type (
	mlkemEK = mlkem.EncapsulationKey1024
	mlkemDK = mlkem.DecapsulationKey1024
)

// mlkemEncapsulationUsesLibraryEntropy is false here: crypto/mlkem draws its own coins from
// the module's DRBG, which the library's entropy source cannot reach.
const mlkemEncapsulationUsesLibraryEntropy = false

func mlkemKeyFromSeed(seed []byte) (*mlkemEK, *mlkemDK, error) {
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, nil, err
	}
	return dk.EncapsulationKey(), dk, nil
}

func mlkemEncapsulate(ek *mlkemEK) (ciphertext, sharedSecret []byte, err error) {
	sharedSecret, ciphertext = ek.Encapsulate()
	return ciphertext, sharedSecret, nil
}

func mlkemDecapsulate(dk *mlkemDK, ciphertext []byte) ([]byte, error) {
	return dk.Decapsulate(ciphertext)
}

func mlkemPublicKeyBytes(ek *mlkemEK) []byte { return ek.Bytes() }

func mlkemParsePublicKey(data []byte) (*mlkemEK, error) {
	return mlkem.NewEncapsulationKey1024(data)
}
