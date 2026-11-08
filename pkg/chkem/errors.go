package chkem

import qerrors "github.com/sara-star-quant/quantum-go/internal/errors"

// Sentinel errors the package returns. They are the values the library itself
// returns, so callers outside the module can match them with errors.Is.
var (
	ErrInvalidKeySize      = qerrors.ErrInvalidKeySize
	ErrInvalidCiphertext   = qerrors.ErrInvalidCiphertext
	ErrDecapsulationFailed = qerrors.ErrDecapsulationFailed
	ErrKeyGenerationFailed = qerrors.ErrKeyGenerationFailed
	ErrEncapsulationFailed = qerrors.ErrEncapsulationFailed
	ErrInvalidPublicKey    = qerrors.ErrInvalidPublicKey
	ErrInvalidPrivateKey   = qerrors.ErrInvalidPrivateKey
)
