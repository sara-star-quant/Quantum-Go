package tunnel

import qerrors "github.com/sara-star-quant/quantum-go/internal/errors"

// Sentinel errors the package returns. They are the values the library itself
// returns, so callers outside the module can match them with errors.Is.
var (
	// Handshake and negotiation.
	ErrHandshakeFailed            = qerrors.ErrHandshakeFailed
	ErrUnsupportedVersion         = qerrors.ErrUnsupportedVersion
	ErrUnsupportedCipherSuite     = qerrors.ErrUnsupportedCipherSuite
	ErrUnsupportedKEMSuite        = qerrors.ErrUnsupportedKEMSuite
	ErrCipherSuiteNotFIPSApproved = qerrors.ErrCipherSuiteNotFIPSApproved

	// Authentication and its configuration.
	ErrServerKeyMismatch       = qerrors.ErrServerKeyMismatch
	ErrStaticAuthRequired      = qerrors.ErrStaticAuthRequired
	ErrStaticAuthMisconfigured = qerrors.ErrStaticAuthMisconfigured
	ErrPSKMisconfigured        = qerrors.ErrPSKMisconfigured
	ErrInvalidPSK              = qerrors.ErrInvalidPSK
	ErrAuthenticationFailed    = qerrors.ErrAuthenticationFailed

	// Records and sessions.
	ErrReplayDetected  = qerrors.ErrReplayDetected
	ErrMessageTooLarge = qerrors.ErrMessageTooLarge
	ErrSessionExpired  = qerrors.ErrSessionExpired
	ErrInvalidState    = qerrors.ErrInvalidState
	ErrInvalidTicket   = qerrors.ErrInvalidTicket
	ErrExpiredTicket   = qerrors.ErrExpiredTicket

	// Tunnel lifecycle.
	ErrTunnelClosed    = qerrors.ErrTunnelClosed
	ErrRekeyRequired   = qerrors.ErrRekeyRequired
	ErrRekeyInProgress = qerrors.ErrRekeyInProgress
	ErrTimeout         = qerrors.ErrTimeout

	// Connection pool.
	ErrPoolClosed    = qerrors.ErrPoolClosed
	ErrPoolTimeout   = qerrors.ErrPoolTimeout
	ErrPoolExhausted = qerrors.ErrPoolExhausted
)
