package tunnel

import qerrors "github.com/pzverkov/quantum-go/internal/errors"

func isProtocolError(err error) bool {
	if err == nil {
		return false
	}

	var perr *qerrors.ProtocolError
	if qerrors.As(err, &perr) {
		return true
	}

	return qerrors.Is(err, qerrors.ErrInvalidMessage) ||
		qerrors.Is(err, qerrors.ErrUnsupportedVersion) ||
		qerrors.Is(err, qerrors.ErrUnsupportedCipherSuite) ||
		qerrors.Is(err, qerrors.ErrHandshakeFailed) ||
		qerrors.Is(err, qerrors.ErrSessionExpired) ||
		qerrors.Is(err, qerrors.ErrInvalidState) ||
		qerrors.Is(err, qerrors.ErrMessageTooLarge) ||
		qerrors.Is(err, qerrors.ErrInvalidTicket) ||
		qerrors.Is(err, qerrors.ErrExpiredTicket)
}
