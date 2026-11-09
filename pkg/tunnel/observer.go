package tunnel

import (
	"context"
	"time"
)

// Observer provides hooks for tunnel lifecycle, metrics, and tracing.
// Implementations should be lightweight; callbacks may run on hot paths.
type Observer interface {
	OnSessionStart()
	OnSessionEnd()
	OnSessionFailed(err error)
	OnHandshakeStart(ctx context.Context) (context.Context, func(error))
	// OnEncrypt and OnDecrypt report one record after it was sealed or opened, with how
	// long it took and its outcome. They are called once per record, so an
	// implementation should not allocate.
	OnEncrypt(plaintextLen int, took time.Duration, err error)
	OnDecrypt(ciphertextLen int, took time.Duration, err error)
	OnReplayDetected()
	OnAuthFailure()
	OnRekeyStart(ctx context.Context) (context.Context, func(error))
	OnProtocolError(err error)
}

// ObserverFactory builds a per-session observer.
type ObserverFactory func(session *Session) Observer

func observerFromConfig(config TransportConfig, session *Session) Observer {
	if config.ObserverFactory != nil {
		return config.ObserverFactory(session)
	}
	return config.Observer
}
