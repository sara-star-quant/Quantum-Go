package tunnel

import "context"

// Observer provides hooks for tunnel lifecycle, metrics, and tracing.
// Implementations should be lightweight; callbacks may run on hot paths.
type Observer interface {
	OnSessionStart()
	OnSessionEnd()
	OnSessionFailed(err error)
	OnHandshakeStart(ctx context.Context) (context.Context, func(error))
	OnEncrypt(ctx context.Context, plaintextLen int) (context.Context, func(error))
	OnDecrypt(ctx context.Context, ciphertextLen int) (context.Context, func(error))
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
