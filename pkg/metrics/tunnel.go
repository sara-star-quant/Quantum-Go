package metrics

import (
	"context"
	"encoding/hex"
	"time"
)

// TunnelObserver provides observability hooks for tunnel operations.
// Attach this to a tunnel to automatically record metrics and traces.
type TunnelObserver struct {
	collector *Collector
	tracer    Tracer
	logger    *Logger
	sessionID string
	role      string
}

// TunnelObserverConfig configures a tunnel observer.
type TunnelObserverConfig struct {
	Collector *Collector
	Tracer    Tracer
	Logger    *Logger
	SessionID []byte
	Role      string // "initiator" or "responder"
}

// NewTunnelObserver creates a new tunnel observer.
func NewTunnelObserver(cfg TunnelObserverConfig) *TunnelObserver {
	if cfg.Collector == nil {
		cfg.Collector = Global()
	}
	if cfg.Tracer == nil {
		cfg.Tracer = GetTracer()
	}
	if cfg.Logger == nil {
		cfg.Logger = GetLogger()
	}

	sessionID := ""
	if len(cfg.SessionID) > 0 {
		sessionID = hex.EncodeToString(cfg.SessionID[:min(8, len(cfg.SessionID))])
	}

	return &TunnelObserver{
		collector: cfg.Collector,
		tracer:    cfg.Tracer,
		logger:    cfg.Logger.Named("tunnel").With(Fields{
			"session_id": sessionID,
			"role":       cfg.Role,
		}),
		sessionID: sessionID,
		role:      cfg.Role,
	}
}

// OnSessionStart should be called when a new session is created.
func (o *TunnelObserver) OnSessionStart() {
	o.collector.SessionStarted()
	o.logger.Info("session started")
}

// OnSessionEnd should be called when a session ends.
func (o *TunnelObserver) OnSessionEnd() {
	o.collector.SessionEnded()
	o.logger.Info("session ended")
}

// OnSessionFailed should be called when a session fails to establish.
func (o *TunnelObserver) OnSessionFailed(err error) {
	o.collector.SessionFailed()
	o.logger.Error("session failed", Fields{"error": err.Error()})
}

// OnHandshakeStart returns a context and completion function for handshake tracing.
func (o *TunnelObserver) OnHandshakeStart(ctx context.Context) (context.Context, func(error)) {
	spanName := SpanHandshakeInitiator
	if o.role == "responder" {
		spanName = SpanHandshakeResponder
	}

	start := time.Now()
	ctx, endSpan := o.tracer.StartSpan(ctx, spanName, WithSpanKind(SpanKindServer))

	o.logger.Debug("handshake started")

	return ctx, func(err error) {
		duration := time.Since(start)
		o.collector.RecordHandshakeLatency(duration)

		if err != nil {
			o.logger.Error("handshake failed", Fields{
				"error":    err.Error(),
				"duration": duration.String(),
			})
		} else {
			o.logger.Info("handshake completed", Fields{
				"duration": duration.String(),
			})
		}

		endSpan(err)
	}
}

// OnEncrypt records encryption metrics.
func (o *TunnelObserver) OnEncrypt(ctx context.Context, plaintextLen int) (context.Context, func(error)) {
	start := time.Now()
	ctx, endSpan := o.tracer.StartSpan(ctx, SpanEncrypt)

	return ctx, func(err error) {
		duration := time.Since(start)
		o.collector.RecordEncryptLatency(duration)

		if err != nil {
			o.collector.RecordEncryptError()
			o.logger.Debug("encrypt failed", Fields{"error": err.Error()})
		} else {
			o.collector.RecordBytesSent(uint64(plaintextLen))
			o.collector.RecordPacketSent()
		}

		endSpan(err)
	}
}

// OnDecrypt records decryption metrics.
func (o *TunnelObserver) OnDecrypt(ctx context.Context, ciphertextLen int) (context.Context, func(error)) {
	start := time.Now()
	ctx, endSpan := o.tracer.StartSpan(ctx, SpanDecrypt)

	return ctx, func(err error) {
		duration := time.Since(start)
		o.collector.RecordDecryptLatency(duration)

		if err != nil {
			o.collector.RecordDecryptError()
			o.logger.Debug("decrypt failed", Fields{"error": err.Error()})
		} else {
			o.collector.RecordBytesReceived(uint64(ciphertextLen))
			o.collector.RecordPacketReceived()
		}

		endSpan(err)
	}
}

// OnReplayDetected records a blocked replay attack.
func (o *TunnelObserver) OnReplayDetected() {
	o.collector.RecordReplayBlocked()
	o.logger.Warn("replay attack blocked")
}

// OnAuthFailure records an authentication failure.
func (o *TunnelObserver) OnAuthFailure() {
	o.collector.RecordAuthFailure()
	o.logger.Warn("authentication failed")
}

// OnRekeyStart records the start of a rekey operation.
func (o *TunnelObserver) OnRekeyStart(ctx context.Context) (context.Context, func(error)) {
	o.collector.RecordRekeyInitiated()
	ctx, endSpan := o.tracer.StartSpan(ctx, SpanRekey)

	o.logger.Debug("rekey initiated")

	return ctx, func(err error) {
		if err != nil {
			o.collector.RecordRekeyFailed()
			o.logger.Error("rekey failed", Fields{"error": err.Error()})
		} else {
			o.collector.RecordRekeyCompleted()
			o.logger.Info("rekey completed")
		}
		endSpan(err)
	}
}

// OnProtocolError records a protocol error.
func (o *TunnelObserver) OnProtocolError(err error) {
	o.collector.RecordProtocolError()
	o.logger.Error("protocol error", Fields{"error": err.Error()})
}

// Logger returns the observer's logger for custom logging.
func (o *TunnelObserver) Logger() *Logger {
	return o.logger
}

// --- Instrumented Wrappers ---

// InstrumentedSession wraps session metrics collection.
// This can be used to wrap encrypt/decrypt calls.
type InstrumentedSession struct {
	observer *TunnelObserver
}

// NewInstrumentedSession creates a new instrumented session wrapper.
func NewInstrumentedSession(observer *TunnelObserver) *InstrumentedSession {
	return &InstrumentedSession{observer: observer}
}

// WrapEncrypt wraps an encrypt operation with metrics.
func (s *InstrumentedSession) WrapEncrypt(ctx context.Context, plaintextLen int, fn func() error) error {
	_, done := s.observer.OnEncrypt(ctx, plaintextLen)
	err := fn()
	done(err)
	return err
}

// WrapDecrypt wraps a decrypt operation with metrics.
func (s *InstrumentedSession) WrapDecrypt(ctx context.Context, ciphertextLen int, fn func() error) error {
	_, done := s.observer.OnDecrypt(ctx, ciphertextLen)
	err := fn()
	done(err)
	return err
}

// --- Event Types ---

// EventType represents a type of tunnel event for logging.
type EventType string

const (
	EventSessionStart   EventType = "session.start"
	EventSessionEnd     EventType = "session.end"
	EventSessionFailed  EventType = "session.failed"
	EventHandshakeStart EventType = "handshake.start"
	EventHandshakeEnd   EventType = "handshake.end"
	EventDataSent       EventType = "data.sent"
	EventDataReceived   EventType = "data.received"
	EventRekeyStart     EventType = "rekey.start"
	EventRekeyEnd       EventType = "rekey.end"
	EventReplayBlocked  EventType = "security.replay_blocked"
	EventAuthFailed     EventType = "security.auth_failed"
	EventError          EventType = "error"
)

// Event represents a structured tunnel event.
type Event struct {
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	SessionID string                 `json:"session_id,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

// min returns the smaller of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
