package metrics

import (
	"context"
	"sync"
	"time"
)

// Tracer provides distributed tracing capabilities.
// This interface allows plugging in different tracing backends (OpenTelemetry, Jaeger, etc.).
type Tracer interface {
	// StartSpan starts a new span with the given name.
	// Returns a context containing the span and a function to end the span.
	StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, SpanEnder)
}

// SpanEnder is a function that ends a span.
// Call with nil error for success, or pass an error to mark the span as failed.
type SpanEnder func(err error)

// SpanOption configures span behavior.
type SpanOption func(*spanConfig)

type spanConfig struct {
	kind       SpanKind
	attributes map[string]interface{}
}

// SpanKind identifies the type of span.
type SpanKind int

// SpanKindInternal is the default span kind; other values indicate server or client spans.
const (
	SpanKindInternal SpanKind = iota
	SpanKindServer
	SpanKindClient
)

// WithSpanKind sets the span kind.
func WithSpanKind(kind SpanKind) SpanOption {
	return func(c *spanConfig) {
		c.kind = kind
	}
}

// WithAttributes sets span attributes.
func WithAttributes(attrs map[string]interface{}) SpanOption {
	return func(c *spanConfig) {
		c.attributes = attrs
	}
}

// --- NoOp Tracer ---

// NoOpTracer is a tracer that does nothing.
// Useful as a default when tracing is not configured.
type NoOpTracer struct{}

// StartSpan returns the context unchanged and a no-op end function.
func (NoOpTracer) StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, SpanEnder) {
	return ctx, func(err error) {}
}

// --- Simple Tracer ---

// SimpleTracer is a basic tracer that records spans in memory.
// Useful for testing and debugging.
type SimpleTracer struct {
	mu    sync.Mutex
	spans []RecordedSpan
}

// RecordedSpan represents a completed span.
type RecordedSpan struct {
	Name       string
	StartTime  time.Time
	EndTime    time.Time
	Duration   time.Duration
	Kind       SpanKind
	Attributes map[string]interface{}
	Error      error
	TraceID    string
	SpanID     string
	ParentID   string
}

// NewSimpleTracer creates a new SimpleTracer.
func NewSimpleTracer() *SimpleTracer {
	return &SimpleTracer{
		spans: make([]RecordedSpan, 0),
	}
}

// StartSpan starts a new span.
func (t *SimpleTracer) StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, SpanEnder) {
	cfg := &spanConfig{
		kind:       SpanKindInternal,
		attributes: make(map[string]interface{}),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	span := &RecordedSpan{
		Name:       name,
		StartTime:  time.Now(),
		Kind:       cfg.kind,
		Attributes: cfg.attributes,
		TraceID:    generateID(),
		SpanID:     generateID(),
	}

	// Check for parent span in context
	if parent := spanFromContext(ctx); parent != nil {
		span.ParentID = parent.SpanID
		span.TraceID = parent.TraceID
	}

	ctx = contextWithSpan(ctx, span)

	return ctx, func(err error) {
		span.EndTime = time.Now()
		span.Duration = span.EndTime.Sub(span.StartTime)
		span.Error = err

		t.mu.Lock()
		t.spans = append(t.spans, *span)
		t.mu.Unlock()
	}
}

// Spans returns all recorded spans.
func (t *SimpleTracer) Spans() []RecordedSpan {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]RecordedSpan, len(t.spans))
	copy(result, t.spans)
	return result
}

// Reset clears all recorded spans.
func (t *SimpleTracer) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.spans = t.spans[:0]
}

// --- Context helpers ---

type spanContextKey struct{}

func contextWithSpan(ctx context.Context, span *RecordedSpan) context.Context {
	return context.WithValue(ctx, spanContextKey{}, span)
}

func spanFromContext(ctx context.Context) *RecordedSpan {
	if span, ok := ctx.Value(spanContextKey{}).(*RecordedSpan); ok {
		return span
	}
	return nil
}

// generateID generates a simple ID for spans.
// In production, use a proper trace ID generator.
func generateID() string {
	// Simple time-based ID for the simple tracer
	return time.Now().Format("20060102150405.000000000")
}

// --- Global Tracer ---

var (
	globalTracer   Tracer = NoOpTracer{}
	globalTracerMu sync.RWMutex
)

// SetTracer sets the global tracer.
func SetTracer(t Tracer) {
	globalTracerMu.Lock()
	defer globalTracerMu.Unlock()
	globalTracer = t
}

// GetTracer returns the global tracer.
func GetTracer() Tracer {
	globalTracerMu.RLock()
	defer globalTracerMu.RUnlock()
	return globalTracer
}

// StartSpan starts a span using the global tracer.
func StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, SpanEnder) {
	return GetTracer().StartSpan(ctx, name, opts...)
}

// --- Span Names ---

// Standard span names for quantum-go operations.
const (
	SpanHandshakeInitiator = "quantum.handshake.initiator"
	SpanHandshakeResponder = "quantum.handshake.responder"
	SpanEncrypt            = "quantum.encrypt"
	SpanDecrypt            = "quantum.decrypt"
	SpanSend               = "quantum.send"
	SpanReceive            = "quantum.receive"
	SpanRekey              = "quantum.rekey"
	SpanCHKEMEncapsulate   = "quantum.chkem.encapsulate"
	SpanCHKEMDecapsulate   = "quantum.chkem.decapsulate"
)

// --- OpenTelemetry Integration Helpers ---

// OTelSpanConfig holds configuration for creating OpenTelemetry-compatible spans.
// Use this when integrating with the official OpenTelemetry SDK.
type OTelSpanConfig struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
}

// SpanAttributes for common quantum-go operations.
type SpanAttributes struct {
	SessionID   string
	Role        string
	CipherSuite string
	BytesSent   int64
	BytesRecv   int64
	Error       string
}

// ToMap converts SpanAttributes to a generic map for use with tracers.
func (a SpanAttributes) ToMap() map[string]interface{} {
	m := make(map[string]interface{})
	if a.SessionID != "" {
		m["session.id"] = a.SessionID
	}
	if a.Role != "" {
		m["session.role"] = a.Role
	}
	if a.CipherSuite != "" {
		m["crypto.cipher_suite"] = a.CipherSuite
	}
	if a.BytesSent > 0 {
		m["network.bytes_sent"] = a.BytesSent
	}
	if a.BytesRecv > 0 {
		m["network.bytes_received"] = a.BytesRecv
	}
	if a.Error != "" {
		m["error.message"] = a.Error
	}
	return m
}
