//go:build !otel
// +build !otel

package metrics

import "context"

// OTelTracer is a stub tracer when built without OpenTelemetry support.
type OTelTracer struct{}

// NewOTelTracer returns a no-op tracer when OpenTelemetry is not enabled.
func NewOTelTracer(serviceName string) *OTelTracer {
	return &OTelTracer{}
}

// StartSpan returns a no-op span.
func (t *OTelTracer) StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, SpanEnder) {
	return ctx, func(err error) {}
}

// OTelEnabled reports whether OpenTelemetry support is built in.
func OTelEnabled() bool {
	return false
}
