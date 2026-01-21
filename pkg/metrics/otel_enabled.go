//go:build otel
// +build otel

package metrics

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// OTelTracer adapts OpenTelemetry tracing to the metrics.Tracer interface.
type OTelTracer struct {
	tracer trace.Tracer
}

// NewOTelTracer creates an OpenTelemetry tracer using the global provider.
func NewOTelTracer(serviceName string) *OTelTracer {
	if serviceName == "" {
		serviceName = "quantum-go"
	}
	return &OTelTracer{
		tracer: otel.Tracer(serviceName),
	}
}

// StartSpan starts an OpenTelemetry span.
func (t *OTelTracer) StartSpan(ctx context.Context, name string, opts ...SpanOption) (context.Context, SpanEnder) {
	cfg := &spanConfig{
		kind:       SpanKindInternal,
		attributes: make(map[string]interface{}),
	}
	for _, opt := range opts {
		opt(cfg)
	}

	spanOpts := []trace.SpanStartOption{
		trace.WithSpanKind(otelSpanKind(cfg.kind)),
	}
	if len(cfg.attributes) > 0 {
		spanOpts = append(spanOpts, trace.WithAttributes(otelAttributes(cfg.attributes)...))
	}

	ctx, span := t.tracer.Start(ctx, name, spanOpts...)
	return ctx, func(err error) {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else {
			span.SetStatus(codes.Ok, "")
		}
		span.End()
	}
}

// OTelEnabled reports whether OpenTelemetry support is built in.
func OTelEnabled() bool {
	return true
}

func otelSpanKind(kind SpanKind) trace.SpanKind {
	switch kind {
	case SpanKindServer:
		return trace.SpanKindServer
	case SpanKindClient:
		return trace.SpanKindClient
	default:
		return trace.SpanKindInternal
	}
}

func otelAttributes(attrs map[string]interface{}) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		switch val := v.(type) {
		case string:
			out = append(out, attribute.String(k, val))
		case bool:
			out = append(out, attribute.Bool(k, val))
		case int:
			out = append(out, attribute.Int(k, val))
		case int64:
			out = append(out, attribute.Int64(k, val))
		case uint64:
			out = append(out, attribute.Int64(k, int64(val)))
		case float32:
			out = append(out, attribute.Float64(k, float64(val)))
		case float64:
			out = append(out, attribute.Float64(k, val))
		default:
			out = append(out, attribute.String(k, fmt.Sprintf("%v", val)))
		}
	}
	return out
}
