package metrics

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNoOpTracer(t *testing.T) {
	tracer := NoOpTracer{}
	ctx := context.Background()

	newCtx, end := tracer.StartSpan(ctx, "test")

	// Should return same context
	if newCtx != ctx {
		t.Error("NoOpTracer should return same context")
	}

	// End should not panic
	end(nil)
	end(errors.New("test error"))
}

func TestSimpleTracer(t *testing.T) {
	tracer := NewSimpleTracer()
	ctx := context.Background()

	_, end := tracer.StartSpan(ctx, "test-span", WithSpanKind(SpanKindServer))
	time.Sleep(10 * time.Millisecond)
	end(nil)

	spans := tracer.Spans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	span := spans[0]
	if span.Name != "test-span" {
		t.Errorf("expected name 'test-span', got %s", span.Name)
	}
	if span.Kind != SpanKindServer {
		t.Errorf("expected kind SpanKindServer, got %v", span.Kind)
	}
	if span.Duration < 10*time.Millisecond {
		t.Errorf("expected duration >= 10ms, got %v", span.Duration)
	}
	if span.Error != nil {
		t.Error("expected no error")
	}
}

func TestSimpleTracerWithError(t *testing.T) {
	tracer := NewSimpleTracer()
	ctx := context.Background()

	expectedErr := errors.New("test error")
	_, end := tracer.StartSpan(ctx, "failing-span")
	end(expectedErr)

	spans := tracer.Spans()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	if spans[0].Error != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, spans[0].Error)
	}
}

func TestSimpleTracerAttributes(t *testing.T) {
	tracer := NewSimpleTracer()
	ctx := context.Background()

	attrs := map[string]interface{}{
		"session_id": "abc123",
		"bytes":      1024,
	}

	_, end := tracer.StartSpan(ctx, "test", WithAttributes(attrs))
	end(nil)

	spans := tracer.Spans()
	if spans[0].Attributes["session_id"] != "abc123" {
		t.Error("expected session_id attribute")
	}
	if spans[0].Attributes["bytes"] != 1024 {
		t.Error("expected bytes attribute")
	}
}

func TestSimpleTracerParentSpan(t *testing.T) {
	tracer := NewSimpleTracer()
	ctx := context.Background()

	// Create parent span
	ctx, endParent := tracer.StartSpan(ctx, "parent")

	// Create child span
	_, endChild := tracer.StartSpan(ctx, "child")
	endChild(nil)

	endParent(nil)

	spans := tracer.Spans()
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}

	// Find child span
	var child *RecordedSpan
	for i := range spans {
		if spans[i].Name == "child" {
			child = &spans[i]
			break
		}
	}

	if child == nil {
		t.Fatal("child span not found")
	}

	if child.ParentID == "" {
		t.Error("expected child to have parent ID")
	}
}

func TestSimpleTracerReset(t *testing.T) {
	tracer := NewSimpleTracer()
	ctx := context.Background()

	_, end := tracer.StartSpan(ctx, "span1")
	end(nil)
	_, end = tracer.StartSpan(ctx, "span2")
	end(nil)

	if len(tracer.Spans()) != 2 {
		t.Fatal("expected 2 spans before reset")
	}

	tracer.Reset()

	if len(tracer.Spans()) != 0 {
		t.Error("expected 0 spans after reset")
	}
}

func TestGlobalTracer(t *testing.T) {
	// Default is NoOpTracer
	tracer := GetTracer()
	if _, ok := tracer.(NoOpTracer); !ok {
		t.Error("default tracer should be NoOpTracer")
	}

	// Set custom tracer
	simple := NewSimpleTracer()
	SetTracer(simple)

	if GetTracer() != simple {
		t.Error("expected custom tracer")
	}

	// Test StartSpan with global tracer
	ctx := context.Background()
	_, end := StartSpan(ctx, "global-test")
	end(nil)

	if len(simple.Spans()) != 1 {
		t.Error("expected span from global StartSpan")
	}

	// Reset to NoOp
	SetTracer(NoOpTracer{})
}

func TestSpanKinds(t *testing.T) {
	if SpanKindInternal != 0 {
		t.Error("SpanKindInternal should be 0")
	}
	if SpanKindServer != 1 {
		t.Error("SpanKindServer should be 1")
	}
	if SpanKindClient != 2 {
		t.Error("SpanKindClient should be 2")
	}
}

func TestSpanAttributes(t *testing.T) {
	attrs := SpanAttributes{
		SessionID:   "sess-123",
		Role:        "initiator",
		CipherSuite: "AES-256-GCM",
		BytesSent:   1000,
		BytesRecv:   2000,
		Error:       "test error",
	}

	m := attrs.ToMap()

	if m["session.id"] != "sess-123" {
		t.Error("expected session.id")
	}
	if m["session.role"] != "initiator" {
		t.Error("expected session.role")
	}
	if m["crypto.cipher_suite"] != "AES-256-GCM" {
		t.Error("expected crypto.cipher_suite")
	}
	if m["network.bytes_sent"] != int64(1000) {
		t.Error("expected network.bytes_sent")
	}
	if m["network.bytes_received"] != int64(2000) {
		t.Error("expected network.bytes_received")
	}
	if m["error.message"] != "test error" {
		t.Error("expected error.message")
	}
}

func TestSpanAttributesEmpty(t *testing.T) {
	attrs := SpanAttributes{}
	m := attrs.ToMap()

	if len(m) != 0 {
		t.Errorf("expected empty map for empty attributes, got %d items", len(m))
	}
}

func TestSpanNames(t *testing.T) {
	// Verify span name constants are defined
	names := []string{
		SpanHandshakeInitiator,
		SpanHandshakeResponder,
		SpanEncrypt,
		SpanDecrypt,
		SpanSend,
		SpanReceive,
		SpanRekey,
		SpanCHKEMEncapsulate,
		SpanCHKEMDecapsulate,
	}

	for _, name := range names {
		if name == "" {
			t.Error("span name should not be empty")
		}
	}
}

func TestSimpleTracerConcurrency(t *testing.T) {
	tracer := NewSimpleTracer()
	ctx := context.Background()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				_, end := tracer.StartSpan(ctx, "concurrent-span")
				time.Sleep(time.Microsecond)
				end(nil)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	spans := tracer.Spans()
	if len(spans) != 1000 {
		t.Errorf("expected 1000 spans, got %d", len(spans))
	}
}
