//go:build !otel

package metrics

import (
	"context"
	"testing"
)

type stubCtxKey struct{}

func TestOTelStubIsInertWithoutTheBuildTag(t *testing.T) {
	if OTelEnabled() {
		t.Fatal("OTelEnabled must be false without the otel build tag")
	}
	tr := NewOTelTracer("svc")
	ctx := context.WithValue(context.Background(), stubCtxKey{}, 1)
	got, end := tr.StartSpan(ctx, "span")
	if got != ctx {
		t.Fatal("the stub tracer must hand back the context it was given")
	}
	end(nil) // must not panic
}
