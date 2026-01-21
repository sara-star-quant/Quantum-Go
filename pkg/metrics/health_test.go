package metrics

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthCheckBasic(t *testing.T) {
	c := NewCollector(nil)
	h := NewHealthCheck(c, "1.0.0")

	response := h.Check()

	if response.Status != HealthStatusHealthy {
		t.Errorf("expected healthy status, got %s", response.Status)
	}
	if response.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", response.Version)
	}
	if response.Uptime == "" {
		t.Error("expected non-empty uptime")
	}
}

func TestHealthCheckWithChecks(t *testing.T) {
	c := NewCollector(nil)
	h := NewHealthCheck(c, "1.0.0")

	// Add passing check
	h.AddCheck("passing", func() error {
		return nil
	})

	response := h.Check()

	if response.Status != HealthStatusHealthy {
		t.Errorf("expected healthy status, got %s", response.Status)
	}
	if len(response.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(response.Checks))
	}
	if response.Checks["passing"].Status != HealthStatusHealthy {
		t.Errorf("expected passing check to be healthy")
	}
}

func TestHealthCheckWithFailingCheck(t *testing.T) {
	c := NewCollector(nil)
	h := NewHealthCheck(c, "1.0.0")

	h.AddCheck("failing", func() error {
		return errors.New("something went wrong")
	})

	response := h.Check()

	if response.Status != HealthStatusUnhealthy {
		t.Errorf("expected unhealthy status, got %s", response.Status)
	}
	if response.Checks["failing"].Status != HealthStatusUnhealthy {
		t.Error("expected failing check to be unhealthy")
	}
	if response.Checks["failing"].Message != "something went wrong" {
		t.Errorf("expected error message, got %s", response.Checks["failing"].Message)
	}
}

func TestHealthCheckWithMetrics(t *testing.T) {
	c := NewCollector(nil)
	c.SessionStarted()
	c.RecordBytesSent(1000)

	h := NewHealthCheck(c, "1.0.0")

	response := h.Check()

	if response.Metrics == nil {
		t.Fatal("expected metrics in response")
	}
	if response.Metrics.SessionsActive != 1 {
		t.Errorf("expected 1 active session, got %d", response.Metrics.SessionsActive)
	}
	if response.Metrics.BytesSent != 1000 {
		t.Errorf("expected 1000 bytes sent, got %d", response.Metrics.BytesSent)
	}
}

func TestHealthCheckRemoveCheck(t *testing.T) {
	c := NewCollector(nil)
	h := NewHealthCheck(c, "1.0.0")

	h.AddCheck("temp", func() error {
		return errors.New("fail")
	})

	response := h.Check()
	if response.Status != HealthStatusUnhealthy {
		t.Error("expected unhealthy with failing check")
	}

	h.RemoveCheck("temp")

	response = h.Check()
	if response.Status != HealthStatusHealthy {
		t.Error("expected healthy after removing check")
	}
}

func TestHealthCheckHandler(t *testing.T) {
	c := NewCollector(nil)
	h := NewHealthCheck(c, "1.0.0")

	handler := h.Handler()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	var response HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response.Status != HealthStatusHealthy {
		t.Errorf("expected healthy status, got %s", response.Status)
	}
}

func TestHealthCheckHandlerUnhealthy(t *testing.T) {
	c := NewCollector(nil)
	h := NewHealthCheck(c, "1.0.0")
	h.AddCheck("failing", func() error {
		return errors.New("fail")
	})

	handler := h.Handler()
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", resp.StatusCode)
	}
}

func TestLivenessHandler(t *testing.T) {
	c := NewCollector(nil)
	h := NewHealthCheck(c, "1.0.0")

	// Even with failing checks, liveness should return OK
	h.AddCheck("failing", func() error {
		return errors.New("fail")
	})

	handler := h.LivenessHandler()
	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 for liveness, got %d", resp.StatusCode)
	}
}

func TestReadinessHandler(t *testing.T) {
	c := NewCollector(nil)
	h := NewHealthCheck(c, "1.0.0")

	// Healthy case
	handler := h.ReadinessHandler()
	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 for readiness, got %d", resp.StatusCode)
	}

	// Unhealthy case
	h.AddCheck("failing", func() error {
		return errors.New("fail")
	})

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	resp = w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected status 503 for unhealthy readiness, got %d", resp.StatusCode)
	}
}

func TestHealthCheckErrorRate(t *testing.T) {
	c := NewCollector(nil)
	h := NewHealthCheck(c, "1.0.0")

	// Add many successful packets
	for i := 0; i < 100; i++ {
		c.RecordPacketSent()
	}

	response := h.Check()
	if response.Metrics.ErrorRate != 0 {
		t.Errorf("expected 0 error rate, got %f", response.Metrics.ErrorRate)
	}

	// Add some errors (>1% threshold for degraded)
	for i := 0; i < 10; i++ {
		c.RecordEncryptError()
	}

	response = h.Check()
	if response.Status != HealthStatusDegraded {
		t.Errorf("expected degraded status with high error rate, got %s", response.Status)
	}
}

func TestServerHandler(t *testing.T) {
	c := NewCollector(nil)

	server := NewServer(ServerConfig{
		Collector:        c,
		Version:          "1.0.0",
		Namespace:        "test",
		EnablePrometheus: true,
		EnableHealth:     true,
	})

	// Test metrics endpoint
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Error("expected /metrics to return 200")
	}

	// Test health endpoint
	req = httptest.NewRequest("GET", "/health", nil)
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Error("expected /health to return 200")
	}

	// Test healthz endpoint
	req = httptest.NewRequest("GET", "/healthz", nil)
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Error("expected /healthz to return 200")
	}

	// Test readyz endpoint
	req = httptest.NewRequest("GET", "/readyz", nil)
	w = httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Error("expected /readyz to return 200")
	}
}

func TestServerAddHealthCheck(t *testing.T) {
	server := NewServer(ServerConfig{
		EnableHealth: true,
	})

	server.AddHealthCheck("test", func() error {
		return errors.New("fail")
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Error("expected /health to return 503 with failing check")
	}
}

func TestFormatDuration(t *testing.T) {
	// Basic smoke test - formatDuration is internal
	result := formatDuration(10 * 1000000000) // 10 seconds in nanoseconds
	if result == "" {
		t.Error("formatDuration should return non-empty string")
	}
}
