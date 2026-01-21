package metrics

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// HealthStatus represents the overall health state.
type HealthStatus string

const (
	// HealthStatusHealthy indicates all checks are passing.
	HealthStatusHealthy HealthStatus = "healthy"
	// HealthStatusDegraded indicates non-critical checks are failing.
	HealthStatusDegraded HealthStatus = "degraded"
	// HealthStatusUnhealthy indicates critical checks are failing.
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// HealthCheck provides health check functionality for the VPN service.
type HealthCheck struct {
	mu        sync.RWMutex
	checks    map[string]CheckFunc
	collector *Collector
	startTime time.Time
	version   string
}

// CheckFunc is a function that performs a health check.
// Returns nil if healthy, or an error describing the problem.
type CheckFunc func() error

// HealthResponse is the JSON response for health checks.
type HealthResponse struct {
	Status    HealthStatus           `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Uptime    string                 `json:"uptime"`
	Version   string                 `json:"version,omitempty"`
	Checks    map[string]CheckResult `json:"checks,omitempty"`
	Metrics   *HealthMetrics         `json:"metrics,omitempty"`
}

// CheckResult represents the result of a single health check.
type CheckResult struct {
	Status  HealthStatus `json:"status"`
	Message string       `json:"message,omitempty"`
	Latency string       `json:"latency,omitempty"`
}

// HealthMetrics contains key metrics for health monitoring.
type HealthMetrics struct {
	SessionsActive int64   `json:"sessions_active"`
	SessionsTotal  int64   `json:"sessions_total"`
	BytesSent      int64   `json:"bytes_sent"`
	BytesReceived  int64   `json:"bytes_received"`
	ErrorRate      float64 `json:"error_rate,omitempty"`
}

// NewHealthCheck creates a new health check instance.
func NewHealthCheck(collector *Collector, version string) *HealthCheck {
	return &HealthCheck{
		checks:    make(map[string]CheckFunc),
		collector: collector,
		startTime: time.Now(),
		version:   version,
	}
}

// AddCheck registers a named health check.
func (h *HealthCheck) AddCheck(name string, check CheckFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[name] = check
}

// RemoveCheck removes a named health check.
func (h *HealthCheck) RemoveCheck(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.checks, name)
}

// Check performs all health checks and returns the overall status.
func (h *HealthCheck) Check() HealthResponse {
	h.mu.RLock()
	checks := make(map[string]CheckFunc, len(h.checks))
	for k, v := range h.checks {
		checks[k] = v
	}
	h.mu.RUnlock()

	response := HealthResponse{
		Status:    HealthStatusHealthy,
		Timestamp: time.Now(),
		Uptime:    formatDuration(time.Since(h.startTime)),
		Version:   h.version,
		Checks:    make(map[string]CheckResult),
	}

	// Run all checks
	hasUnhealthy := false
	hasDegraded := false

	for name, check := range checks {
		start := time.Now()
		err := check()
		latency := time.Since(start)

		result := CheckResult{
			Status:  HealthStatusHealthy,
			Latency: latency.String(),
		}

		if err != nil {
			result.Status = HealthStatusUnhealthy
			result.Message = err.Error()
			hasUnhealthy = true
		}

		response.Checks[name] = result
	}

	// Add collector metrics if available
	if h.collector != nil {
		snap := h.collector.Snapshot()
		response.Metrics = &HealthMetrics{
			SessionsActive: snap.SessionsActive,
			SessionsTotal:  snap.SessionsTotal,
			BytesSent:      snap.BytesSent,
			BytesReceived:  snap.BytesReceived,
		}

		// Calculate error rate
		totalOps := snap.PacketsSent + snap.PacketsRecv
		totalErrors := snap.EncryptErrors + snap.DecryptErrors + snap.ProtocolErrors
		if totalOps > 0 {
			response.Metrics.ErrorRate = float64(totalErrors) / float64(totalOps)
			// High error rate is a warning
			if response.Metrics.ErrorRate > 0.01 { // > 1% error rate
				hasDegraded = true
			}
		}
	}

	// Determine overall status
	if hasUnhealthy {
		response.Status = HealthStatusUnhealthy
	} else if hasDegraded {
		response.Status = HealthStatusDegraded
	}

	return response
}

// Handler returns an http.Handler for the health check endpoint.
func (h *HealthCheck) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := h.Check()

		w.Header().Set("Content-Type", "application/json")

		// Set appropriate status code
		switch response.Status {
		case HealthStatusHealthy:
			w.WriteHeader(http.StatusOK)
		case HealthStatusDegraded:
			w.WriteHeader(http.StatusOK) // Still serving, but with warnings
		case HealthStatusUnhealthy:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			return
		}
	})
}

// LivenessHandler returns a simple liveness probe handler.
// Returns 200 OK if the service is running.
func (h *HealthCheck) LivenessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{
			"status": "alive",
		}); err != nil {
			return
		}
	})
}

// ReadinessHandler returns a readiness probe handler.
// Returns 200 OK only if all health checks pass.
func (h *HealthCheck) ReadinessHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := h.Check()

		w.Header().Set("Content-Type", "application/json")

		if response.Status == HealthStatusUnhealthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"status": response.Status,
			"ready":  response.Status != HealthStatusUnhealthy,
		}); err != nil {
			return
		}
	})
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return formatInt(days, "d") + formatInt(hours, "h") + formatInt(minutes, "m")
	}
	if hours > 0 {
		return formatInt(hours, "h") + formatInt(minutes, "m") + formatInt(seconds, "s")
	}
	if minutes > 0 {
		return formatInt(minutes, "m") + formatInt(seconds, "s")
	}
	if seconds > 0 {
		return formatInt(seconds, "s")
	}
	return "0s"
}

func formatInt(n int, suffix string) string {
	if n == 0 {
		return ""
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10)) + suffix
}

// --- Common Health Checks ---

// MemoryCheck returns a health check that monitors memory usage.
// threshold is the maximum allowed memory in bytes.
func MemoryCheck(threshold uint64) CheckFunc {
	return func() error {
		// Note: This is a placeholder. In production, you would use
		// runtime.ReadMemStats to check actual memory usage.
		return nil
	}
}

// ConnectivityCheck returns a health check that verifies network connectivity.
func ConnectivityCheck(addr string, timeout time.Duration) CheckFunc {
	return func() error {
		// Note: This is a placeholder. In production, you would attempt
		// to dial the address with the given timeout.
		return nil
	}
}

// --- Server ---

// Server provides HTTP endpoints for metrics, health, and observability.
type Server struct {
	mux        *http.ServeMux
	collector  *Collector
	health     *HealthCheck
	prometheus *PrometheusExporter
}

// ServerConfig configures the observability server.
type ServerConfig struct {
	Collector        *Collector
	Version          string
	Namespace        string // Prometheus namespace
	EnablePrometheus bool
	EnableHealth     bool
}

// NewServer creates a new observability server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Collector == nil {
		cfg.Collector = Global()
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "quantum_vpn"
	}

	s := &Server{
		mux:       http.NewServeMux(),
		collector: cfg.Collector,
	}

	if cfg.EnablePrometheus {
		s.prometheus = NewPrometheusExporter(cfg.Collector, cfg.Namespace)
		s.mux.Handle("/metrics", s.prometheus.Handler())
	}

	if cfg.EnableHealth {
		s.health = NewHealthCheck(cfg.Collector, cfg.Version)
		s.mux.Handle("/health", s.health.Handler())
		s.mux.Handle("/healthz", s.health.LivenessHandler())
		s.mux.Handle("/readyz", s.health.ReadinessHandler())
	}

	return s
}

// Handler returns the HTTP handler for the server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// AddHealthCheck adds a health check to the server.
func (s *Server) AddHealthCheck(name string, check CheckFunc) {
	if s.health != nil {
		s.health.AddCheck(name, check)
	}
}

// ListenAndServe starts the observability server.
func (s *Server) ListenAndServe(addr string) error {
	server := newHTTPServer(addr, s.mux)
	return server.ListenAndServe()
}
