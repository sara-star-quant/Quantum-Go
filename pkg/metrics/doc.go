// Package metrics provides observability primitives for the quantum-go VPN library.
//
// # Overview
//
// The metrics package offers a complete observability solution including:
//   - Metrics collection (counters, gauges, histograms)
//   - Prometheus-compatible metrics export
//   - Distributed tracing support (OpenTelemetry-compatible interface)
//   - Structured logging with levels
//   - Health check endpoints
//
// # Quick Start
//
// Basic usage with global collector:
//
//	import "github.com/pzverkov/quantum-go/pkg/metrics"
//
//	// Record metrics
//	metrics.Global().SessionStarted()
//	metrics.Global().RecordHandshakeLatency(150 * time.Millisecond)
//	metrics.Global().RecordBytesSent(1024)
//
//	// Start Prometheus server
//	go metrics.ServePrometheus(":9090", metrics.Global(), "quantum_vpn")
//
// # Metrics Collection
//
// The Collector type aggregates metrics from tunnel sessions:
//
//	collector := metrics.NewCollector(metrics.Labels{
//		"instance": "node-1",
//		"region":   "us-west-2",
//	})
//
//	// Session metrics
//	collector.SessionStarted()
//	collector.SessionEnded()
//	collector.RecordHandshakeLatency(d)
//
//	// Traffic metrics
//	collector.RecordBytesSent(n)
//	collector.RecordBytesReceived(n)
//
//	// Security metrics
//	collector.RecordReplayBlocked()
//	collector.RecordAuthFailure()
//	collector.RecordRekeyInitiated()
//
//	// Get snapshot
//	snap := collector.Snapshot()
//
// # Prometheus Export
//
// Export metrics in Prometheus format:
//
//	exporter := metrics.NewPrometheusExporter(collector, "quantum_vpn")
//	http.Handle("/metrics", exporter.Handler())
//
// # Tracing
//
// The package provides a Tracer interface compatible with OpenTelemetry:
//
//	// Use the simple tracer for testing
//	tracer := metrics.NewSimpleTracer()
//	metrics.SetTracer(tracer)
//
//	// OpenTelemetry adapter (uses global provider)
//	otelTracer := metrics.NewOTelTracer("quantum-vpn")
//	metrics.SetTracer(otelTracer)
//	// Build with -tags otel to enable the adapter.
//
//	// Start spans
//	ctx, end := metrics.StartSpan(ctx, metrics.SpanHandshakeInitiator)
//	defer end(nil) // or end(err) on error
//
//	// Use with OpenTelemetry SDK (implement the Tracer interface)
//	// metrics.SetTracer(myOTelAdapter)
//
// # Structured Logging
//
// The Logger provides structured logging with levels:
//
//	logger := metrics.NewLogger(
//		metrics.WithLevel(metrics.LevelInfo),
//		metrics.WithFormat(metrics.FormatJSON),
//		metrics.WithFields(metrics.Fields{"service": "quantum-vpn"}),
//	)
//
//	logger.Info("session established", metrics.Fields{
//		"session_id": sessionID,
//		"cipher":     "AES-256-GCM",
//	})
//
//	// Child loggers
//	sessionLog := logger.Named("session").With(metrics.Fields{"id": sessionID})
//	sessionLog.Debug("encrypting data")
//
// # Health Checks
//
// Provide health check endpoints for Kubernetes and load balancers:
//
//	health := metrics.NewHealthCheck(collector, "1.0.0")
//	health.AddCheck("crypto", func() error {
//		// Verify crypto subsystem
//		return nil
//	})
//
//	http.Handle("/health", health.Handler())
//	http.Handle("/healthz", health.LivenessHandler())
//	http.Handle("/readyz", health.ReadinessHandler())
//
// # Observability Server
//
// Start a complete observability server:
//
//	server := metrics.NewServer(metrics.ServerConfig{
//		Collector:        collector,
//		Version:          "1.0.0",
//		Namespace:        "quantum_vpn",
//		EnablePrometheus: true,
//		EnableHealth:     true,
//	})
//
//	go server.ListenAndServe(":9090")
//
// This provides:
//   - /metrics - Prometheus metrics
//   - /health  - Detailed health status
//   - /healthz - Kubernetes liveness probe
//   - /readyz  - Kubernetes readiness probe
package metrics
