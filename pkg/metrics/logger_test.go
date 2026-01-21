package metrics

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLoggerLevels(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{LevelSilent, "SILENT"},
	}

	for _, tt := range tests {
		if tt.level.String() != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, tt.level.String())
		}
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected Level
	}{
		{"DEBUG", LevelDebug},
		{"debug", LevelDebug},
		{"INFO", LevelInfo},
		{"WARN", LevelWarn},
		{"WARNING", LevelWarn},
		{"ERROR", LevelError},
		{"SILENT", LevelSilent},
		{"OFF", LevelSilent},
		{"invalid", LevelInfo}, // default
	}

	for _, tt := range tests {
		result := ParseLevel(tt.input)
		if result != tt.expected {
			t.Errorf("ParseLevel(%q) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}

func TestLoggerTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelDebug),
		WithFormat(FormatText),
	)

	logger.Info("test message", Fields{"key": "value"})

	output := buf.String()
	if !strings.Contains(output, "INFO") {
		t.Error("expected INFO level in output")
	}
	if !strings.Contains(output, "test message") {
		t.Error("expected message in output")
	}
	if !strings.Contains(output, "key=value") {
		t.Error("expected field in output")
	}
}

func TestLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelDebug),
		WithFormat(FormatJSON),
	)

	logger.Info("test message", Fields{"key": "value"})

	output := buf.String()

	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry["level"] != "INFO" {
		t.Errorf("expected level INFO, got %v", entry["level"])
	}
	if entry["msg"] != "test message" {
		t.Errorf("expected msg 'test message', got %v", entry["msg"])
	}
	if entry["key"] != "value" {
		t.Errorf("expected key=value, got key=%v", entry["key"])
	}
	if _, ok := entry["time"]; !ok {
		t.Error("expected time field")
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelWarn),
		WithFormat(FormatText),
	)

	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")

	output := buf.String()

	if strings.Contains(output, "debug message") {
		t.Error("debug message should be filtered")
	}
	if strings.Contains(output, "info message") {
		t.Error("info message should be filtered")
	}
	if !strings.Contains(output, "warn message") {
		t.Error("warn message should be present")
	}
	if !strings.Contains(output, "error message") {
		t.Error("error message should be present")
	}
}

func TestLoggerSilentLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelSilent),
	)

	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")

	if buf.Len() > 0 {
		t.Error("expected no output with silent level")
	}
}

func TestLoggerWith(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelDebug),
		WithFormat(FormatJSON),
		WithFields(Fields{"base": "field"}),
	)

	childLogger := logger.With(Fields{"child": "field"})
	childLogger.Info("test")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}

	if entry["base"] != "field" {
		t.Error("expected base field")
	}
	if entry["child"] != "field" {
		t.Error("expected child field")
	}
}

func TestLoggerNamed(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelDebug),
		WithFormat(FormatJSON),
		WithName("parent"),
	)

	childLogger := logger.Named("child")
	childLogger.Info("test")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}

	if entry["logger"] != "parent.child" {
		t.Errorf("expected logger 'parent.child', got %v", entry["logger"])
	}
}

func TestLoggerSetLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelError),
		WithFormat(FormatText),
	)

	logger.Info("should not appear")
	if buf.Len() > 0 {
		t.Error("info should be filtered")
	}

	logger.SetLevel(LevelInfo)
	logger.Info("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Error("info should now be logged")
	}
}

func TestLoggerDefaultFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelDebug),
		WithFormat(FormatJSON),
		WithFields(Fields{"service": "test", "version": "1.0"}),
	)

	logger.Info("test message")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}

	if entry["service"] != "test" {
		t.Error("expected service field")
	}
	if entry["version"] != "1.0" {
		t.Error("expected version field")
	}
}

func TestLoggerFieldMerging(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelDebug),
		WithFormat(FormatJSON),
		WithFields(Fields{"a": "1"}),
	)

	// Call with multiple field maps
	logger.Info("test", Fields{"b": "2"}, Fields{"c": "3"})

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}

	if entry["a"] != "1" {
		t.Error("expected a=1")
	}
	if entry["b"] != "2" {
		t.Error("expected b=2")
	}
	if entry["c"] != "3" {
		t.Error("expected c=3")
	}
}

func TestNullLogger(t *testing.T) {
	logger := NullLogger()

	// Should not panic
	logger.Debug("test")
	logger.Info("test")
	logger.Warn("test")
	logger.Error("test")
}

func TestGlobalLogger(t *testing.T) {
	var buf bytes.Buffer
	custom := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelDebug),
		WithFormat(FormatText),
	)

	SetLogger(custom)

	// Use global functions
	Info("global test")

	if !strings.Contains(buf.String(), "global test") {
		t.Error("expected message from global logger")
	}
}

func TestLoggerTextFieldOrder(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(
		WithOutput(&buf),
		WithLevel(LevelDebug),
		WithFormat(FormatText),
	)

	// Fields should be sorted alphabetically
	logger.Info("test", Fields{"zebra": "1", "apple": "2", "mango": "3"})

	output := buf.String()

	// Check that fields appear in sorted order
	appleIdx := strings.Index(output, "apple=")
	mangoIdx := strings.Index(output, "mango=")
	zebraIdx := strings.Index(output, "zebra=")

	if appleIdx > mangoIdx || mangoIdx > zebraIdx {
		t.Error("fields should be sorted alphabetically")
	}
}
