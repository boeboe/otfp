package core

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestEngineDetectBestMatch(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:   "Low",
		result: Match("Low", 0.3, "low match"),
	})
	_ = reg.Register(&mockFingerprinter{
		name:   "High",
		result: Match("High", 0.95, "high match"),
	})

	engine := NewEngine(reg, DefaultEngineConfig())
	result := engine.Detect(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	if result.Protocol != "High" {
		t.Errorf("Detect() returned %q, want High", result.Protocol)
	}
	if result.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want 0.95", result.Confidence)
	}
}

func TestEngineDetectUnknown(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:   "Fail",
		result: NoMatch("Fail"),
	})

	engine := NewEngine(reg, DefaultEngineConfig())
	result := engine.Detect(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	if result.Protocol != "Unknown" {
		t.Errorf("Detect() returned %q, want Unknown", result.Protocol)
	}
	if result.Matched {
		t.Error("Expected Matched=false")
	}
}

func TestEngineDetectProtocol(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:   "TestProto",
		result: Match("TestProto", 0.9, "ok"),
	})

	engine := NewEngine(reg, DefaultEngineConfig())

	t.Run("existing protocol", func(t *testing.T) {
		result, err := engine.DetectProtocol(context.Background(), Target{IP: "127.0.0.1", Port: 80}, "TestProto")
		if err != nil {
			t.Fatalf("DetectProtocol error: %v", err)
		}
		if !result.Matched {
			t.Error("Expected match")
		}
	})

	t.Run("missing protocol", func(t *testing.T) {
		_, err := engine.DetectProtocol(context.Background(), Target{IP: "127.0.0.1", Port: 80}, "NoSuch")
		if err == nil {
			t.Error("Expected error for missing protocol")
		}
	})
}

func TestEngineSequential(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:   "A",
		result: Match("A", 0.5, "partial"),
	})
	_ = reg.Register(&mockFingerprinter{
		name:   "B",
		result: Match("B", 0.8, "good"),
	})

	config := EngineConfig{
		Parallel:                false,
		EarlyStop:               false,
		HighConfidenceThreshold: 0.9,
	}
	engine := NewEngine(reg, config)
	results := engine.DetectAll(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	if len(results) != 2 {
		t.Fatalf("DetectAll returned %d results, want 2", len(results))
	}
	// Should be sorted by confidence.
	if results[0].Confidence < results[1].Confidence {
		t.Error("Results not sorted by confidence descending")
	}
}

func TestEngineEarlyStop(t *testing.T) {
	callCount := 0
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:   "High",
		result: Match("High", 0.95, "early"),
	})
	_ = reg.Register(&mockFingerprinter{
		name: "Never",
		result: func() Result {
			callCount++
			return NoMatch("Never")
		}(),
	})

	config := EngineConfig{
		Parallel:                false,
		EarlyStop:               true,
		HighConfidenceThreshold: 0.9,
	}
	engine := NewEngine(reg, config)
	results := engine.DetectAll(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	// With early stop, should only have 1 result since first match is high confidence.
	if len(results) != 1 {
		t.Errorf("Expected 1 result with early stop, got %d", len(results))
	}
}

func TestEngineWithErrors(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name: "Error",
		err:  fmt.Errorf("connection failed"),
	})

	engine := NewEngine(reg, DefaultEngineConfig())
	result := engine.Detect(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	if result.Protocol != "Unknown" {
		t.Errorf("Expected Unknown, got %q", result.Protocol)
	}
}

func TestEngineContextCancellation(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{
		name:   "Slow",
		result: NoMatch("Slow"),
	})

	config := EngineConfig{Parallel: false}
	engine := NewEngine(reg, config)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // Ensure context is cancelled.

	results := engine.DetectAll(ctx, Target{IP: "127.0.0.1", Port: 1234})
	// With cancelled context, we may get 0 results.
	_ = results // Just ensure no panic.
}

func TestEngineEmptyRegistry(t *testing.T) {
	reg := NewRegistry()
	engine := NewEngine(reg, DefaultEngineConfig())
	result := engine.Detect(context.Background(), Target{IP: "127.0.0.1", Port: 1234})

	if result.Protocol != "Unknown" {
		t.Errorf("Expected Unknown, got %q", result.Protocol)
	}
}
