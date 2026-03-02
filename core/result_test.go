package core

import (
	"strings"
	"testing"
)

func TestNoMatch(t *testing.T) {
	r := NoMatch("TestProto")
	if r.Matched {
		t.Error("NoMatch should have Matched=false")
	}
	if r.Protocol != "TestProto" {
		t.Errorf("Protocol = %q, want %q", r.Protocol, "TestProto")
	}
	if r.Confidence != 0.0 {
		t.Errorf("Confidence = %f, want 0.0", r.Confidence)
	}
}

func TestMatch(t *testing.T) {
	r := Match("TestProto", 0.95, "test details")
	if !r.Matched {
		t.Error("Match should have Matched=true")
	}
	if r.Protocol != "TestProto" {
		t.Errorf("Protocol = %q, want %q", r.Protocol, "TestProto")
	}
	if r.Confidence != 0.95 {
		t.Errorf("Confidence = %f, want 0.95", r.Confidence)
	}
	if r.Details != "test details" {
		t.Errorf("Details = %q, want %q", r.Details, "test details")
	}
}

func TestResultString(t *testing.T) {
	t.Run("matched", func(t *testing.T) {
		r := Match("Modbus", 0.90, "good match")
		s := r.String()
		if !strings.Contains(s, "Modbus") {
			t.Errorf("String() missing protocol name: %s", s)
		}
		if !strings.Contains(s, "0.90") {
			t.Errorf("String() missing confidence: %s", s)
		}
	})

	t.Run("not matched", func(t *testing.T) {
		r := NoMatch("Modbus")
		s := r.String()
		if !strings.Contains(s, "false") {
			t.Errorf("String() missing 'false': %s", s)
		}
	})
}
