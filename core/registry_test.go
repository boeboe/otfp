package core

import (
	"context"
	"testing"
)

// mockFingerprinter is a test double for Fingerprinter.
type mockFingerprinter struct {
	name     Protocol
	priority int
	result   Result
	err      error
}

func (m *mockFingerprinter) Name() Protocol { return m.name }

func (m *mockFingerprinter) Priority() int { return m.priority }

func (m *mockFingerprinter) Detect(ctx context.Context, target Target) (Result, error) {
	return m.result, m.err
}

func TestRegistryRegister(t *testing.T) {
	reg := NewRegistry()

	fp := &mockFingerprinter{name: "Test"}
	if err := reg.Register(fp); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Duplicate registration.
	if err := reg.Register(fp); err == nil {
		t.Error("expected error on duplicate registration")
	}
}

func TestRegistryGet(t *testing.T) {
	reg := NewRegistry()
	fp := &mockFingerprinter{name: "Test"}
	_ = reg.Register(fp)

	if got := reg.Get("Test"); got == nil {
		t.Error("Get returned nil for registered fingerprinter")
	}
	if got := reg.Get("NonExistent"); got != nil {
		t.Error("Get returned non-nil for unregistered fingerprinter")
	}
}

func TestRegistryAll(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{name: "A", priority: 10})
	_ = reg.Register(&mockFingerprinter{name: "B", priority: 20})
	_ = reg.Register(&mockFingerprinter{name: "C", priority: 30})

	all := reg.All()
	if len(all) != 3 {
		t.Errorf("All() returned %d items, want 3", len(all))
	}
	// All() now returns sorted by priority (ascending).
	if all[0].Name() != "A" || all[1].Name() != "B" || all[2].Name() != "C" {
		t.Error("All() items not sorted by priority")
	}
}

func TestRegistryNames(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(&mockFingerprinter{name: "X"})
	_ = reg.Register(&mockFingerprinter{name: "Y"})

	names := reg.Names()
	if len(names) != 2 || names[0] != "X" || names[1] != "Y" {
		t.Errorf("Names() = %v, want [X Y]", names)
	}
}
