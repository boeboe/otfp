package core

import (
	"fmt"
	"sync"
)

// Registry holds registered protocol fingerprinters.
// It is safe for concurrent use.
type Registry struct {
	mu           sync.RWMutex
	fingerprints []Fingerprinter
	byName       map[string]Fingerprinter
}

// NewRegistry creates an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		byName: make(map[string]Fingerprinter),
	}
}

// Register adds a fingerprinter to the registry.
// Returns an error if a fingerprinter with the same name is already registered.
func (r *Registry) Register(fp Fingerprinter) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := fp.Name()
	if _, exists := r.byName[name]; exists {
		return fmt.Errorf("fingerprinter %q already registered", name)
	}

	r.fingerprints = append(r.fingerprints, fp)
	r.byName[name] = fp
	return nil
}

// Get returns the fingerprinter with the given name, or nil if not found.
func (r *Registry) Get(name string) Fingerprinter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byName[name]
}

// All returns all registered fingerprinters in registration order.
func (r *Registry) All() []Fingerprinter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Fingerprinter, len(r.fingerprints))
	copy(result, r.fingerprints)
	return result
}

// Names returns the names of all registered fingerprinters.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, len(r.fingerprints))
	for i, fp := range r.fingerprints {
		names[i] = fp.Name()
	}
	return names
}
