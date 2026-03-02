package core

import "context"

// Fingerprinter is the interface that each protocol detector must implement.
// Implementations must be safe for concurrent use.
type Fingerprinter interface {
	// Name returns the protocol name this fingerprinter detects.
	Name() string

	// Detect attempts to identify the protocol on the given target.
	// It must respect context cancellation and target timeout.
	// It must never panic, even on malformed or unexpected responses.
	Detect(ctx context.Context, target Target) (Result, error)
}
