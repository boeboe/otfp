package core

import (
	"context"
	"sort"
	"sync"
)

// EngineConfig configures the detection engine behavior.
type EngineConfig struct {
	// Parallel enables parallel protocol detection.
	// When false, protocols are tested sequentially.
	Parallel bool

	// EarlyStop causes the engine to stop after the first high-confidence match
	// (Confidence >= HighConfidenceThreshold).
	EarlyStop bool

	// HighConfidenceThreshold is the minimum confidence to trigger early stop.
	// Default: 0.9
	HighConfidenceThreshold float64

	// MaxConcurrency limits the number of in-flight goroutines when Parallel
	// is true. Zero or negative means unbounded.
	MaxConcurrency int
}

// DefaultEngineConfig returns sensible default engine configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Parallel:                true,
		EarlyStop:               true,
		HighConfidenceThreshold: 0.9,
		MaxConcurrency:          0,
	}
}

// SafeEngineConfig returns a conservative configuration suitable for
// production OT environments where minimising network impact is critical.
func SafeEngineConfig() EngineConfig {
	return EngineConfig{
		Parallel:                false,
		EarlyStop:               true,
		HighConfidenceThreshold: 0.9,
		MaxConcurrency:          1,
	}
}

// Engine orchestrates protocol detection using registered fingerprinters.
type Engine struct {
	registry *Registry
	config   EngineConfig
}

// NewEngine creates a new detection engine with the given registry and config.
func NewEngine(registry *Registry, config EngineConfig) *Engine {
	if config.HighConfidenceThreshold <= 0 {
		config.HighConfidenceThreshold = 0.9
	}
	return &Engine{
		registry: registry,
		config:   config,
	}
}

// DetectAll runs all registered fingerprinters against the target and returns
// all results sorted by confidence (highest first).
func (e *Engine) DetectAll(ctx context.Context, target Target) []Result {
	fps := e.registry.All()
	if len(fps) == 0 {
		return nil
	}

	if e.config.Parallel {
		return e.detectParallel(ctx, target, fps)
	}
	return e.detectSequential(ctx, target, fps)
}

// Detect runs all fingerprinters and returns the best match.
// If no protocol is detected, it returns a Result with Protocol=ProtocolUnknown.
func (e *Engine) Detect(ctx context.Context, target Target) Result {
	results := e.DetectAll(ctx, target)

	// Filter matched results.
	var matched []Result
	for _, r := range results {
		if r.Matched {
			matched = append(matched, r)
		}
	}

	if len(matched) == 0 {
		return Result{
			Protocol:   ProtocolUnknown,
			Matched:    false,
			Confidence: 0.0,
			Details:    "No OT protocol detected",
		}
	}

	// Return highest confidence.
	return matched[0]
}

// DetectProtocol runs a specific named fingerprinter against the target.
func (e *Engine) DetectProtocol(ctx context.Context, target Target, protocol Protocol) (Result, error) {
	fp := e.registry.Get(protocol)
	if fp == nil {
		return Result{}, &ProtocolNotFoundError{Protocol: protocol}
	}
	return fp.Detect(ctx, target)
}

// ProtocolNotFoundError is returned when a requested protocol is not registered.
type ProtocolNotFoundError struct {
	Protocol Protocol
}

func (e *ProtocolNotFoundError) Error() string {
	return "protocol not registered: " + string(e.Protocol)
}

func (e *Engine) detectSequential(ctx context.Context, target Target, fps []Fingerprinter) []Result {
	var results []Result

	for _, fp := range fps {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		result, err := fp.Detect(ctx, target)
		if err != nil {
			results = append(results, ErrorResult(fp.Name(), err))
			continue
		}

		results = append(results, result)

		if e.config.EarlyStop && result.Matched && result.Confidence >= e.config.HighConfidenceThreshold {
			break
		}
	}

	sortResults(results)
	return results
}

func (e *Engine) detectParallel(ctx context.Context, target Target, fps []Fingerprinter) []Result {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type indexedResult struct {
		result Result
		index  int
	}

	ch := make(chan indexedResult, len(fps))
	var wg sync.WaitGroup

	// Semaphore for concurrency limiting. Nil channel = unbounded.
	var sem chan struct{}
	if e.config.MaxConcurrency > 0 {
		sem = make(chan struct{}, e.config.MaxConcurrency)
	}

	for i, fp := range fps {
		wg.Add(1)
		go func(idx int, fp Fingerprinter) {
			defer wg.Done()

			// Acquire semaphore slot if bounded.
			if sem != nil {
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					ch <- indexedResult{result: ErrorResult(fp.Name(), ctx.Err()), index: idx}
					return
				}
			}

			result, err := fp.Detect(ctx, target)
			if err != nil {
				ch <- indexedResult{result: ErrorResult(fp.Name(), err), index: idx}
				return
			}
			ch <- indexedResult{result: result, index: idx}

			// Signal early stop if high confidence match.
			if e.config.EarlyStop && result.Matched && result.Confidence >= e.config.HighConfidenceThreshold {
				cancel()
			}
		}(i, fp)
	}

	// Close channel once all goroutines complete.
	go func() {
		wg.Wait()
		close(ch)
	}()

	results := make([]Result, 0, len(fps))
	for ir := range ch {
		results = append(results, ir.result)
	}

	sortResults(results)
	return results
}

func sortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool {
		// Matched results first, then by confidence descending.
		if results[i].Matched != results[j].Matched {
			return results[i].Matched
		}
		return results[i].Confidence > results[j].Confidence
	})
}
