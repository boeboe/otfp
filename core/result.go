package core

import "fmt"

// Result holds the outcome of a fingerprint detection attempt.
type Result struct {
	// Protocol is the name of the detected protocol (e.g., "Modbus TCP", "S7comm").
	// Empty string or "Unknown" if no protocol could be identified.
	Protocol string

	// Matched is true if the protocol was positively identified.
	Matched bool

	// Confidence is a score between 0.0 and 1.0 indicating detection certainty.
	// 0.0 = no match, 1.0 = definitive match.
	Confidence float64

	// Details provides additional human-readable information about the detection.
	Details string
}

// String returns a human-readable summary of the result.
func (r Result) String() string {
	if !r.Matched {
		return fmt.Sprintf("Protocol: %s, Matched: false", r.Protocol)
	}
	return fmt.Sprintf("Protocol: %s, Matched: true, Confidence: %.2f, Details: %s",
		r.Protocol, r.Confidence, r.Details)
}

// NoMatch returns a Result indicating no protocol was detected.
func NoMatch(protocol string) Result {
	return Result{
		Protocol:   protocol,
		Matched:    false,
		Confidence: 0.0,
	}
}

// Match returns a Result indicating a successful protocol detection.
func Match(protocol string, confidence float64, details string) Result {
	return Result{
		Protocol:   protocol,
		Matched:    true,
		Confidence: confidence,
		Details:    details,
	}
}
