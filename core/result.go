package core

import "fmt"

// Result holds the outcome of a fingerprint detection attempt.
type Result struct {
	// Protocol identifies the protocol this result relates to.
	Protocol Protocol

	// Matched is true if the protocol was positively identified.
	Matched bool

	// Confidence is a score between 0.0 and 1.0 indicating detection certainty.
	// 0.0 = no match, 1.0 = definitive match.
	Confidence float64

	// Details provides additional human-readable information about the detection.
	Details string

	// Error records the underlying error when detection fails.
	// A non-nil Error with Matched==false allows callers to distinguish
	// "no match" from "could not reach host".
	Error error

	// Fingerprint is a short opaque identifier for this detection run,
	// useful for correlating log entries and JSON output.
	Fingerprint string
}

// String returns a human-readable summary of the result.
func (r Result) String() string {
	if !r.Matched {
		if r.Error != nil {
			return fmt.Sprintf("Protocol: %s, Matched: false, Error: %v", r.Protocol, r.Error)
		}
		return fmt.Sprintf("Protocol: %s, Matched: false", r.Protocol)
	}
	return fmt.Sprintf("Protocol: %s, Matched: true, Confidence: %.2f, Details: %s",
		r.Protocol, r.Confidence, r.Details)
}

// NoMatch returns a Result indicating no protocol was detected.
func NoMatch(protocol Protocol) Result {
	return Result{
		Protocol:   protocol,
		Matched:    false,
		Confidence: 0.0,
	}
}

// Match returns a Result indicating a successful protocol detection.
func Match(protocol Protocol, confidence float64, details string) Result {
	return Result{
		Protocol:   protocol,
		Matched:    true,
		Confidence: confidence,
		Details:    details,
	}
}

// ErrorResult returns a Result recording a detection error.
// Matched is false and the error is preserved for inspection.
func ErrorResult(protocol Protocol, err error) Result {
	return Result{
		Protocol:   protocol,
		Matched:    false,
		Confidence: 0.0,
		Error:      err,
	}
}
