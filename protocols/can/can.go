// Package can implements CAN-over-TCP gateway fingerprinting.
//
// Native CAN bus (Controller Area Network) is not a TCP protocol.
// This detector targets SLCAN/ASCII CAN gateways that expose CAN frames
// over a TCP socket (e.g. Lawicel SLCAN, SocketCAN bridges, CAN-Ethernet
// gateways). Detection sends minimal SLCAN commands and validates ASCII
// responses.
package can

import (
	"context"
	"fmt"

	"github.com/boeboe/otfp/core"
	"github.com/boeboe/otfp/transport"
)

const (
	protocolName = core.ProtocolCAN

	maxResponseSize = 512
)

// SLCAN commands.
var (
	// "V\r" — request firmware version.
	probeVersion = []byte{'V', '\r'}
	// "N\r" — request serial number.
	probeSerial = []byte{'N', '\r'}
)

// Fingerprinter detects CAN-over-TCP gateways.
type Fingerprinter struct{}

// New creates a new CAN gateway fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol identifier.
func (f *Fingerprinter) Name() core.Protocol {
	return protocolName
}

// Priority returns the detection order (lower = tested first).
func (f *Fingerprinter) Priority() int { return 90 }

// Detect attempts to identify a CAN-over-TCP gateway on the target.
// It sends SLCAN probe commands and validates ASCII responses.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("can: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// Try version command first.
	resp, err := conn.SendReceive(probeVersion, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("can: %w", err)
	}

	result := validateResponse(resp)
	if result.Matched {
		return result, nil
	}

	// Try serial number command as fallback.
	resp2, err := conn.SendReceive(probeSerial, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), nil
	}

	return validateResponse(resp2), nil
}

// validateResponse checks the response against SLCAN/CAN gateway expectations.
func validateResponse(resp []byte) core.Result {
	if len(resp) == 0 {
		return core.NoMatch(protocolName)
	}

	confidence := 0.0
	details := ""

	// Check 1: Response is ASCII printable (with CR/LF allowed).
	asciiCount := 0
	for _, b := range resp {
		if (b >= 0x20 && b <= 0x7E) || b == '\r' || b == '\n' {
			asciiCount++
		}
	}
	asciiRatio := float64(asciiCount) / float64(len(resp))
	if asciiRatio >= 0.9 {
		confidence += 0.40
		details = "ASCII response"
	} else {
		return core.NoMatch(protocolName)
	}

	// Check 2: Response ends with \r or \r\n.
	lastByte := resp[len(resp)-1]
	if lastByte == '\r' || lastByte == '\n' {
		confidence += 0.20
		details += ", CR/LF terminated"
	}
	if len(resp) >= 2 && resp[len(resp)-2] == '\r' {
		confidence += 0.05
	}

	// Check 3: Match known SLCAN patterns.
	if matchesSLCAN(resp) {
		confidence += 0.40
		details += ", SLCAN pattern"
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	if confidence < 0.5 {
		return core.NoMatch(protocolName)
	}

	return core.Match(protocolName, confidence, details)
}

// matchesSLCAN checks if the response matches known SLCAN response patterns.
func matchesSLCAN(resp []byte) bool {
	if len(resp) == 0 {
		return false
	}

	// SLCAN error/ack: single byte '\r' or '\a' (BEL).
	if len(resp) == 1 && (resp[0] == '\r' || resp[0] == '\a') {
		return true
	}

	if len(resp) < 2 {
		return false
	}

	// SLCAN version response: starts with 'V' followed by digits.
	// e.g. "V1013\r" or "V2.0\r"
	if resp[0] == 'V' && len(resp) >= 3 {
		for _, b := range resp[1:] {
			if b == '\r' || b == '\n' {
				return true
			}
			if (b < '0' || b > '9') && b != '.' {
				break
			}
		}
	}

	// SLCAN serial response: starts with 'N' followed by hex chars.
	// e.g. "NA123\r"
	if resp[0] == 'N' && len(resp) >= 3 {
		for _, b := range resp[1:] {
			if b == '\r' || b == '\n' {
				return true
			}
			if (b < '0' || b > '9') && (b < 'A' || b > 'F') && (b < 'a' || b > 'f') {
				break
			}
		}
	}

	return false
}
