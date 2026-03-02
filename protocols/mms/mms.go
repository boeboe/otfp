// Package mms implements IEC 61850 MMS (Manufacturing Message Specification)
// protocol fingerprinting over ISO-on-TCP (RFC1006).
//
// Detection is based on TPKT/COTP connection-level handshake only.
// No MMS application association or ASN.1 parsing is performed.
package mms

import (
	"context"
	"fmt"

	"github.com/boeboe/otfp/core"
	"github.com/boeboe/otfp/protocols/iso"
	"github.com/boeboe/otfp/transport"
)

const (
	protocolName    = "IEC 61850 MMS"
	maxResponseSize = 512
)

// Fingerprinter detects IEC 61850 MMS protocol over ISO-on-TCP.
type Fingerprinter struct{}

// New creates a new MMS fingerprinter.
func New() *Fingerprinter {
	return &Fingerprinter{}
}

// Name returns the protocol name.
func (f *Fingerprinter) Name() string {
	return protocolName
}

// Detect attempts to identify IEC 61850 MMS on the target.
// It sends a TPKT/COTP Connection Request and validates the response.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
	conn, err := transport.Dial(ctx, target.Addr(), target.EffectiveTimeout())
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("mms: %w", err)
	}
	defer conn.Close()

	// Build ISO-on-TCP COTP Connection Request.
	// Use standard TSAP parameters for MMS (generic ISO transport).
	// TSAP parameters: calling TSAP and called TSAP.
	tsapParams := []byte{
		0xC1, 0x02, 0x00, 0x01, // Calling TSAP: Parameter code 0xC1, length 2, value 0x0001
		0xC2, 0x02, 0x00, 0x01, // Called TSAP: Parameter code 0xC2, length 2, value 0x0001
	}

	cotpCR := iso.BuildCOTPConnectionRequestWithParams(0x0000, 0x0001, 0x00, tsapParams)
	probe := iso.BuildTPKT(cotpCR)

	resp, err := conn.SendReceive(probe, maxResponseSize)
	if err != nil {
		return core.NoMatch(protocolName), fmt.Errorf("mms: %w", err)
	}

	return validateResponse(resp), nil
}

// validateResponse checks the response for MMS over ISO-on-TCP indicators.
func validateResponse(resp []byte) core.Result {
	if len(resp) < iso.TPKTHeaderLen+2 {
		return core.NoMatch(protocolName)
	}

	confidence := 0.0
	details := ""

	// Check 1: Valid TPKT header.
	tpktLen := iso.ValidateTPKT(resp)
	if tpktLen == 0 {
		return core.NoMatch(protocolName)
	}
	confidence += 0.30
	details = "Valid TPKT header"

	// Check 2: COTP CC (Connection Confirm).
	cotpData := resp[iso.TPKTHeaderLen:]
	if !iso.ValidateCOTPCC(cotpData) {
		// Got TPKT but no valid CC - might be ISO but not accepting our CR.
		return core.Result{
			Protocol:   protocolName,
			Matched:    true,
			Confidence: 0.30,
			Details:    "TPKT valid, but no COTP CC",
		}
	}
	confidence += 0.35
	details += ", COTP CC received"

	// Check 3: TPKT length consistency.
	if tpktLen <= len(resp) {
		confidence += 0.15
		details += ", Length consistent"
	}

	// Check 4: COTP header structure.
	if len(cotpData) >= 7 {
		headerLen := int(cotpData[0])
		pduType := cotpData[1] & 0xF0

		if pduType == iso.COTPTypeCC && headerLen >= 6 {
			confidence += 0.15
			details += ", CC structure valid"

			// Check TPDU class in CC response.
			if headerLen >= 6 {
				tpduClass := cotpData[6] & 0xF0
				if tpduClass == 0x00 {
					confidence += 0.05
					details += ", Class 0"
				}
			}
		}
	}

	// Note: This detects ISO-on-TCP / MMS capability.
	// S7comm also uses ISO-on-TCP but will be further distinguished
	// by the S7 fingerprinter which performs an additional S7 setup step.

	if confidence > 1.0 {
		confidence = 1.0
	}

	return core.Match(protocolName, confidence, details)
}
