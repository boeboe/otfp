package mms

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/boeboe/otfp/core"
	"github.com/boeboe/otfp/protocols/iso"
)

func startMockServer(t *testing.T, response []byte) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close() //nolint:errcheck

		buf := make([]byte, 1024)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Read(buf)

		if response != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write(response)
		}
	}()

	return ln.Addr().String(), func() { _ = ln.Close() }
}

func parseAddr(addr string) (string, int) {
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

// buildCOTPCC builds a valid COTP Connection Confirm wrapped in TPKT.
func buildCOTPCC() []byte {
	cc := []byte{
		0x06,           // Header length
		iso.COTPTypeCC, // CC type
		0x00, 0x01,     // Dst ref
		0x00, 0x02, // Src ref
		0x00, // Class 0
	}
	return iso.BuildTPKT(cc)
}

func TestMMSDetectValidCC(t *testing.T) {
	resp := buildCOTPCC()
	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if !result.Matched {
		t.Error("Expected match for valid COTP CC")
	}
	if result.Confidence < 0.5 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestMMSDetectInvalidTPKT(t *testing.T) {
	// Not a TPKT response.
	resp := []byte{0x04, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00}
	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if result.Matched {
		t.Error("Should not match invalid TPKT")
	}
}

func TestMMSDetectHTTPResponse(t *testing.T) {
	// HTTP response - should not match.
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	addr, cleanup := startMockServer(t, resp)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	result, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 2 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if result.Matched {
		t.Error("HTTP response should not match as MMS")
	}
}

func TestMMSDetectConnectionRefused(t *testing.T) {
	fp := New()
	_, err := fp.Detect(context.Background(), core.Target{
		IP:      "127.0.0.1",
		Port:    1,
		Timeout: 1 * time.Second,
	})

	if err == nil {
		t.Error("Expected error for connection refused")
	}
}

func TestMMSName(t *testing.T) {
	fp := New()
	if fp.Name() != "IEC 61850 MMS" {
		t.Errorf("Name() = %q, want %q", fp.Name(), "IEC 61850 MMS")
	}
}
