package can

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/boeboe/otfp/core"
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

func TestCANDetectSLCANVersion(t *testing.T) {
	resp := []byte("V1013\r")
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
		t.Error("Expected match for SLCAN version response")
	}
	if result.Confidence < 0.8 {
		t.Errorf("Confidence too low: %f", result.Confidence)
	}
	t.Logf("Result: %s", result)
}

func TestCANDetectSLCANSerial(t *testing.T) {
	resp := []byte("NA1B2\r")
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
		t.Error("Expected match for SLCAN serial response")
	}
	t.Logf("Result: %s", result)
}

func TestCANDetectBinaryData(t *testing.T) {
	resp := []byte{0x00, 0x01, 0x80, 0xFF, 0xFE}
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
		t.Error("Should not match binary data")
	}
}

func TestCANDetectNoResponse(t *testing.T) {
	addr, cleanup := startMockServer(t, nil)
	defer cleanup()

	host, port := parseAddr(addr)
	fp := New()
	_, err := fp.Detect(context.Background(), core.Target{
		IP:      host,
		Port:    port,
		Timeout: 1 * time.Second,
	})
	_ = err
}

func TestCANDetectConnectionRefused(t *testing.T) {
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

func TestCANName(t *testing.T) {
	fp := New()
	if fp.Name() != core.ProtocolCAN {
		t.Errorf("Name() = %s, want %s", fp.Name(), core.ProtocolCAN)
	}
}

func TestMatchesSLCAN(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"version", []byte("V1013\r"), true},
		{"version_dot", []byte("V2.0\r"), true},
		{"serial", []byte("NA1B2\r"), true},
		{"ack_cr", []byte("\r"), true},
		{"ack_bel", []byte("\a"), true},
		{"empty", []byte{}, false},
		{"random", []byte("hello world"), false},
		{"short", []byte("V"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesSLCAN(tt.input)
			if got != tt.want {
				t.Errorf("matchesSLCAN(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
