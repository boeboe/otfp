package core

import (
	"testing"
	"time"
)

func TestTargetAddr(t *testing.T) {
	tests := []struct {
		ip   string
		port int
		want string
	}{
		{"192.168.1.1", 502, "192.168.1.1:502"},
		{"10.0.0.1", 102, "10.0.0.1:102"},
		{"127.0.0.1", 0, "127.0.0.1:0"},
		{"192.168.1.1", 65535, "192.168.1.1:65535"},
	}

	for _, tt := range tests {
		target := Target{IP: tt.ip, Port: tt.port}
		if got := target.Addr(); got != tt.want {
			t.Errorf("Target{%s, %d}.Addr() = %q, want %q", tt.ip, tt.port, got, tt.want)
		}
	}
}

func TestEffectiveTimeout(t *testing.T) {
	t.Run("zero uses default", func(t *testing.T) {
		target := Target{IP: "127.0.0.1", Port: 502}
		if got := target.EffectiveTimeout(); got != DefaultTimeout {
			t.Errorf("EffectiveTimeout() = %v, want %v", got, DefaultTimeout)
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		target := Target{IP: "127.0.0.1", Port: 502, Timeout: 10 * time.Second}
		if got := target.EffectiveTimeout(); got != 10*time.Second {
			t.Errorf("EffectiveTimeout() = %v, want %v", got, 10*time.Second)
		}
	})
}
