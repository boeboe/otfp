package core

import "testing"

func TestProtocolString(t *testing.T) {
	if ProtocolModbus.String() != "Modbus TCP" {
		t.Errorf("ProtocolModbus.String() = %q", ProtocolModbus.String())
	}
}

func TestProtocolIsValid(t *testing.T) {
	for _, p := range AllProtocols() {
		if !p.IsValid() {
			t.Errorf("%q should be valid", p)
		}
	}
	if ProtocolUnknown.IsValid() {
		t.Error("ProtocolUnknown should not be valid")
	}
	if Protocol("bogus").IsValid() {
		t.Error("arbitrary string should not be valid")
	}
}

func TestAllProtocols(t *testing.T) {
	all := AllProtocols()
	if len(all) != 10 {
		t.Errorf("AllProtocols() returned %d, want 10", len(all))
	}
	// First should be MMS (ISO-based), last should be PROFINET.
	if all[0] != ProtocolMMS {
		t.Errorf("first protocol = %q, want %q", all[0], ProtocolMMS)
	}
	if all[len(all)-1] != ProtocolPROFINET {
		t.Errorf("last protocol = %q, want %q", all[len(all)-1], ProtocolPROFINET)
	}
}
