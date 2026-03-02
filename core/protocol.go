package core

// Protocol represents a named OT protocol identifier.
// It is a string-based type for readability and serialisation while
// providing compile-time safety through typed constants.
type Protocol string

// Known protocol identifiers.
const (
	ProtocolUnknown  Protocol = "Unknown"
	ProtocolModbus   Protocol = "Modbus TCP"
	ProtocolMMS      Protocol = "IEC 61850 MMS"
	ProtocolS7       Protocol = "Siemens S7comm"
	ProtocolOPCUA    Protocol = "OPC UA"
	ProtocolBACnet   Protocol = "BACnet/IP"
	ProtocolCAN      Protocol = "CAN (TCP Gateway)"
	ProtocolPROFINET Protocol = "PROFINET (Ethernet)"
	ProtocolDNP3     Protocol = "DNP3 (TCP)"
	ProtocolIEC104   Protocol = "IEC 60870-5-104"
	ProtocolENIP     Protocol = "EtherNet/IP"
)

// String returns the protocol name as a plain string.
func (p Protocol) String() string { return string(p) }

// IsValid reports whether p is a known, non-Unknown protocol.
func (p Protocol) IsValid() bool {
	switch p {
	case ProtocolModbus, ProtocolMMS, ProtocolS7, ProtocolOPCUA,
		ProtocolBACnet, ProtocolCAN, ProtocolPROFINET, ProtocolDNP3,
		ProtocolIEC104, ProtocolENIP:
		return true
	default:
		return false
	}
}

// AllProtocols returns every known protocol in recommended detection order.
// The order prioritises ISO-based protocols, then progressively moves to
// lighter-weight probes and niche gateways.
func AllProtocols() []Protocol {
	return []Protocol{
		ProtocolMMS,
		ProtocolS7,
		ProtocolENIP,
		ProtocolIEC104,
		ProtocolDNP3,
		ProtocolModbus,
		ProtocolOPCUA,
		ProtocolBACnet,
		ProtocolCAN,
		ProtocolPROFINET,
	}
}
