# otfp — OT Protocol Fingerprinting Library

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)

A pure Golang library for OT (Operational Technology) protocol fingerprinting at the **connection level only**. Detects industrial protocols based on transport framing and handshake behavior — without invoking application-layer logic.

## Supported Protocols

| Protocol | Detection Method | Phase |
|---|---|---|
| **Modbus TCP** | MBAP header validation, Transaction ID echo, FC validation | Single exchange |
| **IEC 61850 MMS** | TPKT/COTP Connection Request → Confirm | Single exchange |
| **Siemens S7comm** | TPKT/COTP CR→CC + S7 Setup Communication → ACK | Two-phase |
| **OPC UA** | HEL/ACK binary handshake | Single exchange |
| **BACnet/IP** | BVLL Who-Is broadcast probe | Single exchange |
| **CAN (TCP Gateway)** | SLCAN ASCII command probe | Single exchange |
| **PROFINET** | DCE/RPC Bind with PNIO CM UUID | Single exchange |
| **DNP3** | Link-layer start bytes + CRC validation | Single exchange |
| **IEC 60870-5-104** | APCI STARTDT_ACT/CON handshake | Single exchange |
| **EtherNet/IP** | Encapsulation RegisterSession handshake | Single exchange |

### TCP Detectability Notes

All protocols above are detectable over raw TCP connections. Some notes on real-world deployments:

- **PROFIBUS** uses RS-485 serial and is not directly detectable over TCP. PROFINET is its TCP/IP successor.
- **CAN** detection targets TCP-to-CAN gateways that expose an SLCAN ASCII interface over a TCP socket.

### Energy & Utility Protocol Coverage

- **DNP3** and **IEC 60870-5-104** are the dominant SCADA protocols in power grid infrastructure. DNP3 is prevalent in North America; IEC 104 dominates European substations.
- **EtherNet/IP** (CIP over TCP) is the primary protocol in Rockwell/Allen-Bradley factory automation environments.

## Key Principles

- **TCP port agnostic** — does not assume Modbus=502, ISO=102
- **Connection-level only** — no register reads, no device info queries, no deep parsing
- **Minimal payloads** — standards-compliant, safe for ICS environments
- **Deterministic detection** — confidence scoring based on protocol framing validation
- **Zero external dependencies** — pure Go standard library

## Installation

```bash
go get github.com/boeboe/otfp
```

### CLI Tool

```bash
go install github.com/boeboe/otfp/cmd/ot-discover@latest
```

## CLI Usage

### Full Detection (all protocols)

```bash
ot-discover --ip 192.168.1.10 --port 102
```

Output:
```
Target: 192.168.1.10:102
Detected: Siemens S7comm
Confidence: 0.95
```

### Protocol-Specific Check

```bash
ot-discover --ip 192.168.1.10 --port 502 --check modbus
```

Output:
```
Modbus: true
```

### Options

| Flag | Description | Default |
|---|---|---|
| `--ip` | Target IP address (required) | — |
| `--port` | Target TCP port (required) | — |
| `--check` | Check specific protocol: `modbus`, `mms`, `s7`, `opcua`, `bacnet`, `can`, `profinet`, `dnp3`, `iec104`, `enip` | (all) |
| `--timeout` | Connection timeout | `5s` |
| `--verbose` | Show detailed detection info | `false` |
| `--parallel` | Run checks in parallel | `true` |

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Protocol detected |
| 1 | Unknown protocol |
| 2 | Connection error |
| 3 | Invalid parameters |

## Library Usage

### Basic Detection

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/boeboe/otfp/core"
    "github.com/boeboe/otfp/protocols/bacnet"
    "github.com/boeboe/otfp/protocols/can"
    "github.com/boeboe/otfp/protocols/dnp3"
    "github.com/boeboe/otfp/protocols/enip"
    "github.com/boeboe/otfp/protocols/iec104"
    "github.com/boeboe/otfp/protocols/modbus"
    "github.com/boeboe/otfp/protocols/mms"
    "github.com/boeboe/otfp/protocols/opcua"
    "github.com/boeboe/otfp/protocols/profinet"
    "github.com/boeboe/otfp/protocols/s7"
)

func main() {
    // Create registry and register protocol fingerprinters.
    registry := core.NewRegistry()
    registry.Register(mms.New())
    registry.Register(s7.New())
    registry.Register(enip.New())
    registry.Register(iec104.New())
    registry.Register(dnp3.New())
    registry.Register(modbus.New())
    registry.Register(opcua.New())
    registry.Register(bacnet.New())
    registry.Register(can.New())
    registry.Register(profinet.New())

    // Create detection engine.
    engine := core.NewEngine(registry, core.DefaultEngineConfig())

    // Define target.
    target := core.Target{
        IP:      "192.168.1.10",
        Port:    502,
        Timeout: 5 * time.Second,
    }

    // Detect protocol.
    result := engine.Detect(context.Background(), target)
    fmt.Printf("Protocol: %s\n", result.Protocol)
    fmt.Printf("Matched:  %v\n", result.Matched)
    fmt.Printf("Confidence: %.2f\n", result.Confidence)
    fmt.Printf("Details: %s\n", result.Details)
}
```

### Single Protocol Check

```go
result, err := engine.DetectProtocol(ctx, target, "Modbus TCP")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Modbus: %v\n", result.Matched)
```

### Custom Fingerprinter

```go
type MyProtocolFingerprinter struct{}

func (f *MyProtocolFingerprinter) Name() string { return "MyProtocol" }

func (f *MyProtocolFingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
    // Your detection logic here...
    return core.Match("MyProtocol", 0.9, "valid response"), nil
}

// Register it:
registry.Register(&MyProtocolFingerprinter{})
```

## Architecture

```
otfp/
├── core/                      # Core types and engine
│   ├── engine.go              # Detection orchestration (parallel/sequential)
│   ├── fingerprinter.go       # Fingerprinter interface
│   ├── registry.go            # Protocol registry
│   ├── result.go              # Detection result with confidence scoring
│   └── target.go              # Target definition
├── protocols/                 # Protocol implementations
│   ├── iso/                   # Shared ISO-on-TCP (RFC1006) utilities
│   │   └── iso.go             # TPKT/COTP builders and validators
│   ├── modbus/                # Modbus TCP fingerprinter
│   │   └── modbus.go          # MBAP header validation
│   ├── mms/                   # IEC 61850 MMS fingerprinter
│   │   └── mms.go             # COTP CR/CC exchange
│   ├── s7/                    # Siemens S7comm fingerprinter
│   │   └── s7.go              # Two-phase: COTP + S7 Setup
│   ├── opcua/                 # OPC UA fingerprinter
│   │   └── opcua.go           # HEL/ACK binary handshake
│   ├── bacnet/                # BACnet/IP fingerprinter
│   │   └── bacnet.go          # BVLL Who-Is probe
│   ├── can/                   # CAN TCP Gateway fingerprinter
│   │   └── can.go             # SLCAN ASCII command detection
│   └── profinet/              # PROFINET fingerprinter
│       └── profinet.go        # DCE/RPC Bind with PNIO CM UUID
├── protocols/
│   ├── dnp3/                  # DNP3 fingerprinter
│   │   └── dnp3.go            # Link-layer start bytes + CRC
│   ├── iec104/                # IEC 60870-5-104 fingerprinter
│   │   └── iec104.go          # APCI STARTDT/CON exchange
│   └── enip/                  # EtherNet/IP fingerprinter
│       └── enip.go            # RegisterSession handshake
├── transport/                 # TCP transport layer
│   └── tcp.go                 # Connection with timeout/deadline support
├── cmd/
│   └── ot-discover/           # CLI tool
│       └── main.go
├── go.mod
└── README.md
```

## Detection Details

### Modbus TCP

Sends a minimal Modbus TCP frame using **FC43 (Read Device Identification)** — a safe, read-only diagnostic function:

1. Constructs MBAP header with known Transaction ID (0x1337)
2. Validates response: Protocol ID=0, Transaction ID echo, length consistency, function code
3. Accepts both normal and exception responses as valid Modbus

**Confidence factors:**
- Protocol ID = 0x0000 (+0.25)
- Transaction ID echoed (+0.25)
- Length field consistent (+0.20)
- Valid function code / exception (+0.20)
- Unit ID echoed (+0.10)

### IEC 61850 MMS (ISO-on-TCP)

Sends a **TPKT/COTP Connection Request** with generic TSAP parameters:

1. Validates TPKT header (version 0x03, reserved 0x00)
2. Validates COTP Connection Confirm (CC) PDU type
3. Checks TPDU class and length consistency

**Confidence factors:**
- Valid TPKT header (+0.30)
- COTP CC received (+0.35)
- Length consistent (+0.15)
- CC structure valid (+0.15)
- Class 0 confirmed (+0.05)

### Siemens S7comm

Two-phase detection that distinguishes S7 from pure MMS:

**Phase 1:** TPKT/COTP CR → CC (same as MMS, with S7-specific TSAP: rack 0 / slot 2)

**Phase 2:** S7 Setup Communication → S7 ACK-Data
1. Validates S7 protocol magic (0x32)
2. Checks message type (Ack-Data = 0x03)
3. Validates error class/code
4. Confirms Setup Communication function code (0xF0)

**Confidence factors:**
- COTP CC confirmed (+0.35)
- S7 Protocol ID 0x32 (+0.25)
- Ack-Data response (+0.20)
- No error (+0.10)
- Setup Comm function confirmed (+0.10)

### OPC UA (Binary)

Sends an **OPC UA HEL (Hello)** message and validates the ACK response:

1. Constructs a minimal HEL message with endpoint URL `opc.tcp://<ip>:<port>`
2. Validates ACK message type signature ("ACK")
3. Checks message size, protocol version, and buffer size fields

**Confidence factors:**
- ACK message type received (+0.40)
- Message size plausible (+0.20)
- Protocol version valid (+0.20)
- Buffer sizes reasonable (+0.20)

### BACnet/IP (BVLL)

Sends a **BVLL Original-Unicast-NPDU** containing a **Who-Is** service request:

1. Constructs BVLL header (type 0x81) with Original-Unicast function (0x0A)
2. Includes minimal NPDU with Who-Is APDU
3. Validates response BVLL type byte and function code

**Confidence factors:**
- BVLL type byte 0x81 (+0.40)
- Valid BVLL function code (+0.30)
- Length field consistent (+0.20)
- NPDU version present (+0.10)

### CAN (TCP Gateway)

Probes for **SLCAN** (Serial Line CAN) ASCII protocol over TCP:

1. Sends `V\r` (version query) and checks for ASCII response
2. Sends `N\r` (serial number query) as a second probe
3. Validates response contains printable ASCII terminated by CR

**Confidence factors:**
- ASCII printable content (+0.40)
- CR-terminated response (+0.20)
- SLCAN command pattern match (+0.40)

### PROFINET (DCE/RPC)

Sends a **DCE/RPC Bind** request with the PNIO Connection Manager UUID:

1. Constructs DCE/RPC Bind PDU (type 0x0B) with PNIO CM interface UUID
2. Validates Bind-Ack response (type 0x0C)
3. Checks for accepted PNIO transfer syntax

**Confidence factors:**
- Bind-Ack received (+0.40)
- Fragment length valid (+0.10)
- PNIO transfer syntax accepted (+0.50)

### DNP3 (TCP)

Sends a minimal **DNP3 Link Status Request** frame with valid CRC:

1. Constructs link-layer frame with start bytes `0x05 0x64`
2. Uses Function Code 0x09 (Link Status Request) with computed CRC-16
3. Validates response start bytes, length, CRC, and control field

**Confidence factors:**
- Start bytes 0x05 0x64 (+0.40)
- Valid length field (+0.20)
- Valid CRC-16 (+0.20)
- Valid response control code (+0.20)

### IEC 60870-5-104

Sends a **STARTDT_ACT** U-format APCI frame and validates the confirmation:

1. Sends 6-byte APCI frame: `68 04 07 00 00 00`
2. Validates start byte `0x68` and APCI length
3. Checks for STARTDT_CON (`0x0B`) or other valid U/S-format response

**Confidence factors:**
- Start byte 0x68 (+0.30)
- Length field valid (+0.20)
- Valid U/S-format control field (+0.30)
- STARTDT_CON received (+0.20)

### EtherNet/IP (CIP over TCP)

Sends a **RegisterSession** encapsulation command and validates the response:

1. Constructs 28-byte RegisterSession request (command 0x0065, protocol version 1)
2. Validates response command code, status, and session handle
3. Non-zero session handle confirms active EtherNet/IP endpoint

**Confidence factors:**
- Command echo 0x0065 (+0.30)
- Status = Success (+0.20)
- Session ID non-zero (+0.30)
- Length field valid (+0.20)

## Security Considerations

This library is designed for safe use in ICS/SCADA environments:

- **No aggressive scanning** — single minimal packet per protocol check
- **No malformed payloads** — all probes are standards-compliant
- **No exploit patterns** — uses safe, read-only diagnostic functions
- **No flooding** — one connection per check, graceful close
- **Minimal footprint** — probes are the smallest valid frames possible
- **Context-aware** — supports cancellation and configurable timeouts

> **Warning:** Even minimal protocol probes may trigger alerts in some IDS/IPS systems configured for OT environments. Always obtain proper authorization before scanning industrial networks.

## Testing

```bash
# Run all tests
go test ./... -v

# Run with race detector
go test ./... -race

# Run specific protocol tests
go test ./protocols/modbus/ -v
go test ./protocols/mms/ -v
go test ./protocols/s7/ -v
go test ./protocols/opcua/ -v
go test ./protocols/bacnet/ -v
go test ./protocols/can/ -v
go test ./protocols/profinet/ -v
go test ./protocols/dnp3/ -v
go test ./protocols/iec104/ -v
go test ./protocols/enip/ -v

# Run fuzz tests (Go 1.18+)
go test ./protocols/modbus/ -fuzz=FuzzValidateResponse -fuzztime=30s
go test ./protocols/opcua/ -fuzz=FuzzValidateResponse -fuzztime=30s
go test ./protocols/bacnet/ -fuzz=FuzzValidateResponse -fuzztime=30s
go test ./protocols/can/ -fuzz=FuzzValidateResponse -fuzztime=30s
go test ./protocols/profinet/ -fuzz=FuzzValidateResponse -fuzztime=30s
go test ./protocols/dnp3/ -fuzz=FuzzValidateResponse -fuzztime=30s
go test ./protocols/iec104/ -fuzz=FuzzValidateResponse -fuzztime=30s
go test ./protocols/enip/ -fuzz=FuzzValidateResponse -fuzztime=30s
```

## License

See [LICENSE](LICENSE) for details.
