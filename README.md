# otfp — OT Protocol Fingerprinting Library

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)

A pure Golang library for OT (Operational Technology) protocol fingerprinting at the **connection level only**. Detects industrial protocols based on transport framing and handshake behavior — without invoking application-layer logic.

## Supported Protocols

| Protocol | Detection Method | Phase |
|---|---|---|
| **Modbus TCP** | MBAP header validation, Transaction ID echo, FC validation | Single exchange |
| **IEC 61850 MMS** | TPKT/COTP Connection Request → Confirm | Single exchange |
| **Siemens S7comm** | TPKT/COTP CR→CC + S7 Setup Communication → ACK | Two-phase |

### Future Protocols (Extensible)

- BACnet/IP
- DNP3
- EtherNet/IP
- OPC UA

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
| `--check` | Check specific protocol: `modbus`, `mms`, `s7` | (all) |
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
    "github.com/boeboe/otfp/protocols/modbus"
    "github.com/boeboe/otfp/protocols/mms"
    "github.com/boeboe/otfp/protocols/s7"
)

func main() {
    // Create registry and register protocol fingerprinters.
    registry := core.NewRegistry()
    registry.Register(modbus.New())
    registry.Register(mms.New())
    registry.Register(s7.New())

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
type BACnetFingerprinter struct{}

func (f *BACnetFingerprinter) Name() string { return "BACnet/IP" }

func (f *BACnetFingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
    // Your detection logic here...
    return core.Match("BACnet/IP", 0.9, "valid BACnet response"), nil
}

// Register it:
registry.Register(&BACnetFingerprinter{})
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
│   └── s7/                    # Siemens S7comm fingerprinter
│       └── s7.go              # Two-phase: COTP + S7 Setup
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

# Run fuzz tests (Go 1.18+)
go test ./protocols/modbus/ -fuzz=FuzzValidateResponse -fuzztime=30s
```

## License

See [LICENSE](LICENSE) for details.
