# API Reference — `github.com/boeboe/otfp`

> **Go ≥ 1.25** | Zero external dependencies | Pure stdlib

Complete reference for every exported type, function, and method. Sections
follow the package layout.

---

## Table of Contents

- [Package `core`](#package-core)
  - [Protocol](#protocol)
  - [Confidence](#confidence)
  - [Fingerprint](#fingerprint)
  - [Result](#result)
  - [Target](#target)
  - [Fingerprinter (interface)](#fingerprinter-interface)
  - [Registry](#registry)
  - [Engine & EngineConfig](#engine--engineconfig)
  - [Observer (interface)](#observer-interface)
  - [ScanReport](#scanreport)
  - [Errors](#errors)
- [Protocol Packages](#protocol-packages)
  - [Detection Order & Priorities](#detection-order--priorities)
  - [Protocol List](#protocol-list)
- [Package `transport`](#package-transport)
- [CLI — `otprobe`](#cli--otprobe)
  - [Flags](#flags)
  - [Exit Codes](#exit-codes)
  - [JSON Output](#json-output)

---

## Package `core`

```go
import "github.com/boeboe/otfp/core"
```

### Protocol

```go
type Protocol uint8
```

Type-safe protocol identifier stored as a compact integer. Values are
**stable across versions** and must not be reordered.

| Constant           | Value | String                |
|--------------------|------:|-----------------------|
| `ProtocolUnknown`  |     0 | `Unknown`             |
| `ProtocolModbus`   |     1 | `Modbus TCP`          |
| `ProtocolMMS`      |     2 | `IEC 61850 MMS`       |
| `ProtocolS7`       |     3 | `Siemens S7comm`      |
| `ProtocolOPCUA`    |     4 | `OPC UA`              |
| `ProtocolBACnet`   |     5 | `BACnet/IP`           |
| `ProtocolCAN`      |     6 | `CAN (TCP Gateway)`   |
| `ProtocolPROFINET` |     7 | `PROFINET (Ethernet)` |
| `ProtocolDNP3`     |     8 | `DNP3 (TCP)`          |
| `ProtocolIEC104`   |     9 | `IEC 60870-5-104`     |
| `ProtocolENIP`     |    10 | `EtherNet/IP`         |

#### Methods

| Method   | Signature  | Description |
|----------|------------|-------------|
| `String` | `() string` | Human-readable name via lookup table. Out-of-range returns `"Unknown"`. |
| `IsValid` | `() bool` | True when `p > 0 && p < protocolCount`. `ProtocolUnknown` returns false. |

#### Functions

| Function        | Signature                        | Description |
|-----------------|----------------------------------|-------------|
| `ParseProtocol` | `(s string) (Protocol, error)`   | Reverse lookup from name string. Returns error for unknown or `"Unknown"`. |
| `AllProtocols`  | `() []Protocol`                  | All 10 protocols in recommended detection order. |

---

### Confidence

```go
type Confidence float64
```

Named floating-point type preventing accidental misuse in arithmetic with
raw `float64` values.

#### Methods

| Method   | Signature                | Description |
|----------|--------------------------|-------------|
| `Valid`  | `() bool`                | True when `0.0 ≤ c ≤ 1.0`. |
| `IsHigh` | `(threshold float64) bool` | True when `float64(c) >= threshold`. |

---

### Fingerprint

```go
type Fingerprint struct {
    ID        string            `json:"id"`
    Signature string            `json:"signature"`
    Metadata  map[string]string `json:"metadata,omitempty"`
}
```

Structured identification data from a detection, suitable for SIEM
integration and asset inventory databases.

- **ID** — Dot-separated identifier, e.g. `"modbus.fc43"`, `"s7.setup_comm"`.
- **Signature** — Compact machine-parseable string of key observations.
- **Metadata** — Protocol-specific key-value pairs.

#### Methods

| Method   | Signature    | Description |
|----------|--------------|-------------|
| `String` | `() string`  | Returns `"id:signature"`. Nil-safe (returns `""`). |

#### Fingerprint IDs per Protocol

| Protocol   | Fingerprint ID          |
|------------|-------------------------|
| Modbus TCP | `modbus.fc43`           |
| IEC 61850 MMS | `mms.cotp_cc`       |
| Siemens S7comm | `s7.setup_comm`    |
| OPC UA     | `opcua.hel_ack`         |
| BACnet/IP  | `bacnet.bvll`           |
| CAN (TCP Gateway) | `can.slcan`      |
| PROFINET   | `profinet.dcerpc_bind`  |
| DNP3 (TCP) | `dnp3.link_status`      |
| IEC 60870-5-104 | `iec104.startdt`  |
| EtherNet/IP | `enip.register_session` |

---

### Result

```go
type Result struct {
    Protocol    Protocol
    Matched     bool
    Confidence  Confidence
    Details     string
    Error       error
    Fingerprint *Fingerprint
    DetectionID string
    Timestamp   time.Time
}
```

Outcome of a single fingerprint detection attempt.

#### Detection Semantics

| Scenario           | Matched | Error                    | Confidence |
|--------------------|---------|--------------------------|------------|
| Positive match     | `true`  | `nil`                    | `> 0`      |
| No match           | `false` | `nil`                    | `0`        |
| Timeout            | `false` | `*TimeoutError`          | `0`        |
| Connection refused | `false` | `*ConnectionError`       | `0`        |
| Invalid response   | `false` | `*InvalidResponseError`  | `0`        |

#### Fields

| Field         | Type           | Description |
|---------------|----------------|-------------|
| `Protocol`    | `Protocol`     | Protocol this result relates to. |
| `Matched`     | `bool`         | True if protocol was positively identified. |
| `Confidence`  | `Confidence`   | Score in `[0.0, 1.0]`. |
| `Details`     | `string`       | Human-readable detection notes. |
| `Error`       | `error`        | Underlying error (nil on success). |
| `Fingerprint` | `*Fingerprint` | Structured ID data (nil when unavailable). |
| `DetectionID` | `string`       | 16-char hex unique ID (`crypto/rand`) for audit trails. |
| `Timestamp`   | `time.Time`    | When the result was created (`time.Now()`). |

#### Methods

| Method            | Signature                      | Description |
|-------------------|--------------------------------|-------------|
| `String`          | `() string`                    | Human-readable summary. |
| `WithFingerprint` | `(fp *Fingerprint) Result`     | Returns a copy with fingerprint set (immutable pattern). |

#### Constructors

| Function      | Signature                                              | Description |
|---------------|--------------------------------------------------------|-------------|
| `NoMatch`     | `(protocol Protocol) Result`                           | No detection; Confidence=0. |
| `Match`       | `(protocol Protocol, confidence Confidence, details string) Result` | Positive detection. |
| `ErrorResult` | `(protocol Protocol, err error) Result`                | Detection failure. |

All constructors auto-generate `DetectionID` (via `crypto/rand`) and set
`Timestamp` to `time.Now()`.

---

### Target

```go
type Target struct {
    IP      string
    Port    int
    Timeout time.Duration
}
```

Network endpoint to fingerprint.

| Constant        | Value | Description |
|-----------------|-------|-------------|
| `DefaultTimeout` | `5s` | Used when `Timeout` is zero. |

#### Methods

| Method             | Signature            | Description |
|--------------------|----------------------|-------------|
| `Addr`             | `() string`          | Returns `"host:port"` string. |
| `EffectiveTimeout` | `() time.Duration`   | Returns `Timeout` or `DefaultTimeout`. |
| `Validate`         | `() error`           | Checks IP parseable (`net.ParseIP`), port `[1, 65535]`, timeout ≥ 0. |

---

### Fingerprinter (interface)

```go
type Fingerprinter interface {
    Name()     Protocol
    Priority() int
    Detect(ctx context.Context, target Target) (Result, error)
}
```

Each protocol detector implements this interface. Implementations must be
safe for concurrent use and must never panic.

| Method       | Description |
|--------------|-------------|
| `Name()`     | Protocol identifier this fingerprinter detects. |
| `Priority()` | Detection order (lower = tested first). Conventionally spaced by 10. |
| `Detect()`   | Attempts identification; respects context cancellation and timeout. |

---

### Registry

```go
type Registry struct { /* unexported fields */ }
```

Thread-safe container for registered fingerprinters.

#### Functions

| Function      | Signature       | Description |
|---------------|-----------------|-------------|
| `NewRegistry` | `() *Registry`  | Creates an empty registry. |

#### Methods

| Method     | Signature                         | Description |
|------------|-----------------------------------|-------------|
| `Register` | `(fp Fingerprinter) error`        | Adds a fingerprinter; error on duplicate name. |
| `Get`      | `(protocol Protocol) Fingerprinter` | Lookup by protocol; nil if not found. |
| `All`      | `() []Fingerprinter`              | All registered, sorted by priority ascending. |
| `Names`    | `() []Protocol`                   | Protocol identifiers of all registered. |

---

### Engine & EngineConfig

```go
type EngineConfig struct {
    Parallel                bool
    EarlyStop               bool
    HighConfidenceThreshold Confidence
    MaxConcurrency          int
    MinInterval             time.Duration
    Observer                Observer
}
```

| Field                     | Type            | Default | Description |
|---------------------------|-----------------|---------|-------------|
| `Parallel`                | `bool`          | `true`  | Run protocol checks concurrently. |
| `EarlyStop`               | `bool`          | `true`  | Stop after first high-confidence match. |
| `HighConfidenceThreshold` | `Confidence`    | `0.9`   | Threshold for early-stop trigger. |
| `MaxConcurrency`          | `int`           | `0`     | Max parallel goroutines (0 = unbounded). |
| `MinInterval`             | `time.Duration` | `0`     | Minimum delay between probes (IDS-safe). |
| `Observer`                | `Observer`      | `nil`   | Receives callbacks during detection. |

#### Preset Configurations

| Function              | Description |
|-----------------------|-------------|
| `DefaultEngineConfig()` | Parallel, early-stop, unbounded concurrency. |
| `SafeEngineConfig()`    | Sequential, early-stop, max concurrency 1. |

#### Engine Methods

| Method           | Signature                                              | Description |
|------------------|--------------------------------------------------------|-------------|
| `NewEngine`      | `(registry *Registry, config EngineConfig) *Engine`    | Creates engine. Auto-defaults threshold to 0.9 when ≤ 0. |
| `Detect`         | `(ctx context.Context, target Target) Result`          | Best single match (or `ProtocolUnknown`). |
| `DetectAll`      | `(ctx context.Context, target Target) []Result`        | All results sorted by confidence descending. |
| `DetectProtocol` | `(ctx context.Context, target Target, protocol Protocol) (Result, error)` | Single named protocol. |
| `Scan`           | `(ctx context.Context, target Target) ScanReport`      | Full sweep with timing metadata. |

---

### Observer (interface)

```go
type Observer interface {
    OnStart(protocol Protocol, target Target)
    OnResult(result Result)
}
```

Receives callbacks during detection for metrics, tracing, or audit logging.
Implementations **must** be safe for concurrent use when `Parallel` is true
and **must** be non-blocking.

| Method     | Called | Description |
|------------|--------|-------------|
| `OnStart`  | Before each detection attempt. | Receives the protocol and target. |
| `OnResult` | After each detection attempt.  | Receives the full `Result`. |

---

### ScanReport

```go
type ScanReport struct {
    Target     Target
    StartedAt  time.Time
    FinishedAt time.Time
    Duration   time.Duration
    Results    []Result
    BestMatch  Result
}
```

Structured summary of a complete detection run returned by `Engine.Scan()`.

| Field        | Type            | Description |
|--------------|-----------------|-------------|
| `Target`     | `Target`        | The endpoint that was scanned. |
| `StartedAt`  | `time.Time`     | When the scan began. |
| `FinishedAt` | `time.Time`     | When the scan completed. |
| `Duration`   | `time.Duration` | Wall-clock time of the scan. |
| `Results`    | `[]Result`      | All detection outcomes, sorted by confidence descending. |
| `BestMatch`  | `Result`        | Highest-confidence match, or `ProtocolUnknown` if nothing matched. |

---

### Errors

| Type                    | Fields                    | Unwrap | Description |
|-------------------------|---------------------------|--------|-------------|
| `DetectError`           | `Protocol`, `Op`, `Err`   | ✓      | Error during detection. `Op` is a short name like `"dial"`, `"send"`, `"receive"`. |
| `TimeoutError`          | `Protocol`, `Addr`, `Err` | ✓      | Deadline exceeded. |
| `ConnectionError`       | `Protocol`, `Addr`, `Err` | ✓      | Transport failure (refused, unreachable). |
| `InvalidResponseError`  | `Protocol`, `Reason`      | —      | Response received but malformed or unexpected framing. |
| `ProtocolNotFoundError` | `Protocol`                | —      | Requested protocol not in registry. |

All error types implement the `error` interface. Use `errors.As()` for
type-safe inspection:

```go
var connErr *core.ConnectionError
if errors.As(err, &connErr) {
    fmt.Printf("failed to reach %s\n", connErr.Addr)
}
```

---

## Protocol Packages

Each protocol lives in its own package under `protocols/`. Every package
exports a single `New()` constructor returning `core.Fingerprinter`.

### Detection Order & Priorities

| Priority | Package    | Protocol                | Default Port |
|---------:|------------|-------------------------|-------------:|
|       10 | `mms`      | IEC 61850 MMS           |          102 |
|       20 | `s7`       | Siemens S7comm          |          102 |
|       30 | `enip`     | EtherNet/IP (CIP)       |        44818 |
|       40 | `iec104`   | IEC 60870-5-104         |         2404 |
|       50 | `dnp3`     | DNP3 (TCP)              |        20000 |
|       60 | `modbus`   | Modbus TCP              |          502 |
|       70 | `opcua`    | OPC UA (Binary)         |         4840 |
|       80 | `bacnet`   | BACnet/IP (BVLL)        |        47808 |
|       90 | `can`      | CAN TCP Gateway (SLCAN) |         3000 |
|      100 | `profinet` | PROFINET (Ethernet)     |        34964 |

### Protocol List

Each detector sends a minimal, standards-compliant probe and analyses the
response to determine protocol presence.

| Package    | Probe Strategy                            | Fingerprint ID          |
|------------|-------------------------------------------|-------------------------|
| `modbus`   | FC 43 (Read Device ID)                    | `modbus.fc43`           |
| `mms`      | ISO COTP CR → CC                          | `mms.cotp_cc`           |
| `s7`       | COTP CR + S7 Setup Communication          | `s7.setup_comm`         |
| `opcua`    | OPC UA HEL → ACK                         | `opcua.hel_ack`         |
| `bacnet`   | BVLC ReadBroadcastDistTable               | `bacnet.bvll`           |
| `can`      | SLCAN version command                     | `can.slcan`             |
| `profinet` | DCE/RPC Endpoint Mapper Bind              | `profinet.dcerpc_bind`  |
| `dnp3`     | DNP3 Link Status Request                  | `dnp3.link_status`      |
| `iec104`   | STARTDT Act → STARTDT Con                 | `iec104.startdt`        |
| `enip`     | EtherNet/IP RegisterSession               | `enip.register_session` |

---

## Package `transport`

```go
import "github.com/boeboe/otfp/transport"
```

Shared TCP transport utilities. Provides context-aware TCP connection
helpers used by all protocol fingerprinters.

---

## CLI — `otprobe`

```
otprobe --ip <address> --port <port> [options]
```

### Flags

| Flag               | Type     | Default      | Description |
|--------------------|----------|--------------|-------------|
| `--ip`             | string   | *(required)* | Target IP address. |
| `--port`           | int      | *(required)* | Target TCP port. |
| `--check`          | string   |              | Check specific protocol only. |
| `--timeout`        | duration | `5s`         | Per-protocol connection timeout. |
| `--global-timeout` | duration | `0`          | Overall timeout (0 = unlimited). |
| `--verbose`        | bool     | `false`      | Show detailed detection info. |
| `--parallel`       | bool     | `true`       | Run protocol checks in parallel. |
| `--safe`           | bool     | `false`      | OT-safe mode: sequential, low concurrency. |
| `--output`         | string   | `text`       | Output format: `text` or `json`. |
| `--version`        | bool     | `false`      | Print version and exit. |
| `--list`           | bool     | `false`      | List supported protocols with priorities and exit. |

### Exit Codes

| Code | Meaning |
|-----:|---------|
|  `0` | Protocol detected (high confidence ≥ 0.9). |
|  `1` | Unknown protocol (no match). |
|  `2` | Connection error. |
|  `3` | Invalid parameters. |
|  `4` | Partial detection (matched but confidence < 0.9). |

Exit codes are a **stable numeric API** for script integration.

### JSON Output

When `--output json` is used, the output is a single JSON object:

```json
{
  "target": "192.168.1.100:502",
  "protocol": "Modbus TCP",
  "matched": true,
  "confidence": 0.95,
  "details": "Valid Modbus response with matching transaction ID",
  "fingerprint": {
    "id": "modbus.fc43",
    "signature": "Valid Modbus response with matching transaction ID"
  },
  "detection_id": "a1b2c3d4e5f67890",
  "timestamp": "2025-01-15T10:30:00.123456789Z"
}
```

| Field         | Type              | Presence | Description |
|---------------|-------------------|----------|-------------|
| `target`      | `string`          | Always   | `"host:port"` |
| `protocol`    | `string`          | Always   | Protocol name or `"Unknown"`. |
| `matched`     | `bool`            | Always   | Whether a protocol was detected. |
| `confidence`  | `float64`         | Always   | Score `[0.0, 1.0]`. |
| `details`     | `string`          | When non-empty | Human-readable notes. |
| `error`       | `string`          | On error | Error message. |
| `fingerprint` | `object`          | When available | `{id, signature, metadata?}`. |
| `detection_id`| `string`          | Always   | 16-char hex unique ID. |
| `timestamp`   | `string`          | Always   | RFC 3339 with nanoseconds. |

---

## Usage Examples

### Library — Basic Detection

```go
package main

import (
    "context"
    "fmt"

    "github.com/boeboe/otfp/core"
    "github.com/boeboe/otfp/protocols/modbus"
    "github.com/boeboe/otfp/protocols/s7"
)

func main() {
    reg := core.NewRegistry()
    _ = reg.Register(modbus.New())
    _ = reg.Register(s7.New())

    engine := core.NewEngine(reg, core.DefaultEngineConfig())
    target := core.Target{IP: "192.168.1.100", Port: 502}

    result := engine.Detect(context.Background(), target)
    fmt.Println(result)
    fmt.Printf("DetectionID: %s\n", result.DetectionID)

    if result.Fingerprint != nil {
        fmt.Printf("Fingerprint: %s\n", result.Fingerprint)
    }
}
```

### Library — ScanReport with Observer

```go
type logger struct{}

func (l *logger) OnStart(p core.Protocol, t core.Target) {
    fmt.Printf("  probing %s on %s\n", p, t.Addr())
}
func (l *logger) OnResult(r core.Result) {
    fmt.Printf("  result: %s matched=%v confidence=%.2f\n",
        r.Protocol, r.Matched, r.Confidence)
}

func scan() {
    reg := core.NewRegistry()
    // ... register protocols ...

    config := core.DefaultEngineConfig()
    config.Observer = &logger{}
    config.MinInterval = 100 * time.Millisecond

    engine := core.NewEngine(reg, config)
    report := engine.Scan(context.Background(),
        core.Target{IP: "10.0.0.1", Port: 502})

    fmt.Printf("Scan took %v, best: %s (%.2f)\n",
        report.Duration, report.BestMatch.Protocol,
        report.BestMatch.Confidence)
}
```

### Library — OT-Safe Mode with Rate Limiting

```go
config := core.SafeEngineConfig()
config.MinInterval = 200 * time.Millisecond
engine := core.NewEngine(reg, config)
```

### Library — Target Validation

```go
target := core.Target{IP: "192.168.1.1", Port: 502}
if err := target.Validate(); err != nil {
    log.Fatalf("bad target: %v", err)
}
```

### CLI — Quick Examples

```bash
# Auto-detect protocol
otprobe --ip 192.168.1.100 --port 502

# Check specific protocol
otprobe --ip 192.168.1.100 --port 502 --check modbus

# JSON output
otprobe --ip 192.168.1.100 --port 502 --output json

# OT-safe mode with global timeout
otprobe --ip 10.0.0.1 --port 102 --safe --global-timeout 30s

# List supported protocols
otprobe --list

# Use exit code in scripts
otprobe --ip 10.0.0.1 --port 502 --output json
case $? in
  0) echo "Detected with high confidence" ;;
  1) echo "No protocol detected" ;;
  4) echo "Low-confidence detection" ;;
esac
```
