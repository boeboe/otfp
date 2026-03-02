# API Reference

Developer guide for using the `otfp` library in your own Go programs.

> **Module path:** `github.com/boeboe/otfp`
> **Go version:** 1.21+ (uses `log/slog` from stdlib)
> **External dependencies:** none — pure Go standard library

---

## Quick Start

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
    registry := core.NewRegistry()
    _ = registry.Register(mms.New())
    _ = registry.Register(s7.New())
    _ = registry.Register(modbus.New())

    engine := core.NewEngine(registry, core.DefaultEngineConfig())

    target := core.Target{
        IP:      "192.168.1.10",
        Port:    502,
        Timeout: 5 * time.Second,
    }

    result := engine.Detect(context.Background(), target)
    fmt.Printf("Protocol: %s (confidence %.2f)\n", result.Protocol, result.Confidence)
}
```

---

## Core Types

### `Protocol`

```go
type Protocol string
```

Type-safe protocol identifier. Provides compile-time safety while remaining
human-readable in logs and JSON output.

**Constants:**

| Constant | Value |
|---|---|
| `ProtocolUnknown` | `"Unknown"` |
| `ProtocolModbus` | `"Modbus TCP"` |
| `ProtocolMMS` | `"IEC 61850 MMS"` |
| `ProtocolS7` | `"Siemens S7comm"` |
| `ProtocolOPCUA` | `"OPC UA"` |
| `ProtocolBACnet` | `"BACnet/IP"` |
| `ProtocolCAN` | `"CAN (TCP Gateway)"` |
| `ProtocolPROFINET` | `"PROFINET (Ethernet)"` |
| `ProtocolDNP3` | `"DNP3 (TCP)"` |
| `ProtocolIEC104` | `"IEC 60870-5-104"` |
| `ProtocolENIP` | `"EtherNet/IP"` |

**Methods:**

| Method | Description |
|---|---|
| `String() string` | Returns the protocol name as a plain string |
| `IsValid() bool` | Reports whether the protocol is a known, non-Unknown identifier |

**Functions:**

| Function | Description |
|---|---|
| `AllProtocols() []Protocol` | Returns every known protocol in recommended detection order |

---

### `Target`

```go
type Target struct {
    IP      string
    Port    int
    Timeout time.Duration
}
```

Defines the network endpoint to probe.

| Field | Description |
|---|---|
| `IP` | Target IP address |
| `Port` | Target TCP port |
| `Timeout` | Per-protocol connection timeout (0 = `DefaultTimeout` of 5s) |

**Methods:**

| Method | Description |
|---|---|
| `Addr() string` | Returns `"host:port"` string |
| `EffectiveTimeout() time.Duration` | Returns `Timeout` or `DefaultTimeout` if zero |

---

### `Result`

```go
type Result struct {
    Protocol    Protocol
    Matched     bool
    Confidence  float64
    Details     string
    Error       error
    Fingerprint string
}
```

Holds the outcome of a fingerprint detection attempt.

| Field | Description |
|---|---|
| `Protocol` | Protocol this result relates to |
| `Matched` | `true` if the protocol was positively identified |
| `Confidence` | Score between 0.0 and 1.0 (0.0 = no match, 1.0 = definitive) |
| `Details` | Human-readable detection information |
| `Error` | Underlying error when detection fails (distinguishes "no match" from "unreachable") |
| `Fingerprint` | Opaque identifier for correlating log entries |

**Constructors:**

```go
// Positive detection
result := core.Match(core.ProtocolModbus, 0.95, "MBAP header valid, TxID echoed")

// No match
result := core.NoMatch(core.ProtocolModbus)

// Detection error (could not reach host, timeout, etc.)
result := core.ErrorResult(core.ProtocolModbus, err)
```

---

### `Fingerprinter` (interface)

```go
type Fingerprinter interface {
    Name() Protocol
    Priority() int
    Detect(ctx context.Context, target Target) (Result, error)
}
```

The interface every protocol detector must implement.

| Method | Description |
|---|---|
| `Name()` | Returns the `Protocol` identifier this fingerprinter detects |
| `Priority()` | Detection order priority (lower = tested first); by convention spaced in increments of 10 |
| `Detect()` | Probes the target; must respect context cancellation and never panic |

Implementations must be safe for concurrent use.

---

### `Registry`

```go
type Registry struct { /* unexported fields */ }
```

Thread-safe collection of registered fingerprinters.

| Method | Description |
|---|---|
| `NewRegistry() *Registry` | Creates an empty registry |
| `Register(fp Fingerprinter) error` | Adds a fingerprinter; returns error if name is already registered |
| `Get(protocol Protocol) Fingerprinter` | Returns the fingerprinter for a protocol, or `nil` |
| `All() []Fingerprinter` | Returns all fingerprinters sorted by priority (lowest first) |
| `Names() []Protocol` | Returns protocol identifiers of all registered fingerprinters |

---

### `EngineConfig`

```go
type EngineConfig struct {
    Parallel                bool
    EarlyStop               bool
    HighConfidenceThreshold float64
    MaxConcurrency          int
}
```

| Field | Default | Safe | Description |
|---|---|---|---|
| `Parallel` | `true` | `false` | Run protocol detections concurrently |
| `EarlyStop` | `true` | `true` | Stop after first high-confidence match |
| `HighConfidenceThreshold` | `0.9` | `0.9` | Minimum confidence to trigger early stop |
| `MaxConcurrency` | `0` (unbounded) | `1` | Max in-flight goroutines (0 = unlimited) |

**Preset constructors:**

```go
config := core.DefaultEngineConfig()  // parallel, early-stop, unbounded
config := core.SafeEngineConfig()     // sequential, max-concurrency=1
```

---

### `Engine`

```go
type Engine struct { /* unexported fields */ }
```

Orchestrates protocol detection across registered fingerprinters.

| Method | Description |
|---|---|
| `NewEngine(registry *Registry, config EngineConfig) *Engine` | Creates a new engine |
| `Detect(ctx context.Context, target Target) Result` | Best match (or `ProtocolUnknown`) |
| `DetectAll(ctx context.Context, target Target) []Result` | All results sorted by confidence (desc) |
| `DetectProtocol(ctx context.Context, target Target, protocol Protocol) (Result, error)` | Single-protocol check |

---

## Error Types

All error types implement `Unwrap()` for use with `errors.Is` / `errors.As`.

### `DetectError`

```go
type DetectError struct {
    Protocol Protocol
    Op       string  // "dial", "send", "receive"
    Err      error
}
```

Wraps an error during protocol detection. Provides structured fields for logging and metrics.

### `TimeoutError`

```go
type TimeoutError struct {
    Protocol Protocol
    Addr     string
    Err      error
}
```

Detection exceeded its deadline.

### `ConnectionError`

```go
type ConnectionError struct {
    Protocol Protocol
    Addr     string
    Err      error
}
```

Transport-level failure (refused, unreachable, etc.).

### `ProtocolNotFoundError`

```go
type ProtocolNotFoundError struct {
    Protocol Protocol
}
```

Returned by `Engine.DetectProtocol` when the protocol is not registered.

**Example — error classification:**

```go
result, err := engine.DetectProtocol(ctx, target, core.ProtocolModbus)
if err != nil {
    var pnf *core.ProtocolNotFoundError
    if errors.As(err, &pnf) {
        log.Fatalf("unknown protocol: %s", pnf.Protocol)
    }
    log.Fatalf("detection failed: %v", err)
}

if result.Error != nil {
    var te *core.TimeoutError
    var ce *core.ConnectionError
    switch {
    case errors.As(result.Error, &te):
        log.Printf("timeout: %s", te.Addr)
    case errors.As(result.Error, &ce):
        log.Printf("connection failed: %s", ce.Addr)
    default:
        log.Printf("error: %v", result.Error)
    }
}
```

---

## Protocol Packages

Each protocol is in its own package under `protocols/`. All expose a single constructor:

```go
func New() *Fingerprinter  // returns a ready-to-use fingerprinter
```

| Package | Import Path | Protocol | Priority |
|---|---|---|---|
| `mms` | `github.com/boeboe/otfp/protocols/mms` | IEC 61850 MMS | 10 |
| `s7` | `github.com/boeboe/otfp/protocols/s7` | Siemens S7comm | 20 |
| `enip` | `github.com/boeboe/otfp/protocols/enip` | EtherNet/IP | 30 |
| `iec104` | `github.com/boeboe/otfp/protocols/iec104` | IEC 60870-5-104 | 40 |
| `dnp3` | `github.com/boeboe/otfp/protocols/dnp3` | DNP3 (TCP) | 50 |
| `modbus` | `github.com/boeboe/otfp/protocols/modbus` | Modbus TCP | 60 |
| `opcua` | `github.com/boeboe/otfp/protocols/opcua` | OPC UA | 70 |
| `bacnet` | `github.com/boeboe/otfp/protocols/bacnet` | BACnet/IP | 80 |
| `can` | `github.com/boeboe/otfp/protocols/can` | CAN (TCP Gateway) | 90 |
| `profinet` | `github.com/boeboe/otfp/protocols/profinet` | PROFINET | 100 |

Shared ISO-on-TCP utilities (TPKT/COTP) live in `protocols/iso/`.

---

## Usage Patterns

### Register a subset of protocols

```go
registry := core.NewRegistry()
_ = registry.Register(modbus.New())
_ = registry.Register(dnp3.New())
_ = registry.Register(iec104.New())
```

### OT-safe scanning

```go
engine := core.NewEngine(registry, core.SafeEngineConfig())
```

Sequential detection with `MaxConcurrency=1` — minimal network impact.

### Parallel with bounded concurrency

```go
config := core.DefaultEngineConfig()
config.MaxConcurrency = 4
engine := core.NewEngine(registry, config)
```

### Global timeout via context

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

result := engine.Detect(ctx, target)
```

### Check a single protocol

```go
result, err := engine.DetectProtocol(ctx, target, core.ProtocolS7)
```

### Iterate all results

```go
for _, r := range engine.DetectAll(ctx, target) {
    fmt.Printf("%-20s matched=%-5v confidence=%.2f\n",
        r.Protocol, r.Matched, r.Confidence)
}
```

### Implement a custom fingerprinter

```go
type MyFingerprinter struct{}

func (f *MyFingerprinter) Name() core.Protocol     { return "My Protocol" }
func (f *MyFingerprinter) Priority() int            { return 200 }
func (f *MyFingerprinter) Detect(ctx context.Context, target core.Target) (core.Result, error) {
    // Your detection logic
    return core.Match("My Protocol", 0.85, "custom probe matched"), nil
}

registry.Register(&MyFingerprinter{})
```

---

## Detection Order

The engine tests fingerprinters in **priority order** (lowest priority number first).
The built-in order is:

1. IEC 61850 MMS (10)
2. Siemens S7comm (20)
3. EtherNet/IP (30)
4. IEC 60870-5-104 (40)
5. DNP3 (50)
6. Modbus TCP (60)
7. OPC UA (70)
8. BACnet/IP (80)
9. CAN TCP Gateway (90)
10. PROFINET (100)

ISO-based protocols (MMS, S7) are tested first because their TPKT/COTP
framing provides highly distinctive signatures. Lighter-weight and
niche gateway probes run last.

With `EarlyStop=true` (default), detection stops as soon as a match
reaches the `HighConfidenceThreshold` (default 0.9).
