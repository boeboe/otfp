package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/boeboe/otfp/core"
	"github.com/boeboe/otfp/protocols/bacnet"
	"github.com/boeboe/otfp/protocols/can"
	"github.com/boeboe/otfp/protocols/dnp3"
	"github.com/boeboe/otfp/protocols/enip"
	"github.com/boeboe/otfp/protocols/iec104"
	"github.com/boeboe/otfp/protocols/mms"
	"github.com/boeboe/otfp/protocols/modbus"
	"github.com/boeboe/otfp/protocols/opcua"
	"github.com/boeboe/otfp/protocols/profinet"
	"github.com/boeboe/otfp/protocols/s7"
)

// Build-time variables injected via ldflags.
var (
	Version   = "dev"
	Branch    = "unknown"
	Revision  = "unknown"
	BuildUser = "unknown"
	BuildDate = "unknown"
)

// Exit codes — stable numeric API for callers.
const (
	exitDetected  = 0
	exitUnknown   = 1
	exitConnError = 2
	exitBadParams = 3
)

// protocolAliases maps short CLI names to typed Protocol identifiers.
var protocolAliases = map[string]core.Protocol{
	"modbus":   core.ProtocolModbus,
	"mms":      core.ProtocolMMS,
	"s7":       core.ProtocolS7,
	"opcua":    core.ProtocolOPCUA,
	"bacnet":   core.ProtocolBACnet,
	"can":      core.ProtocolCAN,
	"profinet": core.ProtocolPROFINET,
	"dnp3":     core.ProtocolDNP3,
	"iec104":   core.ProtocolIEC104,
	"enip":     core.ProtocolENIP,
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the real entry point. Returning an int keeps main() trivially testable.
func run(args []string, stdout, stderr io.Writer) int {
	// ---- flag parsing ----
	fs := flag.NewFlagSet("otprobe", flag.ContinueOnError)
	fs.SetOutput(stderr)

	ip := fs.String("ip", "", "Target IP address (required)")
	port := fs.Int("port", 0, "Target TCP port (required)")
	check := fs.String("check", "", "Check specific protocol: modbus, mms, s7, opcua, bacnet, can, profinet, dnp3, iec104, enip")
	timeout := fs.Duration("timeout", 5*time.Second, "Per-protocol connection timeout")
	globalTimeout := fs.Duration("global-timeout", 0, "Overall timeout for the entire run (0 = unlimited)")
	verbose := fs.Bool("verbose", false, "Show detailed detection info")
	parallel := fs.Bool("parallel", true, "Run protocol checks in parallel")
	safe := fs.Bool("safe", false, "OT-safe mode: sequential, low concurrency, conservative timeouts")
	output := fs.String("output", "text", "Output format: text or json")
	showVersion := fs.Bool("version", false, "Print version information and exit")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "Usage: otprobe --ip <address> --port <port> [options]\n\n")
		_, _ = fmt.Fprintf(stderr, "OT Protocol Fingerprinting Tool\n\n")
		_, _ = fmt.Fprintf(stderr, "Options:\n")
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(stderr, "\nSupported protocols for --check:\n")
		_, _ = fmt.Fprintf(stderr, "  modbus    Modbus TCP\n")
		_, _ = fmt.Fprintf(stderr, "  mms       IEC 61850 MMS (ISO-on-TCP)\n")
		_, _ = fmt.Fprintf(stderr, "  s7        Siemens S7comm\n")
		_, _ = fmt.Fprintf(stderr, "  opcua     OPC UA (Binary)\n")
		_, _ = fmt.Fprintf(stderr, "  bacnet    BACnet/IP (BVLL)\n")
		_, _ = fmt.Fprintf(stderr, "  can       CAN TCP Gateway (SLCAN)\n")
		_, _ = fmt.Fprintf(stderr, "  profinet  PROFINET (DCE/RPC)\n")
		_, _ = fmt.Fprintf(stderr, "  dnp3      DNP3 over TCP\n")
		_, _ = fmt.Fprintf(stderr, "  iec104    IEC 60870-5-104\n")
		_, _ = fmt.Fprintf(stderr, "  enip      EtherNet/IP (CIP)\n")
		_, _ = fmt.Fprintf(stderr, "\nExit codes:\n")
		_, _ = fmt.Fprintf(stderr, "  0  Protocol detected\n")
		_, _ = fmt.Fprintf(stderr, "  1  Unknown protocol\n")
		_, _ = fmt.Fprintf(stderr, "  2  Connection error\n")
		_, _ = fmt.Fprintf(stderr, "  3  Invalid parameters\n")
	}

	if err := fs.Parse(args); err != nil {
		return exitBadParams
	}

	// ---- version ----
	build := BuildInfo{
		Version:   Version,
		Branch:    Branch,
		Revision:  Revision,
		BuildUser: BuildUser,
		BuildDate: BuildDate,
	}

	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "otprobe %s\n", build.String())
		return exitDetected
	}

	// ---- structured logger ----
	logger := initLogger(stderr, *verbose)

	logger.Info("starting otprobe", "version", build.Short())

	// ---- validate params ----
	if *ip == "" {
		logger.Error("--ip is required")
		fs.Usage()
		return exitBadParams
	}
	if *port <= 0 || *port > 65535 {
		logger.Error("--port must be between 1 and 65535", "port", *port)
		fs.Usage()
		return exitBadParams
	}
	if *check != "" {
		lower := strings.ToLower(*check)
		if _, ok := protocolAliases[lower]; !ok {
			logger.Error("unknown protocol", "check", *check,
				"supported", "modbus, mms, s7, opcua, bacnet, can, profinet, dnp3, iec104, enip")
			return exitBadParams
		}
	}
	if *output != "text" && *output != "json" {
		logger.Error("--output must be text or json", "output", *output)
		return exitBadParams
	}

	// ---- safe mode overrides ----
	if *safe {
		logger.Info("OT-safe mode enabled: sequential, low concurrency")
		*parallel = false
	}

	// ---- build registry ----
	registry := defaultRegistry()

	// ---- build target ----
	target := core.Target{
		IP:      *ip,
		Port:    *port,
		Timeout: *timeout,
	}

	// ---- build engine config ----
	config := core.EngineConfig{
		Parallel:                *parallel,
		EarlyStop:               true,
		HighConfidenceThreshold: 0.9,
	}
	if *safe {
		config = core.SafeEngineConfig()
		config.EarlyStop = true
	}
	engine := core.NewEngine(registry, config)

	// ---- context ----
	ctx := context.Background()
	if *globalTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *globalTimeout)
		defer cancel()
	}

	logger.Info("scanning target", "ip", *ip, "port", *port, "parallel", *parallel)

	// ---- run detection ----
	if *check != "" {
		return runSpecificCheck(ctx, logger, engine, target, *check, *output, stdout)
	}
	return runFullDetection(ctx, logger, engine, target, *verbose, *output, stdout)
}

// defaultRegistry returns a registry pre-loaded with all known protocols.
func defaultRegistry() *core.Registry {
	registry := core.NewRegistry()
	_ = registry.Register(mms.New())
	_ = registry.Register(s7.New())
	_ = registry.Register(enip.New())
	_ = registry.Register(iec104.New())
	_ = registry.Register(dnp3.New())
	_ = registry.Register(modbus.New())
	_ = registry.Register(opcua.New())
	_ = registry.Register(bacnet.New())
	_ = registry.Register(can.New())
	_ = registry.Register(profinet.New())
	return registry
}

func runSpecificCheck(ctx context.Context, logger *slog.Logger, engine *core.Engine, target core.Target, protocol, format string, w io.Writer) int {
	lower := strings.ToLower(protocol)
	proto := protocolAliases[lower]

	logger.Info("checking specific protocol", "protocol", proto)

	result, err := engine.DetectProtocol(ctx, target, proto)
	if err != nil {
		logger.Error("detection error", "protocol", proto, "error", err)
		var pnf *core.ProtocolNotFoundError
		if errors.As(err, &pnf) {
			return exitBadParams
		}
		return exitConnError
	}

	if format == "json" {
		return writeJSON(w, target, result)
	}

	if result.Matched {
		_, _ = fmt.Fprintf(w, "%s: true\n", capitalizeFirst(lower))
		_, _ = fmt.Fprintf(w, "Confidence: %.2f\n", result.Confidence)
		_, _ = fmt.Fprintf(w, "Details: %s\n", result.Details)
		return exitDetected
	}
	_, _ = fmt.Fprintf(w, "%s: false\n", capitalizeFirst(lower))
	return exitUnknown
}

func runFullDetection(ctx context.Context, logger *slog.Logger, engine *core.Engine, target core.Target, verbose bool, format string, w io.Writer) int {
	result := engine.Detect(ctx, target)

	logger.Info("detection complete",
		"protocol", result.Protocol,
		"matched", result.Matched,
		"confidence", result.Confidence)

	if format == "json" {
		return writeJSON(w, target, result)
	}

	_, _ = fmt.Fprintf(w, "Target: %s\n", target.Addr())

	if !result.Matched {
		_, _ = fmt.Fprintln(w, "Detected: Unknown")
		return exitUnknown
	}

	_, _ = fmt.Fprintf(w, "Detected: %s\n", result.Protocol)
	_, _ = fmt.Fprintf(w, "Confidence: %.2f\n", result.Confidence)

	if verbose {
		_, _ = fmt.Fprintf(w, "Details: %s\n", result.Details)

		results := engine.DetectAll(ctx, target)
		if len(results) > 1 {
			_, _ = fmt.Fprintln(w, "\nAll results:")
			for _, r := range results {
				status := "no match"
				if r.Matched {
					status = fmt.Sprintf("matched (%.2f)", r.Confidence)
				}
				_, _ = fmt.Fprintf(w, "  %-20s %s\n", r.Protocol, status)
			}
		}
	}

	return exitDetected
}

// jsonOutput is the machine-readable result envelope.
type jsonOutput struct {
	Target     string  `json:"target"`
	Protocol   string  `json:"protocol"`
	Matched    bool    `json:"matched"`
	Confidence float64 `json:"confidence"`
	Details    string  `json:"details,omitempty"`
	Error      string  `json:"error,omitempty"`
}

func writeJSON(w io.Writer, target core.Target, r core.Result) int {
	out := jsonOutput{
		Target:     target.Addr(),
		Protocol:   r.Protocol.String(),
		Matched:    r.Matched,
		Confidence: r.Confidence,
		Details:    r.Details,
	}
	if r.Error != nil {
		out.Error = r.Error.Error()
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out) //nolint:errcheck

	if r.Matched {
		return exitDetected
	}
	return exitUnknown
}

func initLogger(w io.Writer, verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
	}))
}

func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
