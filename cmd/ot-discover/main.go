package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/boeboe/otfp/core"
	"github.com/boeboe/otfp/protocols/mms"
	"github.com/boeboe/otfp/protocols/modbus"
	"github.com/boeboe/otfp/protocols/s7"
)

// Version information, injected at build time via ldflags.
var (
	Version   = "dev"
	Branch    = "unknown"
	Revision  = "unknown"
	BuildUser = "unknown"
	BuildDate = "unknown"
)

const (
	exitDetected  = 0
	exitUnknown   = 1
	exitConnError = 2
	exitBadParams = 3
)

// protocolAliases maps CLI-friendly names to registered protocol names.
var protocolAliases = map[string]string{
	"modbus": "Modbus TCP",
	"mms":    "IEC 61850 MMS",
	"s7":     "Siemens S7comm",
}

func main() {
	ip := flag.String("ip", "", "Target IP address (required)")
	port := flag.Int("port", 0, "Target TCP port (required)")
	check := flag.String("check", "", "Check specific protocol: modbus, mms, s7")
	timeout := flag.Duration("timeout", 5*time.Second, "Connection timeout")
	verbose := flag.Bool("verbose", false, "Show detailed detection info")
	parallel := flag.Bool("parallel", true, "Run protocol checks in parallel")
	showVersion := flag.Bool("version", false, "Print version information and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ot-discover --ip <address> --port <port> [options]\n\n")
		fmt.Fprintf(os.Stderr, "OT Protocol Fingerprinting Tool\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nSupported protocols for --check:\n")
		fmt.Fprintf(os.Stderr, "  modbus    Modbus TCP\n")
		fmt.Fprintf(os.Stderr, "  mms       IEC 61850 MMS (ISO-on-TCP)\n")
		fmt.Fprintf(os.Stderr, "  s7        Siemens S7comm\n")
		fmt.Fprintf(os.Stderr, "\nExit codes:\n")
		fmt.Fprintf(os.Stderr, "  0  Protocol detected\n")
		fmt.Fprintf(os.Stderr, "  1  Unknown protocol\n")
		fmt.Fprintf(os.Stderr, "  2  Connection error\n")
		fmt.Fprintf(os.Stderr, "  3  Invalid parameters\n")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("ot-discover version %s\n", Version)
		fmt.Printf("  branch:     %s\n", Branch)
		fmt.Printf("  revision:   %s\n", Revision)
		fmt.Printf("  build user: %s\n", BuildUser)
		fmt.Printf("  build date: %s\n", BuildDate)
		os.Exit(0)
	}

	// Validate parameters.
	if *ip == "" {
		fmt.Fprintln(os.Stderr, "Error: --ip is required")
		flag.Usage()
		os.Exit(exitBadParams)
	}
	if *port <= 0 || *port > 65535 {
		fmt.Fprintln(os.Stderr, "Error: --port must be between 1 and 65535")
		flag.Usage()
		os.Exit(exitBadParams)
	}
	if *check != "" {
		lower := strings.ToLower(*check)
		if _, ok := protocolAliases[lower]; !ok {
			fmt.Fprintf(os.Stderr, "Error: unknown protocol %q. Supported: modbus, mms, s7\n", *check)
			os.Exit(exitBadParams)
		}
	}

	// Build registry.
	registry := core.NewRegistry()
	_ = registry.Register(modbus.New())
	_ = registry.Register(mms.New())
	_ = registry.Register(s7.New())

	// Build target.
	target := core.Target{
		IP:      *ip,
		Port:    *port,
		Timeout: *timeout,
	}

	// Build engine.
	config := core.EngineConfig{
		Parallel:                *parallel,
		EarlyStop:               true,
		HighConfidenceThreshold: 0.9,
	}
	engine := core.NewEngine(registry, config)

	ctx := context.Background()

	if *check != "" {
		runSpecificCheck(ctx, engine, target, *check, *verbose)
	} else {
		runFullDetection(ctx, engine, target, *verbose)
	}
}

func runSpecificCheck(ctx context.Context, engine *core.Engine, target core.Target, protocol string, verbose bool) {
	lower := strings.ToLower(protocol)
	protoName := protocolAliases[lower]

	result, err := engine.DetectProtocol(ctx, target, protoName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitConnError)
	}

	if result.Matched {
		fmt.Printf("%s: true\n", capitalizeFirst(lower))
		if verbose {
			fmt.Printf("Confidence: %.2f\n", result.Confidence)
			fmt.Printf("Details: %s\n", result.Details)
		}
		os.Exit(exitDetected)
	} else {
		fmt.Printf("%s: false\n", capitalizeFirst(lower))
		os.Exit(exitUnknown)
	}
}

func runFullDetection(ctx context.Context, engine *core.Engine, target core.Target, verbose bool) {
	result := engine.Detect(ctx, target)

	fmt.Printf("Target: %s\n", target.Addr())

	if !result.Matched {
		fmt.Println("Detected: Unknown")
		os.Exit(exitUnknown)
	}

	fmt.Printf("Detected: %s\n", result.Protocol)
	fmt.Printf("Confidence: %.2f\n", result.Confidence)

	if verbose {
		fmt.Printf("Details: %s\n", result.Details)

		// Show all results.
		results := engine.DetectAll(ctx, target)
		if len(results) > 1 {
			fmt.Println("\nAll results:")
			for _, r := range results {
				status := "no match"
				if r.Matched {
					status = fmt.Sprintf("matched (%.2f)", r.Confidence)
				}
				fmt.Printf("  %-20s %s\n", r.Protocol, status)
			}
		}
	}

	os.Exit(exitDetected)
}

func capitalizeFirst(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
