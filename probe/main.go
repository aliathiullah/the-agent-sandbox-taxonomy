// ast-probe: Agent Sandbox Taxonomy verification probe.
// Drop this binary into any sandbox and run it. It probes all 7 AST defense
// layers from the inside, producing a machine-readable score card that can be
// compared against products.yaml.
//
// Safety: all destructive tests are bounded, self-cleaning, and target only
// probe-created resources.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/l1"
	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/l2"
	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/l3"
	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/l4"
	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/l5"
	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/l6"
	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/l7"
	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/report"
)

var version = "0.1.0"

func main() {
	product := flag.String("product", "", "sandbox product name (optional, for report labeling)")
	outFile := flag.String("out", "", "write JSON report to file (default: stdout)")
	quiet := flag.Bool("quiet", false, "suppress progress output, only emit JSON")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ast-probe %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	log := func(format string, args ...any) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}

	log("ast-probe %s — Agent Sandbox Taxonomy verification probe", version)
	log("OS: %s/%s  PID: %d  UID: %d", runtime.GOOS, runtime.GOARCH, os.Getpid(), os.Getuid())
	log("")

	r := &report.Report{
		ProbeVersion: version,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Product:      *product,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		PID:          os.Getpid(),
		UID:          os.Getuid(),
	}

	log("[1/7] L1 — Compute Isolation")
	r.L1 = l1.Probe()
	log("       -> %s (S:%d)", r.L1.DetectedMechanism, r.L1.AssessedStrength)

	log("[2/7] L2 — Resource Limits")
	r.L2 = l2.Probe()
	log("       -> %s (S:%d)", r.L2.DetectedMechanism, r.L2.AssessedStrength)

	log("[3/7] L3 — Filesystem Boundary")
	r.L3 = l3.Probe()
	log("       -> %s (S:%d)", r.L3.DetectedMechanism, r.L3.AssessedStrength)

	log("[4/7] L4 — Network Boundary")
	r.L4 = l4.Probe()
	log("       -> %s (S:%d)", r.L4.DetectedMechanism, r.L4.AssessedStrength)

	log("[5/7] L5 — Credential & Secret Management")
	r.L5 = l5.Probe()
	log("       -> %s (S:%d)", r.L5.DetectedMechanism, r.L5.AssessedStrength)

	log("[6/7] L6 — Action Governance")
	r.L6 = l6.Probe()
	log("       -> %s (S:%d)", r.L6.DetectedMechanism, r.L6.AssessedStrength)

	log("[7/7] L7 — Observability & Audit")
	r.L7 = l7.Probe()
	log("       -> %s (S:%d)", r.L7.DetectedMechanism, r.L7.AssessedStrength)

	r.ComputeFingerprint()
	r.ComputeThreats()

	log("")
	log("═══════════════════════════════════════════")
	log("  Fingerprint: %s", r.Fingerprint)
	log("═══════════════════════════════════════════")

	// Print warnings summary
	allWarnings := collectWarnings(r)
	if len(allWarnings) > 0 {
		log("")
		log("⚠ Warnings (%d):", len(allWarnings))
		for _, w := range allWarnings {
			log("  • %s", w)
		}
	}

	// Print threat summary
	log("")
	log("Threat Coverage:")
	for _, t := range r.Threats {
		symbol := "○"
		switch t.Rating {
		case "full":
			symbol = "●"
		case "partial":
			symbol = "◐"
		}
		log("  %s %s: %s", symbol, t.Threat, t.Detail)
	}
	log("")

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *outFile, err)
			os.Exit(1)
		}
		log("Report written to %s", *outFile)
	} else {
		fmt.Println(string(data))
	}
}

func collectWarnings(r *report.Report) []string {
	var all []string
	layers := []report.LayerResult{r.L1, r.L2, r.L3, r.L4, r.L5, r.L6, r.L7}
	for _, l := range layers {
		for _, w := range l.Warnings {
			all = append(all, fmt.Sprintf("[%s] %s", l.Layer, w))
		}
	}
	return all
}
