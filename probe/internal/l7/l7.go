// Package l7 probes L7 — Observability & Audit.
// Detects logging agents, audit daemons, and telemetry infrastructure
// from inside the sandbox. L7 is inherently limited from the inside —
// we can detect mechanisms but not verify log completeness.
package l7

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/report"
)

// knownLogPaths are paths where audit/logging infrastructure typically writes.
var knownLogPaths = []string{
	"/var/log/audit/audit.log",
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/auth.log",
	"/var/log/kern.log",
	"/var/log/journal",
}

// knownProcesses are process names associated with observability.
var knownProcesses = []string{
	"auditd",
	"rsyslogd",
	"syslog-ng",
	"journald",
	"systemd-journal",
	"fluentd",
	"fluent-bit",
	"filebeat",
	"vector",
	"promtail",
	"otel-collector",
	"opentelemetry",
	"datadog-agent",
	"dd-agent",
	"newrelic",
	"falco",
	"sysdig",
	"osquery",
	"telegraf",
}

// otelPorts are common OpenTelemetry collector ports.
var otelPorts = []struct {
	port int
	desc string
}{
	{4317, "OTLP gRPC"},
	{4318, "OTLP HTTP"},
	{9411, "Zipkin"},
	{14268, "Jaeger HTTP"},
	{8125, "StatsD"},
	{8126, "Datadog APM"},
}

func Probe() report.LayerResult {
	r := report.LayerResult{
		Layer:      "L7",
		Confidence: "verified",
	}

	detectedMechanisms := 0

	// --- Check for audit log files ---
	for _, p := range knownLogPaths {
		if fi, err := os.Stat(p); err == nil {
			detectedMechanisms++
			detail := fmt.Sprintf("Log path exists: %s", p)
			if fi.IsDir() {
				if entries, err := os.ReadDir(p); err == nil {
					detail = fmt.Sprintf("Log directory exists: %s (%d entries)", p, len(entries))
				}
			} else {
				detail = fmt.Sprintf("Log file exists: %s (%d bytes)", p, fi.Size())
			}
			r.Tests = append(r.Tests, report.TestResult{
				Name: "log_path_" + sanitizeName(p), Result: "detected",
				Detail: detail,
			})
		}
	}

	// --- Check for running observability processes ---
	if runtime.GOOS == "linux" {
		// Read /proc to find running processes
		entries, err := os.ReadDir("/proc")
		if err == nil {
			runningProcs := make(map[string]bool)
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				// Check if directory name is a PID (all digits)
				name := entry.Name()
				isPID := true
				for _, c := range name {
					if c < '0' || c > '9' {
						isPID = false
						break
					}
				}
				if !isPID {
					continue
				}
				commPath := fmt.Sprintf("/proc/%s/comm", name)
				if data, err := os.ReadFile(commPath); err == nil {
					comm := strings.TrimSpace(string(data))
					runningProcs[comm] = true
				}
			}

			for _, proc := range knownProcesses {
				if runningProcs[proc] {
					detectedMechanisms++
					r.Tests = append(r.Tests, report.TestResult{
						Name: "process_" + proc, Result: "detected",
						Detail: fmt.Sprintf("Observability process running: %s", proc),
					})
				}
			}
		}
	} else {
		// macOS/other: try ps
		if cmd, err := exec.LookPath("ps"); err == nil {
			out, err := exec.Command(cmd, "aux").Output()
			if err == nil {
				psOutput := string(out)
				for _, proc := range knownProcesses {
					if strings.Contains(psOutput, proc) {
						detectedMechanisms++
						r.Tests = append(r.Tests, report.TestResult{
							Name: "process_" + proc, Result: "detected",
							Detail: fmt.Sprintf("Observability process found in ps: %s", proc),
						})
					}
				}
			}
		}
	}

	// --- Check for OTel / telemetry collector endpoints ---
	for _, ep := range otelPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ep.port), 1*time.Second)
		if err == nil {
			conn.Close()
			detectedMechanisms++
			r.Tests = append(r.Tests, report.TestResult{
				Name: fmt.Sprintf("telemetry_port_%d", ep.port), Result: "detected",
				Detail: fmt.Sprintf("Telemetry endpoint listening: localhost:%d (%s)", ep.port, ep.desc),
			})
		}
	}

	// --- Check for OTel env vars ---
	otelVars := []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_SERVICE_NAME",
		"OTEL_RESOURCE_ATTRIBUTES",
		"DD_AGENT_HOST",
		"DD_TRACE_AGENT_URL",
		"NEW_RELIC_LICENSE_KEY",
		"SENTRY_DSN",
	}
	for _, v := range otelVars {
		if val := os.Getenv(v); val != "" {
			detectedMechanisms++
			r.Tests = append(r.Tests, report.TestResult{
				Name: "otel_env_" + strings.ToLower(v), Result: "detected",
				Detail: fmt.Sprintf("Telemetry env var: %s=%s", v, val),
			})
		}
	}

	// --- Check if stdout/stderr appear to be captured ---
	// If /dev/stdout points to a pipe or socket, something is capturing output
	if fi, err := os.Stat("/dev/stdout"); err == nil {
		mode := fi.Mode()
		if mode&os.ModeNamedPipe != 0 {
			detectedMechanisms++
			r.Tests = append(r.Tests, report.TestResult{
				Name: "stdout_capture", Result: "detected",
				Detail: "stdout is a pipe — output likely captured by orchestrator",
			})
		} else if mode&os.ModeSocket != 0 {
			detectedMechanisms++
			r.Tests = append(r.Tests, report.TestResult{
				Name: "stdout_capture", Result: "detected",
				Detail: "stdout is a socket — output likely streamed to collector",
			})
		}
	}

	// --- Check for Linux audit subsystem ---
	if runtime.GOOS == "linux" {
		// Check if audit rules are loaded
		if data, err := os.ReadFile("/proc/sys/kernel/audit_enabled"); err == nil {
			val := strings.TrimSpace(string(data))
			if val == "1" || val == "2" {
				detectedMechanisms++
				r.Tests = append(r.Tests, report.TestResult{
					Name: "kernel_audit", Result: "detected",
					Detail: fmt.Sprintf("Linux audit subsystem enabled (audit_enabled=%s)", val),
				})
			}
		}
	}

	// --- Check for Falco / eBPF-based runtime security ---
	if runtime.GOOS == "linux" {
		// Check for eBPF programs (requires /sys/fs/bpf or /proc/kallsyms)
		if _, err := os.Stat("/sys/fs/bpf"); err == nil {
			if entries, err := os.ReadDir("/sys/fs/bpf"); err == nil && len(entries) > 0 {
				detectedMechanisms++
				r.Tests = append(r.Tests, report.TestResult{
					Name: "ebpf_programs", Result: "detected",
					Detail: fmt.Sprintf("eBPF filesystem has %d entries — runtime monitoring likely active", len(entries)),
				})
			}
		}
	}

	// --- Assess strength ---
	r.AssessedStrength, r.DetectedMechanism, r.Notes = assessL7(detectedMechanisms, r.Tests)

	return r
}

func assessL7(detected int, tests []report.TestResult) (int, string, string) {
	if detected == 0 {
		return 0, "no-observability", "No logging, audit, or telemetry mechanisms detected"
	}

	// Check for specific high-value indicators
	hasAuditd := false
	hasOTel := false
	hasEBPF := false
	hasKernelAudit := false

	for _, t := range tests {
		if t.Result != "detected" {
			continue
		}
		switch {
		case t.Name == "process_auditd" || t.Name == "kernel_audit":
			hasKernelAudit = true
			hasAuditd = true
		case strings.HasPrefix(t.Name, "otel_env_") || strings.HasPrefix(t.Name, "telemetry_port_"):
			hasOTel = true
		case t.Name == "ebpf_programs":
			hasEBPF = true
		case t.Name == "process_falco" || t.Name == "process_sysdig":
			hasEBPF = true
		}
	}

	// S:3 — Full telemetry: kernel audit + eBPF + OTel
	if hasKernelAudit && (hasEBPF || hasOTel) {
		return 3, "full-telemetry", fmt.Sprintf(
			"Kernel audit + telemetry infrastructure detected (%d mechanisms)", detected)
	}

	// S:2 — Command-level audit: auditd or OTel or structured logging
	if hasAuditd || hasOTel || detected >= 3 {
		return 2, "command-level-audit", fmt.Sprintf(
			"Audit/telemetry infrastructure detected (%d mechanisms); auditd=%v otel=%v ebpf=%v",
			detected, hasAuditd, hasOTel, hasEBPF)
	}

	// S:1 — Session-level: basic logging only
	return 1, "session-level-logs", fmt.Sprintf(
		"Basic logging detected (%d mechanisms); no structured audit or telemetry", detected)
}

func sanitizeName(p string) string {
	p = strings.ReplaceAll(p, "/", "_")
	p = strings.ReplaceAll(p, ".", "")
	p = strings.TrimLeft(p, "_")
	return p
}
