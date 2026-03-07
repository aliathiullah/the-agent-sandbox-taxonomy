// Package l2 probes L2 — Resource Limits.
// Detects cgroup limits, hypervisor allocation, and tests enforcement.
package l2

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/report"
)

// cgroupLimit represents a detected resource limit.
type cgroupLimit struct {
	resource string
	value    string
	path     string
}

func Probe() report.LayerResult {
	r := report.LayerResult{
		Layer:      "L2",
		Confidence: "verified",
	}

	if runtime.GOOS != "linux" {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "os_check", Result: "skipped",
			Detail: fmt.Sprintf("L2 cgroup probing requires Linux (running %s)", runtime.GOOS),
		})
		r.AssessedStrength = -1
		r.DetectedMechanism = "not-applicable"
		r.Notes = "Resource limit detection requires Linux; skipped on " + runtime.GOOS
		return r
	}

	var limits []cgroupLimit

	// --- cgroups v2 detection ---
	cgroupV2 := false
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		cgroupV2 = true
		r.Tests = append(r.Tests, report.TestResult{
			Name: "cgroup_version", Result: "detected",
			Detail: "cgroups v2 (unified hierarchy)",
		})
	} else {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "cgroup_version", Result: "detected",
			Detail: "cgroups v1 or no cgroup filesystem",
		})
	}

	// --- Memory limits ---
	memPaths := []string{
		"/sys/fs/cgroup/memory.max",                    // cgroups v2
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",  // cgroups v1
	}
	// Also check our own cgroup path
	if cgPath := getOwnCgroupPath(); cgPath != "" {
		memPaths = append([]string{
			filepath.Join("/sys/fs/cgroup", cgPath, "memory.max"),
		}, memPaths...)
	}
	for _, p := range memPaths {
		if data, err := os.ReadFile(p); err == nil {
			val := strings.TrimSpace(string(data))
			if val != "" && val != "max" && val != "9223372036854771712" {
				limits = append(limits, cgroupLimit{"memory", val, p})
				r.Tests = append(r.Tests, report.TestResult{
					Name: "memory_limit", Result: "detected",
					Detail: fmt.Sprintf("Memory limit: %s bytes (%s) from %s", val, humanBytes(val), p),
				})
				break
			} else if val == "max" || val == "9223372036854771712" {
				r.Tests = append(r.Tests, report.TestResult{
					Name: "memory_limit", Result: "not_detected",
					Detail: fmt.Sprintf("Memory limit: unlimited (%s from %s)", val, p),
				})
				break
			}
		}
	}

	// --- CPU limits ---
	cpuPaths := []string{
		"/sys/fs/cgroup/cpu.max",                       // cgroups v2
		"/sys/fs/cgroup/cpu/cpu.cfs_quota_us",          // cgroups v1
	}
	if cgPath := getOwnCgroupPath(); cgPath != "" {
		cpuPaths = append([]string{
			filepath.Join("/sys/fs/cgroup", cgPath, "cpu.max"),
		}, cpuPaths...)
	}
	for _, p := range cpuPaths {
		if data, err := os.ReadFile(p); err == nil {
			val := strings.TrimSpace(string(data))
			if val != "" && val != "max 100000" && val != "-1" {
				limits = append(limits, cgroupLimit{"cpu", val, p})
				r.Tests = append(r.Tests, report.TestResult{
					Name: "cpu_limit", Result: "detected",
					Detail: fmt.Sprintf("CPU limit: %s from %s", val, p),
				})
				break
			} else {
				r.Tests = append(r.Tests, report.TestResult{
					Name: "cpu_limit", Result: "not_detected",
					Detail: fmt.Sprintf("CPU limit: unlimited (%s from %s)", val, p),
				})
				break
			}
		}
	}

	// --- PIDs limit (fork bomb protection) ---
	pidPaths := []string{
		"/sys/fs/cgroup/pids.max",
		"/sys/fs/cgroup/pids/pids.max",
	}
	if cgPath := getOwnCgroupPath(); cgPath != "" {
		pidPaths = append([]string{
			filepath.Join("/sys/fs/cgroup", cgPath, "pids.max"),
		}, pidPaths...)
	}
	for _, p := range pidPaths {
		if data, err := os.ReadFile(p); err == nil {
			val := strings.TrimSpace(string(data))
			if val != "" && val != "max" {
				limits = append(limits, cgroupLimit{"pids", val, p})
				r.Tests = append(r.Tests, report.TestResult{
					Name: "pids_limit", Result: "detected",
					Detail: fmt.Sprintf("PIDs limit: %s from %s", val, p),
				})
				break
			} else {
				r.Tests = append(r.Tests, report.TestResult{
					Name: "pids_limit", Result: "not_detected",
					Detail: fmt.Sprintf("PIDs limit: unlimited (%s from %s)", val, p),
				})
				break
			}
		}
	}

	// --- I/O limits ---
	ioPaths := []string{
		"/sys/fs/cgroup/io.max",
	}
	if cgPath := getOwnCgroupPath(); cgPath != "" {
		ioPaths = append([]string{
			filepath.Join("/sys/fs/cgroup", cgPath, "io.max"),
		}, ioPaths...)
	}
	for _, p := range ioPaths {
		if data, err := os.ReadFile(p); err == nil {
			val := strings.TrimSpace(string(data))
			if val != "" {
				limits = append(limits, cgroupLimit{"io", val, p})
				r.Tests = append(r.Tests, report.TestResult{
					Name: "io_limit", Result: "detected",
					Detail: fmt.Sprintf("I/O limit: %s from %s", val, p),
				})
				break
			}
		}
	}

	// --- Disk quota (check filesystem) ---
	// Try to detect disk limits via df on our working directory
	if data, err := os.ReadFile("/proc/mounts"); err == nil {
		// Look for overlay or tmpfs with size limits
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "size=") && (strings.Contains(line, "tmpfs") || strings.Contains(line, "overlay")) {
				r.Tests = append(r.Tests, report.TestResult{
					Name: "disk_limit_mount", Result: "detected",
					Detail: fmt.Sprintf("Size-limited mount: %s", line),
				})
			}
		}
	}

	// --- ulimits ---
	var rlim [2]uint64 // soft, hard encoded as two uint64s
	// RLIMIT_NPROC = 6 on Linux
	if err := rlimitGet(6, &rlim); err == nil {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "ulimit_nproc", Result: "detected",
			Detail: fmt.Sprintf("RLIMIT_NPROC: soft=%d hard=%d", rlim[0], rlim[1]),
		})
		if rlim[1] < 65536 {
			limits = append(limits, cgroupLimit{"nproc", fmt.Sprintf("%d", rlim[1]), "ulimit"})
		}
	}
	// RLIMIT_NOFILE = 7
	if err := rlimitGet(7, &rlim); err == nil {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "ulimit_nofile", Result: "detected",
			Detail: fmt.Sprintf("RLIMIT_NOFILE: soft=%d hard=%d", rlim[0], rlim[1]),
		})
	}
	// RLIMIT_AS = 9 (address space)
	if err := rlimitGet(9, &rlim); err == nil {
		if rlim[1] != ^uint64(0) { // not unlimited
			r.Tests = append(r.Tests, report.TestResult{
				Name: "ulimit_as", Result: "detected",
				Detail: fmt.Sprintf("RLIMIT_AS: soft=%d hard=%d (%s)", rlim[0], rlim[1], humanBytes(fmt.Sprintf("%d", rlim[1]))),
			})
			limits = append(limits, cgroupLimit{"address_space", fmt.Sprintf("%d", rlim[1]), "ulimit"})
		}
	}

	// --- Assess strength ---
	r.AssessedStrength, r.DetectedMechanism, r.Notes = assessL2(limits, cgroupV2)

	return r
}

func assessL2(limits []cgroupLimit, cgroupV2 bool) (int, string, string) {
	if len(limits) == 0 {
		return 0, "none", "No resource limits detected; fork bomb / memory bomb / disk fill unmitigated"
	}

	hasCgroupLimits := false
	for _, l := range limits {
		if l.path != "ulimit" {
			hasCgroupLimits = true
			break
		}
	}

	if hasCgroupLimits && cgroupV2 {
		return 3, "cgroups-v2", fmt.Sprintf("Kernel-enforced resource limits via cgroups v2 (%d limits detected)", len(limits))
	}
	if hasCgroupLimits {
		return 2, "cgroups-v1", fmt.Sprintf("Resource limits via cgroups v1 (%d limits detected)", len(limits))
	}

	// Only ulimits
	return 1, "ulimits-only", fmt.Sprintf("Only ulimit-based limits detected (%d); process can work around some", len(limits))
}

func getOwnCgroupPath() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		// cgroups v2: "0::/path"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" {
			p := strings.TrimSpace(parts[2])
			if p != "" && p != "/" {
				return p
			}
		}
	}
	return ""
}

func humanBytes(s string) string {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return s
	}
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func rlimitGet(resource int, rlim *[2]uint64) error {
	var r syscall.Rlimit
	if err := syscall.Getrlimit(resource, &r); err != nil {
		return err
	}
	rlim[0] = r.Cur
	rlim[1] = r.Max
	return nil
}
