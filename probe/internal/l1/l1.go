// Package l1 probes L1 — Compute Isolation.
// Detects isolation technology and attempts known escape vectors.
package l1

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/report"
)

func Probe() report.LayerResult {
	r := report.LayerResult{
		Layer:      "L1",
		Confidence: "verified",
	}

	// --- Detection: what isolation are we inside? ---

	// Check for Firecracker microVM (CPUID hypervisor brand or DMI)
	if detectFirecracker() {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "firecracker_detection", Result: "detected",
			Detail: "Firecracker microVM signatures found",
		})
	}

	// Check for KVM / generic hypervisor
	if _, err := os.Stat("/dev/kvm"); err == nil {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "kvm_device", Result: "detected",
			Detail: "/dev/kvm exists — running on KVM-capable host or nested VM",
		})
	}

	// Check for generic VM/hypervisor (QEMU, KVM, Hyper-V, Xen, VMware, etc.)
	// This detects whether we're INSIDE a VM, not whether KVM is available.
	if vmType := detectVM(); vmType != "" {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "vm_detection", Result: "detected",
			Detail: fmt.Sprintf("Running inside a virtual machine: %s", vmType),
		})
	}

	// Check for gVisor (runsc)
	if detectGVisor() {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "gvisor_detection", Result: "detected",
			Detail: "gVisor user-space kernel detected via /proc/version or ENOSYS pattern",
		})
	}

	// Check for Docker container
	dockerContainer := false
	if _, err := os.Stat("/.dockerenv"); err == nil {
		dockerContainer = true
		r.Tests = append(r.Tests, report.TestResult{
			Name: "docker_container", Result: "detected",
			Detail: "/.dockerenv exists — running inside Docker container",
		})
	}

	// Check cgroup for container evidence
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") || strings.Contains(content, "containerd") ||
			strings.Contains(content, "kubepods") || strings.Contains(content, "lxc") {
			if !dockerContainer {
				r.Tests = append(r.Tests, report.TestResult{
					Name: "container_cgroup", Result: "detected",
					Detail: "Container-related cgroup entries found in /proc/1/cgroup",
				})
			}
		}
	}

	// Check PID namespace (PID 1 inside namespace vs host)
	if os.Getpid() > 0 {
		// Read /proc/1/sched to see if PID 1 is init or something else
		if data, err := os.ReadFile("/proc/1/comm"); err == nil {
			comm := strings.TrimSpace(string(data))
			r.Tests = append(r.Tests, report.TestResult{
				Name: "pid1_process", Result: "detected",
				Detail: fmt.Sprintf("PID 1 is: %s", comm),
			})
		}
	}

	// Check namespace isolation depth
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "NSpid:") {
				fields := strings.Fields(line)
				depth := len(fields) - 1 // NSpid: <host_pid> [<ns_pid>...]
				r.Tests = append(r.Tests, report.TestResult{
					Name: "pid_namespace_depth", Result: "detected",
					Detail: fmt.Sprintf("PID namespace depth: %d (1=host, >1=nested)", depth),
				})
			}
		}
	}

	// Check user namespace
	if data, err := os.ReadFile("/proc/self/uid_map"); err == nil {
		content := strings.TrimSpace(string(data))
		if content != "         0          0 4294967295" {
			r.Tests = append(r.Tests, report.TestResult{
				Name: "user_namespace", Result: "detected",
				Detail: fmt.Sprintf("Non-root uid_map detected: %s", content),
			})
		}
	}

	// Check mount namespace (count mounts)
	if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		r.Tests = append(r.Tests, report.TestResult{
			Name: "mount_namespace", Result: "detected",
			Detail: fmt.Sprintf("%d mount points visible", len(lines)),
		})
	}

	// Check for seccomp
	seccompActive := false
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Seccomp:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					mode := fields[1]
					seccompActive = mode != "0"
					label := "disabled"
					switch mode {
					case "1":
						label = "strict"
					case "2":
						label = "filter (BPF)"
					}
					r.Tests = append(r.Tests, report.TestResult{
						Name: "seccomp_status", Result: "detected",
						Detail: fmt.Sprintf("Seccomp mode: %s (%s)", mode, label),
					})
				}
			}
		}
	}

	// --- Escape attempts ---

	// Attempt to read host /proc/1/root (container escape vector)
	// But first: if WE are PID 1 (common in containers), reading our own
	// /proc/1/root is not an escape — it's just our own filesystem.
	// Only count this as an escape if PID 1 is a different process.
	weArePID1 := false
	if os.Getpid() == 1 {
		weArePID1 = true
	} else if data, err := os.ReadFile("/proc/self/status"); err == nil {
		// In a PID namespace, our real PID may differ but /proc/1 is still us
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "NSpid:") {
				fields := strings.Fields(line)
				// Last field is our PID in the innermost namespace
				if len(fields) >= 2 && fields[len(fields)-1] == "1" {
					weArePID1 = true
				}
			}
		}
	}

	if _, err := os.ReadDir("/proc/1/root"); err != nil {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "escape_proc1_root", Result: "blocked",
			Detail: fmt.Sprintf("Cannot access /proc/1/root: %v", err),
		})
	} else if weArePID1 {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "escape_proc1_root", Result: "skipped",
			Detail: "We are PID 1 in this namespace — /proc/1/root is our own filesystem, not an escape",
		})
	} else {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "escape_proc1_root", Result: "allowed",
			Detail: "WARNING: /proc/1/root is accessible and PID 1 is a different process — potential container escape vector",
		})
		r.Warnings = append(r.Warnings, "/proc/1/root accessible (PID 1 is a different process)")
	}

	// Attempt to access host /proc/sysrq-trigger
	if f, err := os.OpenFile("/proc/sysrq-trigger", os.O_WRONLY, 0); err != nil {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "escape_sysrq", Result: "blocked",
			Detail: fmt.Sprintf("Cannot write /proc/sysrq-trigger: %v", err),
		})
	} else {
		f.Close()
		r.Tests = append(r.Tests, report.TestResult{
			Name: "escape_sysrq", Result: "allowed",
			Detail: "WARNING: /proc/sysrq-trigger is writable — host kernel influence possible",
		})
		r.Warnings = append(r.Warnings, "/proc/sysrq-trigger writable")
	}

	// Attempt to mount procfs (requires CAP_SYS_ADMIN)
	tmpDir := "/tmp/ast-probe-mount-test"
	os.MkdirAll(tmpDir, 0755)
	err := tryMount("proc", tmpDir, "proc")
	os.Remove(tmpDir)
	if err != nil {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "escape_mount_proc", Result: "blocked",
			Detail: fmt.Sprintf("Cannot mount proc: %v", err),
		})
	} else {
		tryUnmount(tmpDir)
		r.Tests = append(r.Tests, report.TestResult{
			Name: "escape_mount_proc", Result: "allowed",
			Detail: "WARNING: Can mount filesystems — CAP_SYS_ADMIN likely available",
		})
		r.Warnings = append(r.Warnings, "mount syscall succeeded (CAP_SYS_ADMIN)")
	}

	// Check capabilities
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					r.Tests = append(r.Tests, report.TestResult{
						Name: "effective_capabilities", Result: "detected",
						Detail: fmt.Sprintf("CapEff: %s (0000000000000000=none, ffffffffffffffff=all)", fields[1]),
					})
					if fields[1] == "0000003fffffffff" || fields[1] == "000001ffffffffff" {
						r.Warnings = append(r.Warnings, "Full or near-full capabilities detected")
					}
				}
			}
		}
	}

	// Attempt ptrace on PID 1
	if runtime.GOOS == "linux" {
		err := tryPtraceAttach(1)
		if err != nil {
			r.Tests = append(r.Tests, report.TestResult{
				Name: "escape_ptrace_pid1", Result: "blocked",
				Detail: fmt.Sprintf("Cannot ptrace PID 1: %v", err),
			})
		} else {
			tryPtraceDetach(1)
			r.Tests = append(r.Tests, report.TestResult{
				Name: "escape_ptrace_pid1", Result: "allowed",
				Detail: "WARNING: Can ptrace PID 1 — weak isolation",
			})
			r.Warnings = append(r.Warnings, "ptrace on PID 1 succeeded")
		}
	}

	// --- Assess strength ---
	r.AssessedStrength, r.DetectedMechanism, r.Notes = assessL1(r.Tests, seccompActive)

	return r
}

func assessL1(tests []report.TestResult, seccompActive bool) (int, string, string) {
	hasFirecracker := testDetected(tests, "firecracker_detection")
	hasGVisor := testDetected(tests, "gvisor_detection")
	hasDocker := testDetected(tests, "docker_container") || testDetected(tests, "container_cgroup")
	hasVM := testDetected(tests, "vm_detection")

	// --- VM-based isolation (S:4) ---
	// Inside a VM, the isolation boundary is the hypervisor, not the kernel.
	// Full root, all caps, mount works — that's expected. The agent has a
	// full kernel but cannot escape the hardware boundary.
	// Escape tests are irrelevant here: they test the inner environment,
	// not the hypervisor boundary.
	if hasFirecracker {
		return 4, "firecracker-microvm", "Dedicated kernel per workload via KVM; minimal VMM; hardware isolation boundary"
	}
	if hasVM {
		return 4, "virtual-machine", "Running inside a VM; hardware isolation boundary (hypervisor-enforced)"
	}

	// --- For non-VM isolation, escape tests matter ---
	escapeSucceeded := false
	for _, t := range tests {
		if strings.HasPrefix(t.Name, "escape_") && t.Result == "allowed" {
			escapeSucceeded = true
			break
		}
	}

	if hasGVisor {
		if escapeSucceeded {
			return 2, "gvisor (escape vector found)", "gVisor detected but escape vector succeeded — downgrading from S:3"
		}
		return 3, "gvisor-userspace-kernel", "User-space kernel intercepting syscalls; reduced host surface"
	}

	if hasDocker {
		if seccompActive {
			if escapeSucceeded {
				return 2, "container+seccomp (escape vector found)", "Container with seccomp but escape vector succeeded"
			}
			return 3, "container+seccomp", "Container with kernel-enforced syscall filtering"
		}
		if escapeSucceeded {
			return 1, "container (weak)", "Container isolation with successful escape vector — near bare process"
		}
		return 2, "container-namespaces", "Linux namespaces + cgroups; shared host kernel"
	}

	// Check for any namespace isolation at all
	for _, t := range tests {
		if t.Name == "pid_namespace_depth" && strings.Contains(t.Detail, "depth: 1") {
			// We're on the host
			if seccompActive {
				return 3, "process+seccomp", "Process-level sandbox with seccomp-BPF"
			}
			return 0, "bare-process", "No isolation detected; full host access"
		}
	}

	if seccompActive {
		return 3, "process+seccomp", "Seccomp active but isolation type unclear"
	}

	return 1, "unknown-minimal", "Some isolation indicators present but type unclear; scoring conservatively"
}

func detectFirecracker() bool {
	// Check DMI product name
	if data, err := os.ReadFile("/sys/class/dmi/id/board_vendor"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "amazon") {
			if data2, err := os.ReadFile("/sys/class/dmi/id/board_name"); err == nil {
				if strings.Contains(strings.ToLower(string(data2)), "firecracker") {
					return true
				}
			}
		}
	}
	// Check hypervisor signature in cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "firecracker") || strings.Contains(lower, "fc_micro") {
			return true
		}
	}
	return false
}

func detectGVisor() bool {
	// gVisor identifies itself in /proc/version
	if data, err := os.ReadFile("/proc/version"); err == nil {
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "gvisor") || strings.Contains(lower, "runsc") {
			return true
		}
	}
	// gVisor's /proc/sys/kernel/hostname handling differs
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		if strings.Contains(string(data), "gvisor") {
			return true
		}
	}
	return false
}

func testDetected(tests []report.TestResult, name string) bool {
	for _, t := range tests {
		if t.Name == name && t.Result == "detected" {
			return true
		}
	}
	return false
}

// detectVM checks multiple sources to determine if we're inside a virtual machine.
// Returns the hypervisor name or empty string if not detected.
func detectVM() string {
	// 1. Check DMI/SMBIOS product name (most reliable on Linux)
	dmiPaths := []struct {
		path string
		desc string
	}{
		{"/sys/class/dmi/id/product_name", "product_name"},
		{"/sys/class/dmi/id/sys_vendor", "sys_vendor"},
		{"/sys/class/dmi/id/board_vendor", "board_vendor"},
		{"/sys/class/dmi/id/bios_vendor", "bios_vendor"},
		{"/sys/class/dmi/id/chassis_vendor", "chassis_vendor"},
	}

	vmSignatures := map[string]string{
		"qemu":          "QEMU/KVM",
		"kvm":           "KVM",
		"virtualbox":    "VirtualBox",
		"vmware":        "VMware",
		"hyper-v":       "Hyper-V",
		"microsoft":     "Hyper-V",
		"xen":           "Xen",
		"bochs":         "Bochs",
		"parallels":     "Parallels",
		"bhyve":         "bhyve",
		"apple virtualization": "Apple Virtualization.framework",
		"orbstack":      "OrbStack",
	}

	for _, dmi := range dmiPaths {
		if data, err := os.ReadFile(dmi.path); err == nil {
			lower := strings.ToLower(strings.TrimSpace(string(data)))
			for sig, name := range vmSignatures {
				if strings.Contains(lower, sig) {
					return name + " (via " + dmi.desc + ")"
				}
			}
		}
	}

	// 2. Check /proc/cpuinfo for hypervisor flag
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lower := strings.ToLower(string(data))
		if strings.Contains(lower, "hypervisor") {
			// The "hypervisor" CPU flag means we're in a VM
			return "hypervisor CPU flag detected"
		}
	}

	// 3. Check systemd-detect-virt style: /sys/hypervisor/type
	if data, err := os.ReadFile("/sys/hypervisor/type"); err == nil {
		hvType := strings.TrimSpace(string(data))
		if hvType != "" {
			return hvType + " (via /sys/hypervisor/type)"
		}
	}

	// 4. Check device tree (ARM VMs)
	if data, err := os.ReadFile("/proc/device-tree/hypervisor/compatible"); err == nil {
		return strings.TrimSpace(string(data)) + " (via device-tree)"
	}

	// 5. Check kernel version string for VM-specific builds
	// Some lightweight VMs (OrbStack, Lima, WSL2, Kata) ship custom kernels
	// that don't expose DMI/CPUID but are identifiable by their version string.
	if data, err := os.ReadFile("/proc/version"); err == nil {
		lower := strings.ToLower(string(data))
		kernelVMSignatures := map[string]string{
			"orbstack":       "OrbStack",
			"lima":           "Lima",
			"microsoft-standard-wsl": "WSL2",
			"kata":           "Kata Containers",
			"linuxkit":       "LinuxKit (Docker Desktop VM)",
			"multipass":      "Multipass",
		}
		for sig, name := range kernelVMSignatures {
			if strings.Contains(lower, sig) {
				return name + " (via /proc/version kernel string)"
			}
		}
	}

	return ""
}
