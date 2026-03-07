# ast-probe

A portable, statically-linked binary that probes all 7 AST (Agent Sandbox Taxonomy) defense layers from inside a sandbox, producing a machine-readable JSON score card with verified scores.

Drop it into any sandbox. Run it. Get verified scores instead of documentation-based guesses.

## Install

Download from [GitHub Releases](https://github.com/kajogo777/the-agent-sandbox-taxonomy/releases):

```bash
# Linux x86_64 (most cloud sandboxes)
curl -LO https://github.com/kajogo777/the-agent-sandbox-taxonomy/releases/latest/download/ast-probe-linux-amd64
chmod +x ast-probe-linux-amd64

# Linux ARM64 (Graviton, Apple Silicon VMs like OrbStack/Lima)
curl -LO https://github.com/kajogo777/the-agent-sandbox-taxonomy/releases/latest/download/ast-probe-linux-arm64

# macOS Apple Silicon
curl -LO https://github.com/kajogo777/the-agent-sandbox-taxonomy/releases/latest/download/ast-probe-darwin-arm64

# macOS Intel
curl -LO https://github.com/kajogo777/the-agent-sandbox-taxonomy/releases/latest/download/ast-probe-darwin-amd64
```

Or build from source:

```bash
cd probe && make build       # current platform
make build-all               # all 4 targets
```

## Usage

```bash
# Basic: run and print JSON to stdout
./ast-probe

# Label the report with the product name
./ast-probe --product "E2B"

# Write JSON to file, show progress on stderr
./ast-probe --product "Docker-hardened" --out report.json

# Quiet mode: JSON only on stdout, no progress
./ast-probe --quiet | jq .fingerprint

# Version
./ast-probe --version
```

### Flags

| Flag | Description |
|------|-------------|
| `--product NAME` | Label the report with the sandbox product name |
| `--out FILE` | Write JSON report to file (default: stdout) |
| `--quiet` | Suppress progress output, only emit JSON |
| `--version` | Print version and exit |

## What It Probes

| Layer | What It Tests |
|-------|--------------:|
| **L1 Compute Isolation** | Detects isolation type: Firecracker, gVisor, container, VM (QEMU/KVM, OrbStack, Lima, WSL2, Kata, VMware, Hyper-V), or bare process. Checks seccomp, capabilities, namespace depth, PID 1 identity. Tests escape vectors: /proc/1/root access, sysrq-trigger, mount syscall, ptrace PID 1. |
| **L2 Resource Limits** | Reads cgroup v1/v2 limits (memory, CPU, PIDs, I/O). Checks ulimits (nproc, nofile, address space). Detects size-limited mounts. Linux only — skipped on macOS. |
| **L3 Filesystem Boundary** | Checks 13 sensitive paths (~/.ssh, ~/.aws, ~/.kube, ~/.config/gcloud, etc.) and 4 system paths (/etc/shadow, /root, Docker socket). Tests writes outside CWD (distinguishes tmpfs scratch from persistent host paths). Checks root FS mutability, ephemeral/overlay detection, .env files, Docker socket connectivity. |
| **L4 Network Boundary** | Enumerates network interfaces. Tests DNS resolution, HTTPS outbound (httpbin.org), and raw TCP (1.1.1.1:443). Detects cooperative vs opaque enforcement (proxy env vars set but raw TCP bypasses = S:1). Tests cloud metadata endpoints (AWS/GCP/Azure). Probes RFC1918 ranges for lateral movement. Tests raw socket creation (CAP_NET_RAW). Scans loopback services. |
| **L5 Credential Management** | Scans env vars against 11 secret patterns (AWS, GCP, Azure, GitHub, DB, API keys, etc.). Detects placeholder substitution. Checks 12 credential file paths. Looks for credential proxy indicators (Unix sockets, Vault env vars). |
| **L6 Action Governance** | Tests writability of protected system paths (/etc/hostname, /etc/passwd, /etc/hosts, /usr/bin/env) — permission checks only, never modifies. Tests persistence vector writability (cron dirs, systemd dirs, git hooks). Tests shell/curl/wget execution. Tests dangerous syscalls (reboot, sethostname, init_module). Checks if running as root. |
| **L7 Observability & Audit** | Checks for audit log files, running observability processes (auditd, fluentd, OTel, Datadog, Falco, osquery, etc.). Probes telemetry ports (OTLP, Zipkin, Jaeger, StatsD). Detects OTel/DD/Sentry env vars. Checks kernel audit subsystem, eBPF programs, stdout capture mode. |

## Output

JSON report with per-layer results, an AST fingerprint, and mechanically-derived threat coverage:

```json
{
  "probe_version": "0.2.2",
  "fingerprint": "L1:3/L2:3/L3:4/L4:4/L5:4/L6:3/L7:1",
  "threats": [
    {"threat": "T1-Exfiltration", "rating": "full", "detail": "L3:4 L4:4 L5:4 (all need >=2)"},
    {"threat": "T2-SupplyChain", "rating": "partial", "detail": "L3:4 L4:4 L7:1 (all need >=2)"},
    {"threat": "T3-DestructiveOps", "rating": "full", "detail": "Local(L1:3,L3:4) Remote(L4:4,L6:3)"},
    {"threat": "T4-LateralMovement", "rating": "full", "detail": "L4:4 L1:3 (both need >=2)"},
    {"threat": "T5-Persistence", "rating": "full", "detail": "L1:3 L3:4 L6:3 ephemeral=false"},
    {"threat": "T6-PrivilegeEscalation", "rating": "full", "detail": "L1:3(need>=3) L2:3(need>=2)"},
    {"threat": "T7-DoS", "rating": "full", "detail": "L2:3 L1:3 (both need >=2)"}
  ]
}
```

## Safety

**The probe never performs destructive operations.** All tests use permission checks, not actual destruction:

- **Filesystem tests** use `OpenFile(O_WRONLY)` then immediately `Close()` — zero bytes written. Write tests create probe-owned temp files (`.ast-probe-*`) and immediately remove them.
- **Escape vector tests** are read-only: `stat`, `open`, `ptrace` — no actual exploitation.
- **Syscall tests** (reboot, sethostname, init_module) are Linux-only and return `ENOSYS` stubs on macOS. On Linux, `reboot(CAD_OFF)` only disables Ctrl-Alt-Del, `sethostname` changes the hostname inside the sandbox's UTS namespace (not the host), and `init_module` with null args fails immediately.
- **Network tests** connect to well-known public endpoints (httpbin.org, 1.1.1.1, dns.google) and cloud metadata IPs (169.254.169.254). On macOS, the first run may trigger a firewall dialog for the unsigned binary — you can allow or deny (denial is useful probe data).
- **No fork bombs** — resource limit detection reads cgroup files, doesn't stress-test.
- **No credential exfiltration** — secret scanning reads env var names and lengths, never logs values.

## Known Quirks & Limitations

### L1: VM Detection

Lightweight VMs that don't expose DMI/SMBIOS or CPUID hypervisor flags (OrbStack, Lima, WSL2, Kata, LinuxKit) are detected via `/proc/version` kernel string matching. If a VM ships a vanilla kernel without identifiable strings, the probe will score it as `S:0` (bare process) — a false negative. Known detected signatures:

| VM | Detection Method |
|----|-----------------|
| Firecracker | DMI board_vendor + board_name |
| QEMU/KVM | DMI product_name / sys_vendor |
| VirtualBox, VMware, Hyper-V, Xen, Parallels | DMI signatures |
| OrbStack | `/proc/version` contains "orbstack" |
| Lima | `/proc/version` contains "lima" |
| WSL2 | `/proc/version` contains "microsoft-standard-wsl" |
| Kata Containers | `/proc/version` contains "kata" |
| LinuxKit (Docker Desktop) | `/proc/version` contains "linuxkit" |
| gVisor | `/proc/version` contains "gvisor" or "runsc" |

**If your VM is not detected**, the probe will undercount L1. Check the `L1.tests` array in the JSON output for `vm_detection` results.

### L2: Linux Only

L2 (Resource Limits) probes cgroups and is skipped entirely on macOS/Darwin, returning `S:-1` (not assessed). macOS resource limits (sandbox profiles, launchd limits) are not yet probed.

### L3: tmpfs Awareness

The probe distinguishes between writes to tmpfs (bounded scratch space, expected in containers) and writes to persistent host paths. A write to `/tmp` on a tmpfs mount is not counted as an "escape" — only writes to persistent paths outside CWD count against the score.

### L4: macOS Firewall Dialog

On macOS, the first run triggers a system firewall dialog because the binary is unsigned. Allowing or denying both produce useful data — denial means the probe records network as blocked.

### L5: No Secrets Means No Score

If the environment has zero secrets in env vars and zero credential files, L5 returns `S:-1` (cannot assess) rather than `S:4`. The probe can't distinguish "credentials were never needed" from "credentials were structurally excluded." A `S:4` score requires positive evidence of a credential proxy or filtering mechanism.

### L6: Permission Checks, Not Execution

L6 tests whether protected paths are *writable*, not whether destructive operations *succeed*. This means: if `/etc/passwd` is writable but a MAC policy (AppArmor, SELinux) would block the actual write at a different layer, the probe may overcount L6 allowed results. The probe cannot detect MAC policies that permit `open()` but deny `write()`.

### L7: Inside-Out Limitation

L7 (Observability) is inherently limited from inside the sandbox. The probe can detect logging agents, audit daemons, and telemetry infrastructure that are *visible* from inside, but cannot verify:
- Whether logs are actually being collected and stored
- Whether the audit trail is tamper-evident
- Whether an external observer (Falco on the host, cloud-native audit) is watching

A sandbox with excellent external observability but no visible indicators inside will score low on L7.

### General: Threat Scores Are Mechanical

Threat coverage (T1–T7) is derived mechanically from layer scores using the AST threshold rules. The probe does not independently verify threat scenarios — it computes them from the layer assessments. If a layer score is wrong, the threat scores will be wrong too.

## Scoring Logic

Scores map directly to the AST mechanism reference tables:

| Score | Level | What It Means |
|-------|-------|---------------|
| **S:0** | None | No enforcement detected |
| **S:1** | Cooperative | Enforcement the sandboxed process can circumvent (e.g., proxy env vars) |
| **S:2** | Software-enforced | Separate process/proxy, not bypassable from inside |
| **S:3** | Kernel-enforced | seccomp, Landlock, Seatbelt — irreversible once applied |
| **S:4** | Structural | Resource doesn't exist inside sandbox (no network device, no credentials, VM boundary) |
| **S:-1** | Not assessed | Layer could not be evaluated (e.g., L2 on macOS) |

## Cross-Compilation

```bash
make build-all
# Produces:
#   ast-probe-linux-amd64
#   ast-probe-linux-arm64
#   ast-probe-darwin-amd64
#   ast-probe-darwin-arm64
```

All binaries are statically linked (`CGO_ENABLED=0`), zero dependencies.

## Releasing

Tag with `probe/v*` to trigger the GitHub Actions release workflow:

```bash
git tag probe/v0.2.2
git push origin probe/v0.2.2
```

This builds all 4 platform binaries, generates SHA-256 checksums, and creates a GitHub Release.
