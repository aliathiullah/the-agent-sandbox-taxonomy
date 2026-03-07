// Package l4 probes L4 — Network Boundary.
// Tests what external systems the agent can communicate with and how
// traffic is intercepted (cooperative vs opaque vs structural).
package l4

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/report"
)

// cloudMetadataEndpoints are IMDS endpoints that should be blocked.
var cloudMetadataEndpoints = []struct {
	name    string
	addr    string
	headers map[string]string
}{
	{"aws", "http://169.254.169.254/latest/meta-data/", nil},
	{"gcp", "http://metadata.google.internal/computeMetadata/v1/", map[string]string{"Metadata-Flavor": "Google"}},
	{"azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", map[string]string{"Metadata": "true"}},
}

// rfc1918Ranges are private network ranges for lateral movement testing.
var rfc1918Probes = []string{
	"10.0.0.1:80",
	"172.17.0.1:80",  // Docker bridge default
	"192.168.1.1:80",
}

func Probe() report.LayerResult {
	r := report.LayerResult{
		Layer:      "L4",
		Confidence: "verified",
	}

	// --- Check if network interfaces exist at all ---
	ifaces, err := net.Interfaces()
	if err != nil {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "network_interfaces", Result: "error",
			Detail: fmt.Sprintf("Cannot enumerate interfaces: %v", err),
		})
	} else {
		nonLoopback := 0
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
				nonLoopback++
			}
		}
		if nonLoopback == 0 {
			r.Tests = append(r.Tests, report.TestResult{
				Name: "network_interfaces", Result: "blocked",
				Detail: "No non-loopback network interfaces — network structurally disabled (S:4)",
			})
			// Structural: no network device
			r.AssessedStrength = 4
			r.DetectedMechanism = "network-disabled"
			r.Notes = "No network interface exists; structural enforcement"
			return r
		}
		names := make([]string, 0, len(ifaces))
		for _, iface := range ifaces {
			names = append(names, fmt.Sprintf("%s(%s)", iface.Name, iface.Flags))
		}
		r.Tests = append(r.Tests, report.TestResult{
			Name: "network_interfaces", Result: "detected",
			Detail: fmt.Sprintf("%d interfaces (%d non-loopback up): %s", len(ifaces), nonLoopback, strings.Join(names, ", ")),
		})
	}

	// --- Check for proxy env vars (cooperative enforcement indicator) ---
	proxyVars := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "NO_PROXY"}
	proxySet := false
	for _, v := range proxyVars {
		if val := os.Getenv(v); val != "" {
			proxySet = true
			r.Tests = append(r.Tests, report.TestResult{
				Name: "proxy_env_" + strings.ToLower(v), Result: "detected",
				Detail: fmt.Sprintf("%s=%s", v, val),
			})
		}
	}

	// --- DNS resolution test ---
	dnsOK := false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resolver := &net.Resolver{}
	if addrs, err := resolver.LookupHost(ctx, "dns.google"); err == nil {
		dnsOK = true
		r.Tests = append(r.Tests, report.TestResult{
			Name: "dns_resolution", Result: "allowed",
			Detail: fmt.Sprintf("DNS resolves dns.google -> %v", addrs),
		})
	} else {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "dns_resolution", Result: "blocked",
			Detail: fmt.Sprintf("DNS resolution failed: %v", err),
		})
	}

	// --- HTTP/HTTPS outbound test (uses standard library — respects proxy) ---
	httpClient := &http.Client{Timeout: 10 * time.Second}
	httpOK := false
	if resp, err := httpClient.Get("https://httpbin.org/get"); err == nil {
		resp.Body.Close()
		httpOK = true
		r.Tests = append(r.Tests, report.TestResult{
			Name: "https_outbound", Result: "allowed",
			Detail: fmt.Sprintf("HTTPS to httpbin.org succeeded (status %d)", resp.StatusCode),
		})
	} else {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "https_outbound", Result: "blocked",
			Detail: fmt.Sprintf("HTTPS to httpbin.org failed: %v", err),
		})
	}

	// --- Raw TCP socket test (bypasses proxy env vars) ---
	// This is the key cooperative vs opaque test. If proxy env vars are set
	// but raw TCP succeeds, enforcement is cooperative (S:1).
	rawTCPOK := false
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 5*time.Second)
	if err == nil {
		conn.Close()
		rawTCPOK = true
		r.Tests = append(r.Tests, report.TestResult{
			Name: "raw_tcp_outbound", Result: "allowed",
			Detail: "Raw TCP to 1.1.1.1:443 succeeded (bypasses proxy env vars)",
		})
		if proxySet {
			r.Warnings = append(r.Warnings, "Proxy env vars set but raw TCP succeeds — cooperative enforcement only (S:1)")
		}
	} else {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "raw_tcp_outbound", Result: "blocked",
			Detail: fmt.Sprintf("Raw TCP to 1.1.1.1:443 blocked: %v", err),
		})
	}

	// --- Raw socket creation test (SOCK_RAW — needs CAP_NET_RAW) ---
	rawSockFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err == nil {
		syscall.Close(rawSockFd)
		r.Tests = append(r.Tests, report.TestResult{
			Name: "raw_socket_create", Result: "allowed",
			Detail: "Can create SOCK_RAW (ICMP) — CAP_NET_RAW available",
		})
		r.Warnings = append(r.Warnings, "Raw socket creation allowed (CAP_NET_RAW)")
	} else {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "raw_socket_create", Result: "blocked",
			Detail: fmt.Sprintf("SOCK_RAW creation blocked: %v", err),
		})
	}

	// --- Cloud metadata endpoint tests ---
	metadataBlocked := 0
	metadataAllowed := 0
	for _, ep := range cloudMetadataEndpoints {
		req, _ := http.NewRequest("GET", ep.addr, nil)
		for k, v := range ep.headers {
			req.Header.Set(k, v)
		}
		client := &http.Client{
			Timeout: 3 * time.Second,
			// Don't follow redirects for metadata
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			metadataBlocked++
			r.Tests = append(r.Tests, report.TestResult{
				Name: "metadata_" + ep.name, Result: "blocked",
				Detail: fmt.Sprintf("%s metadata endpoint unreachable: %v", ep.name, err),
			})
		} else {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				metadataAllowed++
				r.Tests = append(r.Tests, report.TestResult{
					Name: "metadata_" + ep.name, Result: "allowed",
					Detail: fmt.Sprintf("WARNING: %s metadata endpoint accessible (status %d)", ep.name, resp.StatusCode),
				})
				r.Warnings = append(r.Warnings, fmt.Sprintf("Cloud metadata accessible: %s", ep.name))
			} else {
				metadataBlocked++
				r.Tests = append(r.Tests, report.TestResult{
					Name: "metadata_" + ep.name, Result: "blocked",
					Detail: fmt.Sprintf("%s metadata returned status %d", ep.name, resp.StatusCode),
				})
			}
		}
	}

	// --- RFC1918 lateral movement probes ---
	lateralReachable := 0
	for _, addr := range rfc1918Probes {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			conn.Close()
			lateralReachable++
			r.Tests = append(r.Tests, report.TestResult{
				Name: "lateral_" + strings.Replace(addr, ":", "_", 1), Result: "allowed",
				Detail: fmt.Sprintf("Can reach private network: %s", addr),
			})
		} else {
			r.Tests = append(r.Tests, report.TestResult{
				Name: "lateral_" + strings.Replace(addr, ":", "_", 1), Result: "blocked",
				Detail: fmt.Sprintf("Private network unreachable: %s (%v)", addr, err),
			})
		}
	}

	// --- Loopback access (other services on same host) ---
	loopbackPorts := []int{8080, 3000, 5432, 6379, 27017} // common dev services
	loopbackReachable := 0
	for _, port := range loopbackPorts {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			conn.Close()
			loopbackReachable++
			r.Tests = append(r.Tests, report.TestResult{
				Name: fmt.Sprintf("loopback_%d", port), Result: "allowed",
				Detail: fmt.Sprintf("Loopback port %d is reachable (service running)", port),
			})
		}
		// Don't log blocked loopback — too noisy, most ports won't have services
	}
	if loopbackReachable > 0 {
		r.Tests = append(r.Tests, report.TestResult{
			Name: "loopback_summary", Result: "detected",
			Detail: fmt.Sprintf("%d loopback services reachable", loopbackReachable),
		})
	}

	// --- Assess strength ---
	r.AssessedStrength, r.DetectedMechanism, r.Notes = assessL4(
		dnsOK, httpOK, rawTCPOK, proxySet, metadataAllowed, lateralReachable,
	)

	return r
}

func assessL4(dnsOK, httpOK, rawTCPOK, proxySet bool, metadataAllowed, lateralReachable int) (int, string, string) {
	// No outbound at all
	if !dnsOK && !httpOK && !rawTCPOK {
		return 4, "network-disabled", "All outbound blocked (DNS, HTTP, raw TCP) — structural or near-structural enforcement"
	}

	// Proxy set but raw TCP works — cooperative only
	if proxySet && rawTCPOK {
		return 1, "cooperative-proxy", "Proxy env vars set but raw TCP bypasses them — cooperative enforcement (S:1)"
	}

	// HTTP works but raw TCP blocked — opaque proxy/firewall
	if httpOK && !rawTCPOK {
		if metadataAllowed == 0 && lateralReachable == 0 {
			return 3, "kernel-enforced-filter", "HTTP proxied, raw TCP blocked, metadata blocked, no lateral — kernel/hypervisor enforcement"
		}
		return 2, "opaque-proxy", "HTTP proxied, raw TCP blocked — opaque enforcement but some gaps"
	}

	// Everything works but metadata blocked
	if rawTCPOK && metadataAllowed == 0 && lateralReachable == 0 {
		return 2, "partial-firewall", "Outbound allowed but metadata and private networks blocked — partial firewall"
	}

	// Everything works, some restrictions
	if rawTCPOK && (metadataAllowed == 0 || lateralReachable == 0) {
		return 1, "minimal-network-restriction", "Outbound mostly unrestricted with minor blocks"
	}

	// Everything works, no restrictions
	if rawTCPOK {
		return 0, "no-network-boundary", fmt.Sprintf(
			"Full outbound access: raw TCP OK, %d metadata endpoints reachable, %d private networks reachable",
			metadataAllowed, lateralReachable)
	}

	// DNS works but nothing else
	if dnsOK && !httpOK && !rawTCPOK {
		return 3, "dns-only", "Only DNS resolution works; all TCP blocked"
	}

	return 1, "unknown-partial", "Some network restrictions detected but pattern unclear"
}
