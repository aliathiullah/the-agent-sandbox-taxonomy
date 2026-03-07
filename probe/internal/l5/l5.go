// Package l5 probes L5 — Credential & Secret Management.
// Scans for secrets in environment variables and on disk, and tests
// whether the full T1 exfiltration chain (read secret + send it out) works.
package l5

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kajogo777/the-agent-sandbox-taxonomy/probe/internal/report"
)

// secretPatterns are regex patterns that match common secret env var names.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|_)(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)$`),
	regexp.MustCompile(`(?i)(^|_)(AZURE_CLIENT_SECRET|AZURE_TENANT_ID)$`),
	regexp.MustCompile(`(?i)(^|_)(GCP_SERVICE_ACCOUNT_KEY|GOOGLE_APPLICATION_CREDENTIALS)$`),
	regexp.MustCompile(`(?i)(^|_)(ANTHROPIC_API_KEY|OPENAI_API_KEY)$`),
	regexp.MustCompile(`(?i)(^|_)(GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|BITBUCKET_TOKEN)$`),
	regexp.MustCompile(`(?i)(^|_)(DATABASE_URL|DB_PASSWORD|REDIS_URL|MONGO_URI)$`),
	regexp.MustCompile(`(?i)(^|_)(SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)$`),
	regexp.MustCompile(`(?i)(^|_)(JWT_SECRET|SESSION_SECRET|ENCRYPTION_KEY|SIGNING_KEY)$`),
	regexp.MustCompile(`(?i)(^|_)(SLACK_TOKEN|SLACK_WEBHOOK|DISCORD_TOKEN|TELEGRAM_TOKEN)$`),
	regexp.MustCompile(`(?i)(^|_)(STRIPE_SECRET|TWILIO_AUTH_TOKEN|SENDGRID_API_KEY)$`),
	regexp.MustCompile(`(?i)(^|_)(NPM_TOKEN|PYPI_TOKEN|DOCKER_PASSWORD|REGISTRY_PASSWORD)$`),
}

// placeholderPatterns detect if secrets have been substituted with placeholders.
var placeholderPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^<REDACTED.*>$`),
	regexp.MustCompile(`^\*+$`),
	regexp.MustCompile(`^placeholder-`),
	regexp.MustCompile(`^PLACEHOLDER`),
	regexp.MustCompile(`^sk-placeholder`),
	regexp.MustCompile(`^MASKED`),
	regexp.MustCompile(`^\$\{.*\}$`), // ${VAR} style
}

// credentialFiles are files that commonly contain credentials.
var credentialFiles = []struct {
	path string
	desc string
}{
	{"~/.ssh/id_rsa", "SSH private key (RSA)"},
	{"~/.ssh/id_ed25519", "SSH private key (Ed25519)"},
	{"~/.ssh/id_ecdsa", "SSH private key (ECDSA)"},
	{"~/.aws/credentials", "AWS credentials file"},
	{"~/.aws/config", "AWS config (may contain SSO tokens)"},
	{"~/.kube/config", "Kubernetes config (may contain tokens)"},
	{"~/.config/gcloud/application_default_credentials.json", "GCP application default credentials"},
	{"~/.docker/config.json", "Docker registry credentials"},
	{"~/.netrc", "Netrc credentials (git, curl)"},
	{"~/.npmrc", "NPM registry token"},
	{"~/.pypirc", "PyPI upload credentials"},
	{"~/.gitconfig", "Git config (may contain tokens)"},
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return p
		}
		return filepath.Join(home, p[2:])
	}
	return p
}

func Probe() report.LayerResult {
	r := report.LayerResult{
		Layer:      "L5",
		Confidence: "verified",
	}

	// --- Scan environment variables for secrets ---
	secretsInEnv := 0
	placeholdersFound := 0
	filteredVars := 0
	totalChecked := 0

	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name, value := parts[0], parts[1]

		for _, pat := range secretPatterns {
			if pat.MatchString(name) {
				totalChecked++
				if value == "" {
					filteredVars++
					r.Tests = append(r.Tests, report.TestResult{
						Name: "env_secret_" + strings.ToLower(name), Result: "blocked",
						Detail: fmt.Sprintf("Secret var %s exists but is empty (filtered)", name),
					})
				} else if isPlaceholder(value) {
					placeholdersFound++
					r.Tests = append(r.Tests, report.TestResult{
						Name: "env_secret_" + strings.ToLower(name), Result: "blocked",
						Detail: fmt.Sprintf("Secret var %s contains placeholder value (substituted)", name),
					})
				} else {
					secretsInEnv++
					// Don't log the actual value — just the name and length
					r.Tests = append(r.Tests, report.TestResult{
						Name: "env_secret_" + strings.ToLower(name), Result: "allowed",
						Detail: fmt.Sprintf("WARNING: Secret var %s is present (%d chars)", name, len(value)),
					})
					r.Warnings = append(r.Warnings, fmt.Sprintf("Secret in env: %s (%d chars)", name, len(value)))
				}
				break // don't double-count
			}
		}
	}

	r.Tests = append(r.Tests, report.TestResult{
		Name: "env_secret_summary", Result: "detected",
		Detail: fmt.Sprintf("Env scan: %d secrets exposed, %d placeholders, %d filtered, %d total matched",
			secretsInEnv, placeholdersFound, filteredVars, totalChecked),
	})

	// --- Scan credential files ---
	credFilesReadable := 0
	credFilesBlocked := 0
	for _, cf := range credentialFiles {
		expanded := expandHome(cf.path)
		if data, err := os.ReadFile(expanded); err == nil {
			credFilesReadable++
			r.Tests = append(r.Tests, report.TestResult{
				Name: "cred_file_" + sanitizeName(cf.path), Result: "allowed",
				Detail: fmt.Sprintf("WARNING: %s readable (%d bytes) — %s", cf.path, len(data), cf.desc),
			})
			r.Warnings = append(r.Warnings, fmt.Sprintf("Credential file readable: %s", cf.path))
		} else {
			credFilesBlocked++
			r.Tests = append(r.Tests, report.TestResult{
				Name: "cred_file_" + sanitizeName(cf.path), Result: "blocked",
				Detail: fmt.Sprintf("%s not readable: %v", cf.path, err),
			})
		}
	}

	// --- Check for credential proxy indicators ---
	// Look for signs that credentials are proxied rather than injected
	proxyIndicators := 0

	// Check for Unix socket credential proxies
	proxySocketPaths := []string{
		"/tmp/credential-proxy.sock",
		"/var/run/credential-proxy.sock",
		"/tmp/auth-proxy.sock",
	}
	for _, sp := range proxySocketPaths {
		if fi, err := os.Stat(sp); err == nil && fi.Mode()&os.ModeSocket != 0 {
			proxyIndicators++
			r.Tests = append(r.Tests, report.TestResult{
				Name: "credential_proxy_socket", Result: "detected",
				Detail: fmt.Sprintf("Credential proxy socket found: %s", sp),
			})
		}
	}

	// Check for credential proxy env vars
	proxyEnvVars := []string{
		"CREDENTIAL_PROXY_URL",
		"AUTH_PROXY_ENDPOINT",
		"VAULT_ADDR",
		"VAULT_TOKEN",
	}
	for _, v := range proxyEnvVars {
		if val := os.Getenv(v); val != "" {
			proxyIndicators++
			r.Tests = append(r.Tests, report.TestResult{
				Name: "credential_proxy_env_" + strings.ToLower(v), Result: "detected",
				Detail: fmt.Sprintf("Credential proxy indicator: %s=%s", v, val),
			})
		}
	}

	// --- Assess strength ---
	r.AssessedStrength, r.DetectedMechanism, r.Notes = assessL5(
		secretsInEnv, placeholdersFound, filteredVars, credFilesReadable, credFilesBlocked, proxyIndicators,
	)

	return r
}

func assessL5(secretsInEnv, placeholders, filtered, credFilesReadable, credFilesBlocked, proxyIndicators int) (int, string, string) {
	totalSecretSources := secretsInEnv + credFilesReadable

	// S:4 — Credential proxy: no secrets present at all
	if totalSecretSources == 0 && proxyIndicators > 0 {
		return 4, "credential-proxy", fmt.Sprintf(
			"No secrets in env or on disk; credential proxy detected (%d indicators)", proxyIndicators)
	}

	// S:4 — No secrets present (even without proxy)
	if totalSecretSources == 0 && placeholders == 0 && filtered == 0 {
		return 4, "no-credentials-present", "No secrets found in env or on disk — structural absence"
	}

	// S:3 — Placeholder substitution: secrets replaced with tokens
	if placeholders > 0 && secretsInEnv == 0 && credFilesReadable == 0 {
		return 3, "placeholder-substitution", fmt.Sprintf(
			"Secrets substituted with placeholders (%d found); no raw secrets in env or on disk", placeholders)
	}

	// S:3 — Credential files blocked, env filtered
	if credFilesReadable == 0 && credFilesBlocked > 0 && secretsInEnv == 0 {
		return 3, "sensitive-file-blocking", fmt.Sprintf(
			"All credential files blocked (%d), env vars filtered (%d)", credFilesBlocked, filtered)
	}

	// S:2 — Env var filtering (some secrets filtered but some leak)
	if filtered > 0 && secretsInEnv == 0 {
		return 2, "env-var-filtering", fmt.Sprintf(
			"Env vars filtered (%d filtered); credential files: %d readable, %d blocked",
			filtered, credFilesReadable, credFilesBlocked)
	}

	// S:1 — Secrets present but some mitigation
	if totalSecretSources > 0 && (filtered > 0 || credFilesBlocked > 0) {
		return 1, "partial-credential-exposure", fmt.Sprintf(
			"Secrets exposed (%d env, %d files) despite some filtering (%d filtered, %d files blocked)",
			secretsInEnv, credFilesReadable, filtered, credFilesBlocked)
	}

	// S:0 — Full credential exposure
	if totalSecretSources > 0 {
		return 0, "full-credential-exposure", fmt.Sprintf(
			"Full credential exposure: %d secrets in env, %d credential files readable",
			secretsInEnv, credFilesReadable)
	}

	// No secrets found and no filtering — can't determine
	return -1, "no-credentials-to-test", "No secrets or credential files found; cannot assess credential management"
}

func isPlaceholder(value string) bool {
	for _, pat := range placeholderPatterns {
		if pat.MatchString(value) {
			return true
		}
	}
	return false
}

func sanitizeName(p string) string {
	p = strings.ReplaceAll(p, "/", "_")
	p = strings.ReplaceAll(p, "~", "home")
	p = strings.ReplaceAll(p, ".", "")
	p = strings.TrimLeft(p, "_")
	return p
}
