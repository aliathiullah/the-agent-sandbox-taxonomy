// Package report defines the AST probe output structure and scoring logic.
package report

import "fmt"

// TestResult captures a single probe test outcome.
type TestResult struct {
	Name   string `json:"name"`
	Result string `json:"result"` // "blocked", "allowed", "error", "skipped", "detected", "not_detected"
	Detail string `json:"detail"` // human-readable explanation
}

// LayerResult captures the probe findings for one AST layer.
type LayerResult struct {
	Layer             string       `json:"layer"`
	AssessedStrength  int          `json:"assessed_strength"` // 0-4, -1 = not addressed
	Confidence        string       `json:"confidence"`        // "verified"
	DetectedMechanism string       `json:"detected_mechanism"`
	Tests             []TestResult `json:"tests"`
	Warnings          []string     `json:"warnings,omitempty"`
	Notes             string       `json:"notes"`
}

// ThreatResult captures the assessed coverage for one threat.
type ThreatResult struct {
	Threat string `json:"threat"`
	Rating string `json:"rating"` // "full", "partial", "none"
	Detail string `json:"detail"`
}

// Report is the top-level probe output.
type Report struct {
	ProbeVersion string         `json:"probe_version"`
	Timestamp    string         `json:"timestamp"`
	Product      string         `json:"product,omitempty"`
	OS           string         `json:"os"`
	Arch         string         `json:"arch"`
	PID          int            `json:"pid"`
	UID          int            `json:"uid"`
	L1           LayerResult    `json:"L1"`
	L2           LayerResult    `json:"L2"`
	L3           LayerResult    `json:"L3"`
	L4           LayerResult    `json:"L4"`
	L5           LayerResult    `json:"L5"`
	L6           LayerResult    `json:"L6"`
	L7           LayerResult    `json:"L7"`
	Fingerprint  string         `json:"fingerprint"`
	Threats      []ThreatResult `json:"threats"`
}

func fmtS(s int) string {
	if s < 0 {
		return "-"
	}
	return fmt.Sprintf("%d", s)
}

// ComputeFingerprint builds the compact fingerprint string from layer scores.
func (r *Report) ComputeFingerprint() {
	r.Fingerprint = fmt.Sprintf("L1:%s/L2:%s/L3:%s/L4:%s/L5:%s/L6:%s/L7:%s",
		fmtS(r.L1.AssessedStrength),
		fmtS(r.L2.AssessedStrength),
		fmtS(r.L3.AssessedStrength),
		fmtS(r.L4.AssessedStrength),
		fmtS(r.L5.AssessedStrength),
		fmtS(r.L6.AssessedStrength),
		fmtS(r.L7.AssessedStrength),
	)
}

func meets(s, min int) bool {
	return s >= min
}

func triRate(all, any bool) string {
	if all {
		return "full"
	}
	if any {
		return "partial"
	}
	return "none"
}

// ComputeThreats derives threat coverage mechanically from layer scores,
// following the AST threshold rules exactly (SKILL.md Part 7, Step 3).
func (r *Report) ComputeThreats() {
	s := func(lr LayerResult) int { return lr.AssessedStrength }

	// T1 Exfiltration: L3, L4, L5 all >= 2
	t1All := meets(s(r.L3), 2) && meets(s(r.L4), 2) && meets(s(r.L5), 2)
	t1Any := meets(s(r.L3), 2) || meets(s(r.L4), 2) || meets(s(r.L5), 2)
	r.Threats = append(r.Threats, ThreatResult{
		Threat: "T1-Exfiltration",
		Rating: triRate(t1All, t1Any),
		Detail: fmt.Sprintf("L3:%d L4:%d L5:%d (all need >=2)", s(r.L3), s(r.L4), s(r.L5)),
	})

	// T2 Supply Chain: L3, L4, L7 all >= 2
	t2All := meets(s(r.L3), 2) && meets(s(r.L4), 2) && meets(s(r.L7), 2)
	t2Any := meets(s(r.L3), 2) || meets(s(r.L4), 2) || meets(s(r.L7), 2)
	r.Threats = append(r.Threats, ThreatResult{
		Threat: "T2-SupplyChain",
		Rating: triRate(t2All, t2Any),
		Detail: fmt.Sprintf("L3:%d L4:%d L7:%d (all need >=2)", s(r.L3), s(r.L4), s(r.L7)),
	})

	// T3 Destructive Ops: Local(L1,L3 both>=2) + Remote(L4,L6 both>=2)
	t3lAll := meets(s(r.L1), 2) && meets(s(r.L3), 2)
	t3lAny := meets(s(r.L1), 2) || meets(s(r.L3), 2)
	t3rAll := meets(s(r.L4), 2) && meets(s(r.L6), 2)
	t3rAny := meets(s(r.L4), 2) || meets(s(r.L6), 2)
	t3Rating := "none"
	if t3lAll && t3rAll {
		t3Rating = "full"
	} else if t3lAny || t3rAny {
		t3Rating = "partial"
	}
	r.Threats = append(r.Threats, ThreatResult{
		Threat: "T3-DestructiveOps",
		Rating: t3Rating,
		Detail: fmt.Sprintf("Local(L1:%d,L3:%d) Remote(L4:%d,L6:%d)", s(r.L1), s(r.L3), s(r.L4), s(r.L6)),
	})

	// T4 Lateral Movement: L4, L1 both >= 2
	t4All := meets(s(r.L4), 2) && meets(s(r.L1), 2)
	t4Any := meets(s(r.L4), 2) || meets(s(r.L1), 2)
	r.Threats = append(r.Threats, ThreatResult{
		Threat: "T4-LateralMovement",
		Rating: triRate(t4All, t4Any),
		Detail: fmt.Sprintf("L4:%d L1:%d (both need >=2)", s(r.L4), s(r.L1)),
	})

	// T5 Persistence: ephemeral(L1>=4) OR all of L1>=2, L3>=2, L6>=2
	t5Ephemeral := s(r.L1) >= 4
	t5All := meets(s(r.L1), 2) && meets(s(r.L3), 2) && meets(s(r.L6), 2)
	t5Any := meets(s(r.L1), 2) || meets(s(r.L3), 2) || meets(s(r.L6), 2)
	t5Rating := "none"
	if t5Ephemeral || t5All {
		t5Rating = "full"
	} else if t5Any {
		t5Rating = "partial"
	}
	r.Threats = append(r.Threats, ThreatResult{
		Threat: "T5-Persistence",
		Rating: t5Rating,
		Detail: fmt.Sprintf("L1:%d L3:%d L6:%d ephemeral=%v", s(r.L1), s(r.L3), s(r.L6), t5Ephemeral),
	})

	// T6 Privilege Escalation: L1 >= 3 AND L2 >= 2
	t6All := meets(s(r.L1), 3) && meets(s(r.L2), 2)
	t6Any := meets(s(r.L1), 2) || meets(s(r.L2), 2)
	r.Threats = append(r.Threats, ThreatResult{
		Threat: "T6-PrivilegeEscalation",
		Rating: triRate(t6All, t6Any),
		Detail: fmt.Sprintf("L1:%d(need>=3) L2:%d(need>=2)", s(r.L1), s(r.L2)),
	})

	// T7 DoS: L2, L1 both >= 2
	t7All := meets(s(r.L2), 2) && meets(s(r.L1), 2)
	t7Any := meets(s(r.L2), 2) || meets(s(r.L1), 2)
	r.Threats = append(r.Threats, ThreatResult{
		Threat: "T7-DoS",
		Rating: triRate(t7All, t7Any),
		Detail: fmt.Sprintf("L2:%d L1:%d (both need >=2)", s(r.L2), s(r.L1)),
	})
}
