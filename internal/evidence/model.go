// Package evidence defines TrustFall's versioned, deliberately non-binary evidence model.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "1.0.0"

type Classification string

const (
	Observed Classification = "observed"
	Verified Classification = "verified"
	Inferred Classification = "inferred"
	Unknown  Classification = "unknown"
)

type Severity string

const (
	SeverityNote     Severity = "note"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Status string

const (
	StatusPass          Status = "pass"
	StatusFail          Status = "fail"
	StatusInfo          Status = "informational"
	StatusUnknown       Status = "unknown"
	StatusNotApplicable Status = "not_applicable"
)

type ProbeMetadata struct {
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Duration     time.Duration `json:"duration_ns"`
	TimedOut     bool          `json:"timed_out,omitempty"`
	Network      bool          `json:"network,omitempty"`
	Active       bool          `json:"active,omitempty"`
	Requirements []string      `json:"requirements,omitempty"`
}

type Finding struct {
	RuleID         string         `json:"rule_id"`
	Title          string         `json:"title"`
	Severity       Severity       `json:"severity"`
	Classification Classification `json:"evidence_classification"`
	Module         string         `json:"module"`
	Status         Status         `json:"status"`
	Observed       string         `json:"observed_condition"`
	Expected       string         `json:"expected_condition,omitempty"`
	Implications   string         `json:"security_implications"`
	Remediation    string         `json:"remediation_guidance"`
	Timestamp      time.Time      `json:"timestamp"`
	Probe          ProbeMetadata  `json:"probe"`
	Evidence       map[string]any `json:"evidence,omitempty"`
	Fingerprint    string         `json:"fingerprint"`
}

type RunMetadata struct {
	ID            string    `json:"id"`
	StartedAt     time.Time `json:"started_at"`
	CompletedAt   time.Time `json:"completed_at"`
	Profile       string    `json:"profile"`
	PolicyMode    string    `json:"policy_mode"`
	NetworkDenied bool      `json:"network_denied"`
	ToolVersion   string    `json:"tool_version"`
}

type Report struct {
	SchemaVersion string      `json:"schema_version"`
	Tool          string      `json:"tool"`
	Run           RunMetadata `json:"run"`
	Findings      []Finding   `json:"findings"`
}

func NewFinding(rule, title, module string, severity Severity, class Classification, status Status, observed string) Finding {
	f := Finding{RuleID: rule, Title: title, Module: module, Severity: severity, Classification: class, Status: status, Observed: observed, Timestamp: time.Now().UTC(), Evidence: map[string]any{}}
	f.Fingerprint = Fingerprint(f)
	return f
}

func Fingerprint(f Finding) string {
	parts := []string{f.RuleID, f.Module, f.Title}
	if target, ok := f.Evidence["target"].(string); ok {
		parts = append(parts, target)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *Report) Normalize() error {
	if r.SchemaVersion == "" {
		r.SchemaVersion = SchemaVersion
	}
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported report schema version %q", r.SchemaVersion)
	}
	if r.Tool == "" {
		r.Tool = "trustfall"
	}
	for i := range r.Findings {
		if r.Findings[i].RuleID == "" || r.Findings[i].Module == "" {
			return fmt.Errorf("finding %d is missing rule_id or module", i)
		}
		r.Findings[i].Evidence = RedactMap(r.Findings[i].Evidence)
		r.Findings[i].Title = RedactString(r.Findings[i].Title)
		r.Findings[i].Observed = RedactString(r.Findings[i].Observed)
		r.Findings[i].Expected = RedactString(r.Findings[i].Expected)
		r.Findings[i].Implications = RedactString(r.Findings[i].Implications)
		r.Findings[i].Remediation = RedactString(r.Findings[i].Remediation)
		r.Findings[i].Fingerprint = Fingerprint(r.Findings[i])
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		if r.Findings[i].RuleID == r.Findings[j].RuleID {
			return r.Findings[i].Fingerprint < r.Findings[j].Fingerprint
		}
		return r.Findings[i].RuleID < r.Findings[j].RuleID
	})
	return nil
}

func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityNote:
		return 1
	default:
		return 0
	}
}
