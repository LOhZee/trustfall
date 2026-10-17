package compare

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/LOhZee/trustfall/internal/evidence"
)

type Change struct {
	Key      string    `json:"key"`
	RuleID   string    `json:"rule_id"`
	Title    string    `json:"title"`
	Category string    `json:"category"`
	Before   *Snapshot `json:"before,omitempty"`
	After    *Snapshot `json:"after,omitempty"`
	Note     string    `json:"note"`
}
type Snapshot struct {
	Status         evidence.Status         `json:"status"`
	Classification evidence.Classification `json:"evidence_classification"`
	Severity       evidence.Severity       `json:"severity"`
	Observed       string                  `json:"observed_condition"`
	Evidence       map[string]any          `json:"evidence,omitempty"`
}
type Result struct {
	SchemaVersion  string            `json:"schema_version"`
	BaselineRunID  string            `json:"baseline_run_id"`
	CandidateRunID string            `json:"candidate_run_id"`
	Context        ComparisonContext `json:"context"`
	Changes        []Change          `json:"changes"`
	Disclaimer     string            `json:"disclaimer"`
}
type ComparisonContext struct {
	AssessmentDifferences []string `json:"assessment_differences"`
	RuntimeDifferences    []string `json:"runtime_differences"`
	RuntimeComparable     bool     `json:"runtime_comparable"`
}

func Reports(before, after evidence.Report) Result {
	left, right := index(before), index(after)
	keys := map[string]bool{}
	for k := range left {
		keys[k] = true
	}
	for k := range right {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	result := Result{SchemaVersion: "1.0.0", BaselineRunID: before.Run.ID, CandidateRunID: after.Run.ID, Context: compareContext(before.Run, after.Run), Changes: []Change{}, Disclaimer: "Differences are observational. TrustFall does not attribute causality to a configuration change without supporting evidence."}
	for _, k := range ordered {
		a, aok := left[k]
		b, bok := right[k]
		if aok && bok && a.Status == b.Status && a.Classification == b.Classification && a.Observed == b.Observed && a.Severity == b.Severity && sameEvidence(a.Evidence, b.Evidence) {
			continue
		}
		c := Change{Key: k}
		if aok {
			c.RuleID, c.Title = a.RuleID, a.Title
			c.Before = snapshot(a)
		}
		if bok {
			c.RuleID, c.Title = b.RuleID, b.Title
			c.After = snapshot(b)
		}
		switch {
		case !aok:
			c.Category = "new_evidence"
			c.Note = "Finding appears only in the candidate report. Missing baseline evidence cannot establish that the property or capability is newly exposed."
		case !bok:
			c.Category = "missing_evidence"
			c.Note = "Finding appears only in the baseline report. Its absence from the candidate is not evidence that the property or capability was removed."
		case a.Probe.Name != b.Probe.Name || a.Probe.Version != b.Probe.Version:
			c.Category = "inconclusive"
			c.Note = "Probe identity or version differs, so the results are not directly comparable."
		case a.Classification == evidence.Unknown || b.Classification == evidence.Unknown || a.Status == evidence.StatusUnknown || b.Status == evidence.StatusUnknown:
			c.Category = "inconclusive"
			c.Note = "At least one side lacks conclusive evidence."
		case a.Status != evidence.StatusFail && b.Status == evidence.StatusFail:
			c.Category = "regression"
			c.Note = "Candidate evidence records a failing condition that baseline evidence did not."
		case a.Status == evidence.StatusFail && b.Status != evidence.StatusFail:
			c.Category = "improvement"
			c.Note = "The previously failing condition was not observed as failing in the candidate."
		default:
			c.Category = "changed"
			c.Note = "A runtime property changed; no causal configuration claim is made."
		}
		result.Changes = append(result.Changes, c)
	}
	return result
}

func compareContext(before, after evidence.RunMetadata) ComparisonContext {
	c := ComparisonContext{AssessmentDifferences: []string{}, RuntimeDifferences: []string{}}
	if before.Profile != after.Profile {
		c.AssessmentDifferences = append(c.AssessmentDifferences, fmt.Sprintf("profile: %q -> %q", before.Profile, after.Profile))
	}
	if before.PolicyMode != after.PolicyMode {
		c.AssessmentDifferences = append(c.AssessmentDifferences, fmt.Sprintf("policy_mode: %q -> %q", before.PolicyMode, after.PolicyMode))
	}
	if before.NetworkDenied != after.NetworkDenied {
		c.AssessmentDifferences = append(c.AssessmentDifferences, fmt.Sprintf("network_denied: %t -> %t", before.NetworkDenied, after.NetworkDenied))
	}
	if before.ToolVersion != after.ToolVersion {
		c.AssessmentDifferences = append(c.AssessmentDifferences, fmt.Sprintf("tool_version: %q -> %q", before.ToolVersion, after.ToolVersion))
	}
	runtimeFields := []struct{ name, before, after string }{
		{"repository", before.Runtime.Repository, after.Runtime.Repository},
		{"workflow_ref", before.Runtime.WorkflowRef, after.Runtime.WorkflowRef},
		{"runner_environment", before.Runtime.RunnerEnvironment, after.Runtime.RunnerEnvironment},
		{"runner_os", before.Runtime.RunnerOS, after.Runtime.RunnerOS},
		{"runner_arch", before.Runtime.RunnerArch, after.Runtime.RunnerArch},
		{"container_image", before.Runtime.ContainerImage, after.Runtime.ContainerImage},
	}
	complete := true
	for _, field := range runtimeFields {
		if field.before == "" || field.after == "" {
			complete = false
		}
		if field.before != field.after {
			c.RuntimeDifferences = append(c.RuntimeDifferences, fmt.Sprintf("%s: %q -> %q", field.name, field.before, field.after))
		}
	}
	c.RuntimeComparable = complete && len(c.RuntimeDifferences) == 0
	if !complete {
		c.RuntimeDifferences = append(c.RuntimeDifferences, "runtime context is incomplete on one or both reports")
	}
	return c
}
func index(r evidence.Report) map[string]evidence.Finding {
	m := map[string]evidence.Finding{}
	for _, f := range r.Findings {
		k := f.RuleID + "|" + f.Title
		if target, ok := f.Evidence["target"].(string); ok {
			k += "|" + target
		}
		if _, exists := m[k]; exists {
			k = fmt.Sprintf("%s|%s", k, f.Fingerprint)
		}
		m[k] = f
	}
	return m
}
func snapshot(f evidence.Finding) *Snapshot {
	return &Snapshot{Status: f.Status, Classification: f.Classification, Severity: f.Severity, Observed: f.Observed, Evidence: f.Evidence}
}

func sameEvidence(a, b map[string]any) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	return errLeft == nil && errRight == nil && string(left) == string(right)
}
