package compare

import (
	"fmt"
	"sort"

	"github.com/trustfall-ci/trustfall/internal/evidence"
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
}
type Result struct {
	SchemaVersion  string   `json:"schema_version"`
	BaselineRunID  string   `json:"baseline_run_id"`
	CandidateRunID string   `json:"candidate_run_id"`
	Changes        []Change `json:"changes"`
	Disclaimer     string   `json:"disclaimer"`
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
	result := Result{SchemaVersion: "1.0.0", BaselineRunID: before.Run.ID, CandidateRunID: after.Run.ID, Changes: []Change{}, Disclaimer: "Differences are observational. TrustFall does not attribute causality to a configuration change without supporting evidence."}
	for _, k := range ordered {
		a, aok := left[k]
		b, bok := right[k]
		if aok && bok && a.Status == b.Status && a.Classification == b.Classification && a.Observed == b.Observed && a.Severity == b.Severity {
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
			if b.Status == evidence.StatusFail && (b.Classification == evidence.Observed || b.Classification == evidence.Verified) {
				c.Category = "new_exposure"
				c.Note = "Candidate contains direct evidence of a failing exposure absent from the baseline report; verify equivalent probe coverage before calling it newly created."
			} else {
				c.Category = "new"
				c.Note = "Finding appears only in the candidate report; this is not necessarily a newly created capability."
			}
		case !bok:
			if a.Status == evidence.StatusFail && (a.Classification == evidence.Observed || a.Classification == evidence.Verified) {
				c.Category = "removed_exposure"
				c.Note = "A directly evidenced baseline exposure is absent from the candidate; verify equivalent probe coverage before treating it as removed."
			} else {
				c.Category = "removed"
				c.Note = "Finding appears only in the baseline report; verify that the probe set was equivalent."
			}
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
	return &Snapshot{Status: f.Status, Classification: f.Classification, Severity: f.Severity, Observed: f.Observed}
}
