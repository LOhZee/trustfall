package compare

import (
	"github.com/LOhZee/trustfall/internal/evidence"
	"testing"
)

func TestReportsClassifiesRegressionAndInconclusive(t *testing.T) {
	base := evidence.Report{Run: evidence.RunMetadata{ID: "a"}, Findings: []evidence.Finding{{RuleID: "TF-A", Title: "a", Module: "m", Status: evidence.StatusPass, Classification: evidence.Observed}, {RuleID: "TF-B", Title: "b", Module: "m", Status: evidence.StatusUnknown, Classification: evidence.Unknown}}}
	candidate := evidence.Report{Run: evidence.RunMetadata{ID: "b"}, Findings: []evidence.Finding{{RuleID: "TF-A", Title: "a", Module: "m", Status: evidence.StatusFail, Classification: evidence.Observed}, {RuleID: "TF-B", Title: "b", Module: "m", Status: evidence.StatusPass, Classification: evidence.Observed}}}
	r := Reports(base, candidate)
	if len(r.Changes) != 2 {
		t.Fatalf("got %d changes", len(r.Changes))
	}
	if r.Changes[0].Category != "regression" || r.Changes[1].Category != "inconclusive" {
		t.Fatalf("unexpected categories: %+v", r.Changes)
	}
}

func TestReportsDoesNotCallMissingBaselineEvidenceANewExposure(t *testing.T) {
	candidate := evidence.Report{Findings: []evidence.Finding{{RuleID: "TF-X", Title: "socket", Module: "isolation", Status: evidence.StatusFail, Classification: evidence.Observed}}}
	r := Reports(evidence.Report{}, candidate)
	if len(r.Changes) != 1 || r.Changes[0].Category != "new_evidence" {
		t.Fatalf("unexpected comparison: %+v", r)
	}
}

func TestReportsExposesAssessmentAndRuntimeDifferences(t *testing.T) {
	base := evidence.Report{Run: evidence.RunMetadata{Profile: "baseline", NetworkDenied: false, ToolVersion: "v1", Runtime: evidence.RuntimeContext{Repository: "LOhZee/trustfall", WorkflowRef: "workflow@a", RunnerEnvironment: "github-hosted", RunnerOS: "Linux", RunnerArch: "X64", ContainerImage: "image@one"}}}
	candidate := evidence.Report{Run: evidence.RunMetadata{Profile: "hardened", NetworkDenied: true, ToolVersion: "v1", Runtime: evidence.RuntimeContext{Repository: "LOhZee/trustfall", WorkflowRef: "workflow@a", RunnerEnvironment: "github-hosted", RunnerOS: "Linux", RunnerArch: "X64", ContainerImage: "image@two"}}}
	r := Reports(base, candidate)
	if len(r.Context.AssessmentDifferences) != 2 || len(r.Context.RuntimeDifferences) != 1 || r.Context.RuntimeComparable {
		t.Fatalf("comparison context omitted material differences: %+v", r.Context)
	}
}

func TestReportsComparesSupportingEvidence(t *testing.T) {
	baseFinding := evidence.Finding{RuleID: "TF-ISO-001", Title: "caps", Module: "isolation", Status: evidence.StatusPass, Classification: evidence.Observed, Evidence: map[string]any{"bounding": []string{"CAP_CHOWN"}}}
	candidateFinding := baseFinding
	candidateFinding.Evidence = map[string]any{"bounding": []string{}}
	r := Reports(evidence.Report{Findings: []evidence.Finding{baseFinding}}, evidence.Report{Findings: []evidence.Finding{candidateFinding}})
	if len(r.Changes) != 1 || r.Changes[0].Category != "changed" {
		t.Fatalf("supporting evidence change was lost: %+v", r.Changes)
	}
}

func TestReportsUsesEmptyArrayForNoChanges(t *testing.T) {
	r := Reports(evidence.Report{}, evidence.Report{})
	if r.Changes == nil {
		t.Fatal("changes must serialize as an empty array, not null")
	}
}
