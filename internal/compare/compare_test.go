package compare

import (
	"github.com/trustfall-ci/trustfall/internal/evidence"
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

func TestReportsClassifiesNewExposure(t *testing.T) {
	candidate := evidence.Report{Findings: []evidence.Finding{{RuleID: "TF-X", Title: "socket", Module: "isolation", Status: evidence.StatusFail, Classification: evidence.Observed}}}
	r := Reports(evidence.Report{}, candidate)
	if len(r.Changes) != 1 || r.Changes[0].Category != "new_exposure" {
		t.Fatalf("unexpected comparison: %+v", r)
	}
}

func TestReportsUsesEmptyArrayForNoChanges(t *testing.T) {
	r := Reports(evidence.Report{}, evidence.Report{})
	if r.Changes == nil {
		t.Fatal("changes must serialize as an empty array, not null")
	}
}
