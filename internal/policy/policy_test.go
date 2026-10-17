package policy

import (
	"strings"
	"testing"

	"github.com/LOhZee/trustfall/internal/evidence"
)

func TestDecodeRejectsUnknownAndUnsafeTargets(t *testing.T) {
	for _, input := range []string{
		"version: '1'\nmode: audit\nunexpected: true\n",
		"version: '1'\nmode: audit\nnetwork:\n  targets:\n    - name: bad\n      type: https\n      address: http://example.com\n",
		"version: '1'\nmode: audit\ncloud:\n  azure:\n    enabled: true\n    targets:\n      - name: bad\n        url: https://evil.example/a\n",
		"version: '1'\nmode: audit\nnetwork:\n  targets:\n    - name: signed\n      type: https\n      address: https://example.com/?token=must-not-be-in-policy\n",
		"version: '1'\nmode: audit\n---\nversion: '1'\nmode: audit\n",
	} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted malformed/unsafe policy:\n%s", input)
		}
	}
}

func TestAuditAndEnforceEvaluation(t *testing.T) {
	p, _ := Builtin("baseline")
	r := evidence.Report{SchemaVersion: evidence.SchemaVersion, Findings: []evidence.Finding{{RuleID: "TF-X", Module: "x", Title: "x", Severity: evidence.SeverityHigh, Status: evidence.StatusFail}}}
	if got := p.Evaluate(&r); len(got.Violations) != 1 {
		t.Fatalf("evaluation must identify violations independently of audit exit behavior: %+v", got)
	}
	p.Mode = "enforce"
	p.FailOn = evidence.SeverityCritical
	if got := p.Evaluate(&r); len(got.Violations) != 0 {
		t.Fatalf("high finding exceeded critical threshold: %+v", got)
	}
}

func TestPermissionUnknownDoesNotBecomeViolation(t *testing.T) {
	p, _ := Builtin("hardened")
	r := evidence.Report{Findings: []evidence.Finding{{RuleID: "TF-ISO-001", Module: "isolation", Title: "caps", Severity: evidence.SeverityHigh, Status: evidence.StatusUnknown, Classification: evidence.Unknown}}}
	if got := p.Evaluate(&r); len(got.Violations) != 0 {
		t.Fatalf("unknown must remain inconclusive, got %+v", got)
	}
}
