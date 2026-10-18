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
		"version: '1'\nmode: audit\ncloud:\n  aws:\n    enabled: true\n    role_arn: arn:aws:iam::123456789012:role/test\n    targets:\n      - name: destructive\n        service: ec2\n        region: us-east-1\n        url: https://ec2.us-east-1.amazonaws.com/?Action=TerminateInstances\n",
		"version: '1'\nmode: audit\ncloud:\n  aws:\n    enabled: true\n    role_arn: arn:aws:iam::123456789012:role/test\n    targets:\n      - name: wrong-host\n        service: sts\n        region: us-east-1\n        url: https://example.com/?Action=GetCallerIdentity\n",
		"version: '1'\nmode: audit\ncloud:\n  aws:\n    enabled: true\n    role_arn: arn:aws:iam::123456789012:role/test\n    targets:\n      - name: ambiguous\n        service: sts\n        region: us-east-1\n        url: https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Action=AssumeRole\n",
		"version: '1'\nmode: audit\ncloud:\n  aws:\n    enabled: true\n    role_arn: arn:aws:iam::123456789012:role/test\n    targets:\n      - name: signed-url\n        service: s3\n        region: us-east-1\n        url: https://s3.amazonaws.com/example?X-Amz-Signature=must-not-enter-policy\n",
		"version: '1'\nmode: audit\ncloud:\n  gcp:\n    enabled: true\n    audience: //iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/x\n    targets:\n      - name: bad\n        url: https://evil.example/v1/projects/x\n",
		"version: '1'\nmode: audit\nnetwork:\n  targets:\n    - name: signed\n      type: https\n      address: https://example.com/?token=must-not-be-in-policy\n",
		"version: '1'\nmode: audit\n---\nversion: '1'\nmode: audit\n",
	} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted malformed/unsafe policy:\n%s", input)
		}
	}
}

func TestDecodeAcceptsBoundedAWSAndGCPPolicies(t *testing.T) {
	input := `version: "1"
mode: audit
cloud:
  aws:
    enabled: true
    role_arn: arn:aws:iam::123456789012:role/trustfall
    targets:
      - name: identity
        service: sts
        region: us-east-1
        url: https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15
        expected_status: [200]
  gcp:
    enabled: true
    workload_identity_provider: projects/123/locations/global/workloadIdentityPools/github/providers/trustfall
    targets:
      - name: project
        url: https://cloudresourcemanager.googleapis.com/v3/projects/example
        expected_status: [200, 403]
`
	p, err := Decode(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if p.Cloud.AWS.Audience != "sts.amazonaws.com" || p.Cloud.AWS.SessionName != "trustfall" || p.Cloud.GCP.Scope != "https://www.googleapis.com/auth/cloud-platform" || p.Cloud.GCP.Audience != "https://iam.googleapis.com/"+p.Cloud.GCP.WorkloadIdentityProvider {
		t.Fatalf("provider defaults not applied: %+v", p.Cloud)
	}
}

func TestNetworkNegativeEvidenceValidation(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"explicit refused", "type: tcp\n      address: example.com:443\n      expect_reachable: false\n      negative_evidence: connection_refused", false},
		{"explicit nxdomain", "type: dns\n      address: missing.example\n      expect_reachable: false\n      negative_evidence: dns_nxdomain", false},
		{"missing expectation", "type: tcp\n      address: example.com:443\n      negative_evidence: connection_refused", true},
		{"positive expectation", "type: tcp\n      address: example.com:443\n      expect_reachable: true\n      negative_evidence: connection_refused", true},
		{"refused DNS", "type: dns\n      address: missing.example\n      expect_reachable: false\n      negative_evidence: connection_refused", true},
		{"ambiguous timeout", "type: tcp\n      address: example.com:443\n      expect_reachable: false\n      negative_evidence: timeout", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := "version: '1'\nmode: audit\nnetwork:\n  targets:\n    - name: target\n      " + test.target + "\n"
			_, err := Decode(strings.NewReader(input))
			if (err != nil) != test.wantErr {
				t.Fatalf("Decode() error = %v, wantErr %t", err, test.wantErr)
			}
		})
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
