package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LOhZee/trustfall/internal/evidence"
)

func TestExitCodes(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version", "--json"}, &out, &errOut); code != exitOK {
		t.Fatalf("version exit %d: %s", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"validate", "--policy", "missing"}, &out, &errOut); code != exitUsage {
		t.Fatalf("invalid policy exit %d", code)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"compare", "missing-a.json", "missing-b.json"}, &out, &errOut); code != exitOperational {
		t.Fatalf("operational exit %d", code)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"assess", "--profile", "baseline", "--no-network", "--output", filepath.Join(t.TempDir(), "audit.json")}, &out, &errOut); code != exitOK {
		t.Fatalf("audit exit %d: %s", code, errOut.String())
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	contents := "version: '1'\nmode: enforce\nfail_on: critical\nexpectations:\n  TF-ID-001:\n    status: fail\n    condition: process must run as root for this deliberately failing test\n"
	if e := os.WriteFile(path, []byte(contents), 0o600); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	errOut.Reset()
	code := run([]string{"assess", "--profile", "custom", "--policy", path, "--no-network"}, &out, &errOut)
	if code != exitPolicy {
		t.Fatalf("policy exit %d stderr=%s", code, errOut.String())
	}
}

func TestCommandsRejectUnexpectedOrUnsafeArguments(t *testing.T) {
	cases := [][]string{
		{},
		{"unknown"},
		{"version", "extra"},
		{"doctor", "extra"},
		{"compare", "only-one.json"},
		{"validate"},
		{"assess", "extra"},
		{"assess", "--timeout", "0s"},
		{"assess", "--format", "yaml"},
		{"assess", "--output", ""},
		{"assess", "--fail-on", "extreme"},
		{"assess", "--profile", "custom"},
		{"assess", "--profile", "baseline", "--policy", "policy.yaml"},
		{"assess", "--output", "-", "--sarif", "-"},
	}
	for _, args := range cases {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitUsage {
			t.Fatalf("args %v returned %d; stdout=%s stderr=%s", args, code, out.String(), errOut.String())
		}
	}
}

func TestAssessWritesPrivateReportsAndCompareOutput(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	sarifPath := filepath.Join(dir, "report.sarif")
	summaryPath := filepath.Join(dir, "summary.md")
	for _, path := range []string{reportPath, sarifPath, summaryPath} {
		if err := os.WriteFile(path, nil, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	code := run([]string{"assess", "--profile", "baseline", "--no-network", "--output", reportPath, "--sarif", sarifPath, "--summary", summaryPath}, &out, &errOut)
	if code != exitOK {
		t.Fatalf("assess exit %d: %s", code, errOut.String())
	}
	for _, path := range []string{reportPath, sarifPath, summaryPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s permissions are %o, want no group/world access", path, info.Mode().Perm())
		}
	}
	comparisonPath := filepath.Join(dir, "comparison.json")
	out.Reset()
	errOut.Reset()
	if code := run([]string{"compare", "--output", comparisonPath, reportPath, reportPath}, &out, &errOut); code != exitOK {
		t.Fatalf("compare exit %d: %s", code, errOut.String())
	}
	var comparison struct {
		Changes []any `json:"changes"`
	}
	raw, err := os.ReadFile(comparisonPath)
	if err != nil || json.Unmarshal(raw, &comparison) != nil || comparison.Changes == nil || len(comparison.Changes) != 0 {
		t.Fatalf("unexpected comparison output: %s (%v)", raw, err)
	}
}

func TestAWSCloudConfigurationWithoutOIDCRemainsUnknown(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	policyPath := filepath.Join(t.TempDir(), "aws.yaml")
	reportPath := filepath.Join(t.TempDir(), "aws.json")
	contents := `version: "1"
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
`
	if err := os.WriteFile(policyPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"assess", "--profile", "custom", "--policy", policyPath, "--output", reportPath}, &out, &errOut); code != exitOK {
		t.Fatalf("audit exit %d: %s", code, errOut.String())
	}
	raw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report evidence.Report
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, finding := range report.Findings {
		if finding.RuleID == "TF-CLOUD-AWS-001" {
			found = true
			if finding.Classification != evidence.Unknown || finding.Status != evidence.StatusUnknown || !strings.Contains(finding.Observed, "OIDC") {
				t.Fatalf("missing OIDC was overstated: %+v", finding)
			}
		}
	}
	if !found {
		t.Fatal("AWS provider finding was not emitted")
	}
}

func TestOIDCAndTimeoutArgumentsFailClosed(t *testing.T) {
	for _, args := range [][]string{
		{"assess", "--oidc-audience", "trustfall", "--no-network"},
		{"assess", "--timeout", "6m", "--no-network"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitUsage {
			t.Fatalf("args %v returned %d, stderr=%s", args, code, errOut.String())
		}
	}
}
