package reporting

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LOhZee/trustfall/internal/evidence"
)

func TestSARIFHasRequiredShapeAndNoFabricatedLocations(t *testing.T) {
	r := evidence.Report{SchemaVersion: evidence.SchemaVersion, Run: evidence.RunMetadata{ToolVersion: "test"}, Findings: []evidence.Finding{{RuleID: "TF-X", Title: "runtime", Module: "m", Severity: evidence.SeverityHigh, Classification: evidence.Observed, Status: evidence.StatusFail, Observed: "condition"}}}
	var b bytes.Buffer
	if err := WriteSARIF(&b, r); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("wrong version: %v", doc["version"])
	}
	if bytes.Contains(b.Bytes(), []byte("\"locations\"")) {
		t.Fatal("runtime result contained fabricated location")
	}
}

func TestJSONNormalizesAndRedactsBeforeSerialization(t *testing.T) {
	r := evidence.Report{Findings: []evidence.Finding{
		{RuleID: "TF-B", Title: "b", Module: "m", Severity: evidence.SeverityLow, Classification: evidence.Verified, Status: evidence.StatusPass, Observed: "ok", Evidence: map[string]any{"access_token": "secret", "url": "https://user:pass@example.com/path"}},
		{RuleID: "TF-A", Title: "a", Module: "m", Severity: evidence.SeverityNote, Classification: evidence.Unknown, Status: evidence.StatusUnknown, Observed: "unknown"},
	}}
	var output bytes.Buffer
	if err := WriteJSON(&output, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "secret") || strings.Contains(output.String(), "user:pass") {
		t.Fatal("secret material reached JSON")
	}
	decoded, err := ReadJSON(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.SchemaVersion != evidence.SchemaVersion || decoded.Tool != "trustfall" || decoded.Findings[0].RuleID != "TF-A" || decoded.Findings[1].Fingerprint == "" {
		t.Fatalf("report was not normalized: %+v", decoded)
	}
}

func TestSARIFLevelsKindsAndFingerprints(t *testing.T) {
	r := evidence.Report{Run: evidence.RunMetadata{ToolVersion: "test"}, Findings: []evidence.Finding{
		{RuleID: "TF-H", Title: "high", Module: "m", Severity: evidence.SeverityHigh, Classification: evidence.Observed, Status: evidence.StatusFail, Observed: "high failure"},
		{RuleID: "TF-M", Title: "medium", Module: "m", Severity: evidence.SeverityMedium, Classification: evidence.Observed, Status: evidence.StatusFail, Observed: "medium failure"},
		{RuleID: "TF-P", Title: "pass", Module: "m", Severity: evidence.SeverityLow, Classification: evidence.Verified, Status: evidence.StatusPass, Observed: "passed"},
	}}
	var output bytes.Buffer
	if err := WriteSARIF(&output, r); err != nil {
		t.Fatal(err)
	}
	var document sarifLog
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	results := document.Runs[0].Results
	if len(results) != 3 || results[0].Level != "error" || results[0].Kind != "fail" || results[1].Level != "warning" || results[2].Kind != "pass" || results[2].Fingerprints["trustfall/v1"] == "" {
		t.Fatalf("unexpected SARIF results: %+v", results)
	}
}

func TestSummaryEscapesTableContentAndSortsViolations(t *testing.T) {
	r := evidence.Report{Run: evidence.RunMetadata{Profile: "custom|profile"}, Findings: []evidence.Finding{{RuleID: "TF-X", Title: "x", Module: "m", Severity: evidence.SeverityHigh, Classification: evidence.Observed, Status: evidence.StatusFail, Observed: "line one|line two\nnext"}}}
	violations := []string{"z|last", "a\nfirst"}
	var output bytes.Buffer
	if err := WriteSummary(&output, r, violations); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "custom\\|profile") || !strings.Contains(text, "line one\\|line two next") || strings.Index(text, "a first") > strings.Index(text, "z\\|last") {
		t.Fatalf("summary was not safely rendered:\n%s", text)
	}
}

func TestReadJSONRejectsUnknownAndTrailingContent(t *testing.T) {
	for _, input := range []string{
		`{"schema_version":"1.0.0","tool":"trustfall","run":{},"findings":[],"unexpected":true}`,
		`{"schema_version":"1.0.0","tool":"trustfall","run":{},"findings":[]} {}`,
	} {
		if _, err := ReadJSON(bytes.NewBufferString(input)); err == nil {
			t.Fatalf("accepted malformed report: %s", input)
		}
	}
}
