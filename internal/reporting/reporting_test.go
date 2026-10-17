package reporting

import (
	"bytes"
	"encoding/json"
	"github.com/trustfall-ci/trustfall/internal/evidence"
	"testing"
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
