package reporting

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/LOhZee/trustfall/internal/evidence"
)

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties,omitempty"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	Help             sarifMessage   `json:"help"`
	Properties       map[string]any `json:"properties,omitempty"`
}
type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	Level        string            `json:"level"`
	Kind         string            `json:"kind"`
	Message      sarifMessage      `json:"message"`
	Fingerprints map[string]string `json:"partialFingerprints"`
	Properties   map[string]any    `json:"properties,omitempty"`
}
type sarifMessage struct {
	Text string `json:"text"`
}

func WriteSARIF(w io.Writer, r evidence.Report) error {
	if err := r.Normalize(); err != nil {
		return err
	}
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		if _, ok := rules[f.RuleID]; !ok {
			rules[f.RuleID] = sarifRule{ID: f.RuleID, Name: f.Title, ShortDescription: sarifMessage{Text: f.Title}, Help: sarifMessage{Text: f.Implications + " " + f.Remediation}, Properties: map[string]any{"module": f.Module, "default_severity": f.Severity}}
		}
		results = append(results, sarifResult{RuleID: f.RuleID, Level: sarifLevel(f), Kind: sarifKind(f), Message: sarifMessage{Text: f.Observed}, Fingerprints: map[string]string{"trustfall/v1": f.Fingerprint}, Properties: map[string]any{"module": f.Module, "severity": f.Severity, "evidence_classification": f.Classification, "status": f.Status, "expected_condition": f.Expected, "evidence": f.Evidence}})
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ordered := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		ordered = append(ordered, rules[id])
	}
	log := sarifLog{Version: "2.1.0", Schema: "https://json.schemastore.org/sarif-2.1.0.json", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "TrustFall", Version: r.Run.ToolVersion, InformationURI: "https://github.com/LOhZee/trustfall", Rules: ordered}}, Results: results, Properties: map[string]any{"runtime_assessment": true, "source_locations_omitted": true, "report_schema_version": r.SchemaVersion}}}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
func sarifLevel(f evidence.Finding) string {
	if f.Status != evidence.StatusFail {
		return "note"
	}
	switch f.Severity {
	case evidence.SeverityCritical, evidence.SeverityHigh:
		return "error"
	case evidence.SeverityMedium, evidence.SeverityLow:
		return "warning"
	default:
		return "note"
	}
}
func sarifKind(f evidence.Finding) string {
	if f.Status == evidence.StatusFail {
		return "fail"
	}
	if f.Status == evidence.StatusPass {
		return "pass"
	}
	return "informational"
}
