package evidence

import (
	"fmt"
	"strings"
	"testing"
)

func TestRedactMapNeverEmitsSecretsOrJWTs(t *testing.T) {
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzZWNyZXQifQ.signature123"
	in := map[string]any{"access_token": "super-secret", "message": "saw " + jwt, "url": "https://user:password@example.com/path?token=query-secret", "nested": []map[string]any{{"client_secret": "nested-secret"}}}
	out := RedactMap(in)
	encoded := out["access_token"].(string) + out["message"].(string) + out["url"].(string)
	for _, forbidden := range []string{"super-secret", jwt, "password"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("redaction leaked %q: %s", forbidden, encoded)
		}
	}
	if strings.Contains(fmt.Sprint(out), "query-secret") || strings.Contains(fmt.Sprint(out), "nested-secret") {
		t.Fatalf("nested/query redaction failed: %#v", out)
	}
}

func TestFingerprintStableAcrossStatusChanges(t *testing.T) {
	a := NewFinding("TF-X", "Title", "module", SeverityLow, Observed, StatusPass, "one")
	b := a
	b.Status = StatusFail
	b.Classification = Verified
	b.Observed = "two"
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("finding identity changed with assessment result")
	}
}

func TestRedactionPreservesBooleanPresenceMarkers(t *testing.T) {
	out := RedactMap(map[string]any{"github_token_variable_present": true, "access_token": "secret"})
	if out["github_token_variable_present"] != true || out["access_token"] != "[REDACTED]" {
		t.Fatalf("unexpected marker redaction: %#v", out)
	}
}

func TestNestedArrayMapsAreRedacted(t *testing.T) {
	in := map[string]any{"items": []any{map[string]any{"client_secret": "nested-secret", "message": "safe"}}}
	out := RedactMap(in)
	items := out["items"].([]any)
	nested := items[0].(map[string]any)
	if nested["client_secret"] != "[REDACTED]" || nested["message"] != "safe" {
		t.Fatalf("nested redaction failed: %#v", out)
	}
}

func TestNormalizeRejectsInvalidEvidenceSemantics(t *testing.T) {
	base := NewFinding("TF-X", "Title", "identity", SeverityLow, Observed, StatusPass, "condition")
	for name, mutate := range map[string]func(*Finding){
		"severity":       func(f *Finding) { f.Severity = "extreme" },
		"classification": func(f *Finding) { f.Classification = "assumed" },
		"status":         func(f *Finding) { f.Status = "secure" },
	} {
		t.Run(name, func(t *testing.T) {
			finding := base
			mutate(&finding)
			report := Report{SchemaVersion: SchemaVersion, Findings: []Finding{finding}}
			if err := report.Normalize(); err == nil {
				t.Fatalf("accepted invalid %s", name)
			}
		})
	}
}
