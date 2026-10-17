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
