package identity

import (
	"context"
	"encoding/json"
	"github.com/trustfall-ci/trustfall/internal/engine"
	"github.com/trustfall-ci/trustfall/internal/evidence"
	"strings"
	"testing"
)

func TestAbsentOIDCIsUnknown(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	findings, err := (Probe{}).Run(context.Background(), engine.Config{Options: map[string]any{"request_oidc": true}})
	if err != nil {
		t.Fatal(err)
	}
	last := findings[len(findings)-1]
	if last.RuleID != "TF-ID-004" || last.Classification != evidence.Unknown {
		t.Fatalf("unexpected OIDC finding: %+v", last)
	}
}

func TestTokenValuesNeverEnterFindings(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "github-super-secret")
	t.Setenv("ACTIONS_RUNTIME_TOKEN", "runtime-super-secret")
	findings, err := (Probe{}).Run(context.Background(), engine.Config{Options: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(findings)
	if strings.Contains(string(raw), "super-secret") {
		t.Fatalf("token value leaked: %s", raw)
	}
}
