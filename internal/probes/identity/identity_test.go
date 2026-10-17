package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LOhZee/trustfall/internal/engine"
	"github.com/LOhZee/trustfall/internal/evidence"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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

func TestPassiveModeMakesOIDCNotTestedVisible(t *testing.T) {
	findings, err := (Probe{}).Run(context.Background(), engine.Config{Options: map[string]any{"request_oidc": false}})
	if err != nil {
		t.Fatal(err)
	}
	last := findings[len(findings)-1]
	if last.RuleID != "TF-ID-004" || last.Classification != evidence.Unknown || last.Status != evidence.StatusNotApplicable {
		t.Fatalf("unexpected passive OIDC finding: %+v", last)
	}
}

func TestOIDCClaimsAreValidatedWithoutTokenRetention(t *testing.T) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "trustfall", "sub": "repo:LOhZee/trustfall:ref:refs/heads/main",
		"repository": "LOhZee/trustfall", "ref": "refs/heads/main", "iat": now.Unix() - 10, "nbf": now.Unix() - 10, "exp": now.Unix() + 300,
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jwt := "header." + base64.RawURLEncoding.EncodeToString(raw) + ".signature"
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://vstoken.actions.githubusercontent.com/example?api-version=2.0")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-secret")
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("audience") != "trustfall" || r.Header.Get("Authorization") != "Bearer request-secret" {
			t.Fatalf("unexpected OIDC request")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"value":"` + jwt + `"}`)), Request: r}, nil
	})}
	findings, err := (Probe{Client: client}).Run(context.Background(), engine.Config{Options: map[string]any{"request_oidc": true, "oidc_audience": "trustfall"}})
	if err != nil {
		t.Fatal(err)
	}
	got := findings[len(findings)-1]
	if got.Classification != evidence.Verified || got.Status != evidence.StatusPass {
		t.Fatalf("unexpected OIDC finding: %+v", got)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), jwt) || strings.Contains(string(encoded), "request-secret") {
		t.Fatalf("token material retained: %s", encoded)
	}
}

func TestOIDCInvalidClaimsFailOnlyClaimExpectation(t *testing.T) {
	now := time.Now().UTC()
	problems := validateClaims(map[string]any{"iss": "https://example.invalid", "aud": "wrong", "sub": "", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Unix() - 300}, "trustfall", now)
	if len(problems) < 4 {
		t.Fatalf("expected issuer, audience, subject, and temporal failures: %v", problems)
	}
}

func TestOIDCEndpointHostIsConstrained(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://attacker.example/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-secret")
	findings, err := (Probe{}).Run(context.Background(), engine.Config{Options: map[string]any{"request_oidc": true}})
	if err != nil {
		t.Fatal(err)
	}
	last := findings[len(findings)-1]
	if last.Classification != evidence.Unknown || !strings.Contains(last.Observed, "untrusted OIDC endpoint") {
		t.Fatalf("unexpected result: %+v", last)
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
