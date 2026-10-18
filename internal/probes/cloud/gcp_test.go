package cloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
)

func TestGCPFederationAndAllowedTargetDoNotRecordTokens(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://vstoken.actions.githubusercontent.com/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-request-secret")
	const providerName = "projects/123456789/locations/global/workloadIdentityPools/github/providers/trustfall"
	const audience = "https://iam.googleapis.com/" + providerName
	const accessToken = "gcp-access-token"
	client := &http.Client{Transport: azureRoundTrip(func(r *http.Request) (*http.Response, error) {
		response := &http.Response{Request: r, Header: make(http.Header)}
		switch r.URL.Hostname() {
		case "vstoken.actions.githubusercontent.com":
			if r.URL.Query().Get("audience") != audience {
				t.Fatal("unexpected GCP OIDC audience")
			}
			response.StatusCode = http.StatusOK
			response.Body = io.NopCloser(strings.NewReader(`{"value":"header.claims.signature"}`))
		case "sts.googleapis.com":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			form, err := url.ParseQuery(string(body))
			if err != nil || form.Get("subject_token") == "" || form.Get("audience") != "//iam.googleapis.com/"+providerName {
				t.Fatal("invalid GCP exchange form")
			}
			response.StatusCode = http.StatusOK
			response.Body = io.NopCloser(strings.NewReader(`{"access_token":"` + accessToken + `","expires_in":900,"token_type":"Bearer"}`))
		case "cloudresourcemanager.googleapis.com":
			if r.Header.Get("Authorization") != "Bearer "+accessToken {
				t.Fatal("GCP access token not used for target")
			}
			response.StatusCode = http.StatusOK
			response.Body = io.NopCloser(strings.NewReader(`{"sensitive":"response is never recorded"}`))
		default:
			t.Fatalf("unexpected host %s", r.URL.Hostname())
		}
		return response, nil
	})}
	provider := GCP{Client: client, Config: policy.GCP{
		Enabled: true, WorkloadIdentityProvider: providerName, Audience: audience, Scope: "https://www.googleapis.com/auth/cloud-platform",
		Targets: []policy.GCPTarget{{Name: "project", URL: "https://cloudresourcemanager.googleapis.com/v3/projects/trustfall-test", Method: "GET", ExpectedStatus: []int{200}}},
	}}
	findings, err := provider.Assess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].Classification != evidence.Verified || findings[1].Status != evidence.StatusPass || findings[1].Evidence["operation_authorized"] != true {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{accessToken, "header.claims.signature", "github-request-secret", "response is never recorded"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("credential or response material reached GCP findings")
		}
	}
}

func TestGCPDeniedExchangeIsUnknown(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://vstoken.actions.githubusercontent.com/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-secret")
	client := &http.Client{Transport: azureRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "vstoken.actions.githubusercontent.com" {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"value":"header.claims.signature"}`)), Header: make(http.Header), Request: r}, nil
		}
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(`{"error":"invalid_grant","error_description":"do not record details"}`)), Header: make(http.Header), Request: r}, nil
	})}
	findings, err := (GCP{Client: client, Config: policy.GCP{Enabled: true, WorkloadIdentityProvider: "projects/123/locations/global/workloadIdentityPools/p/providers/x", Audience: "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/x", Scope: "https://www.googleapis.com/auth/cloud-platform"}}).Assess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Classification != evidence.Unknown || findings[0].Status != evidence.StatusUnknown || findings[0].Evidence["provider_error_code"] != "invalid_grant" {
		t.Fatalf("exchange failure was overstated: %+v", findings)
	}
}
