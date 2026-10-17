package cloud

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/trustfall-ci/trustfall/internal/evidence"
	"github.com/trustfall-ci/trustfall/internal/policy"
)

type azureRoundTrip func(*http.Request) (*http.Response, error)

func (f azureRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAzureRecordsDeniedOperationWithoutResponseBody(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000001")
	t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000002")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://oidc.example/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-secret")
	client := &http.Client{Transport: azureRoundTrip(func(r *http.Request) (*http.Response, error) {
		response := &http.Response{Request: r, Header: make(http.Header)}
		switch r.URL.Hostname() {
		case "oidc.example":
			response.StatusCode = 200
			response.Body = io.NopCloser(strings.NewReader(`{"value":"header.claims.signature"}`))
		case "login.microsoftonline.com":
			response.StatusCode = 200
			response.Body = io.NopCloser(strings.NewReader(`{"access_token":"azure-secret"}`))
		case "management.azure.com":
			response.StatusCode = 403
			response.Header.Set("x-ms-error-code", "AuthorizationFailed")
			response.Body = io.NopCloser(strings.NewReader(`{"secret":"must-not-appear"}`))
		default:
			t.Fatalf("unexpected host %s", r.URL.Host)
			return nil, nil
		}
		return response, nil
	})}
	a := Azure{Client: client, Config: policy.Azure{Enabled: true, Audience: "api://AzureADTokenExchange", Scope: "https://management.azure.com/.default", Targets: []policy.AzureTarget{{Name: "read", URL: "https://management.azure.com/subscriptions/00000000-0000-0000-0000-000000000000?api-version=2022-12-01", Method: "GET", ExpectedStatus: []int{200}}}}}
	findings, err := a.Assess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings: %+v", findings)
	}
	target := findings[1]
	if target.Classification != evidence.Verified || target.Status != evidence.StatusFail {
		t.Fatalf("target: %+v", target)
	}
	if target.Evidence["provider_error_code"] != "AuthorizationFailed" || target.Evidence["response_body_recorded"] != false {
		t.Fatalf("evidence: %+v", target.Evidence)
	}
}

func TestAzureMissingIdentityIsUnknown(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	findings, err := (Azure{Config: policy.Azure{Enabled: true}}).Assess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Classification != evidence.Unknown {
		t.Fatalf("got %+v", findings[0])
	}
}
