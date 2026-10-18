package cloud

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
	"github.com/LOhZee/trustfall/internal/reporting"
)

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func assertNoSecretsInReportFormats(t *testing.T, findings []evidence.Finding, secrets ...string) {
	t.Helper()
	report := evidence.Report{Run: evidence.RunMetadata{Profile: "test", ToolVersion: "test"}, Findings: findings}
	writers := map[string]func(io.Writer) error{
		"json":    func(w io.Writer) error { return reporting.WriteJSON(w, report) },
		"sarif":   func(w io.Writer) error { return reporting.WriteSARIF(w, report) },
		"summary": func(w io.Writer) error { return reporting.WriteSummary(w, report, nil) },
	}
	for name, write := range writers {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			if err := write(&output); err != nil {
				t.Fatal(err)
			}
			for _, secret := range secrets {
				if strings.Contains(output.String(), secret) {
					t.Fatalf("%s report leaked synthetic secret %q", name, secret)
				}
			}
		})
	}
}

func TestCloudClientDisablesAmbientProxyAndRefusesRedirects(t *testing.T) {
	client := cloudHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("credential-bearing client can use environment proxy: %#v", client.Transport)
	}
	client.Transport = azureRoundTrip(func(r *http.Request) (*http.Response, error) {
		result := response(http.StatusFound, "")
		result.Header.Set("Location", "https://attacker.example/")
		result.Request = r
		return result, nil
	})
	req, _ := http.NewRequest(http.MethodGet, "https://sts.amazonaws.com/", nil)
	_, err := client.Do(req)
	if cloudTransportOutcome(err) != "redirect_refused" {
		t.Fatalf("redirect outcome = %q (%v)", cloudTransportOutcome(err), err)
	}
}

func TestProviderExchangeFailureClassification(t *testing.T) {
	const assertion = "header.synthetic-assertion.signature"
	const secret = "SYNTHETIC-PROVIDER-BODY-SECRET"
	tests := []struct {
		name         string
		provider     string
		status       int
		body         string
		transportErr error
		redirect     bool
		wantOutcome  string
		wantCode     string
	}{
		{"AWS invalid audience", "aws", 400, `<ErrorResponse><Error><Code>InvalidIdentityToken</Code><Message>` + secret + `</Message></Error></ErrorResponse>`, nil, false, "credential_exchange_rejected", "InvalidIdentityToken"},
		{"AWS expired assertion", "aws", 400, `<ErrorResponse><Error><Code>ExpiredToken</Code><Message>` + secret + `</Message></Error></ErrorResponse>`, nil, false, "credential_exchange_rejected", "ExpiredToken"},
		{"AWS malformed", "aws", 200, `<not-credentials>` + secret, nil, false, "malformed_token_response", ""},
		{"AWS rate limit", "aws", 429, `<ErrorResponse><Error><Code>Throttling</Code></Error></ErrorResponse>`, nil, false, "rate_limited", "Throttling"},
		{"AWS network", "aws", 0, "", errors.New(secret), false, "transport_error", ""},
		{"AWS redirect", "aws", 302, "", nil, true, "redirect_refused", ""},
		{"Azure invalid audience", "azure", 400, `{"error":"invalid_client","error_description":"` + secret + `"}`, nil, false, "credential_exchange_rejected", "invalid_client"},
		{"Azure expired assertion", "azure", 401, `{"error":"invalid_grant","error_description":"` + secret + `"}`, nil, false, "credential_exchange_rejected", "invalid_grant"},
		{"Azure malformed", "azure", 200, `{"access_token":`, nil, false, "malformed_token_response", ""},
		{"Azure rate limit", "azure", 429, `{"error":"temporarily_unavailable"}`, nil, false, "rate_limited", "temporarily_unavailable"},
		{"Azure network", "azure", 0, "", errors.New(secret), false, "transport_error", ""},
		{"Azure redirect", "azure", 302, "", nil, true, "redirect_refused", ""},
		{"GCP invalid audience", "gcp", 400, `{"error":"invalid_target","error_description":"` + secret + `"}`, nil, false, "credential_exchange_rejected", "invalid_target"},
		{"GCP expired assertion", "gcp", 400, `{"error":"invalid_grant","error_description":"` + secret + `"}`, nil, false, "credential_exchange_rejected", "invalid_grant"},
		{"GCP malformed", "gcp", 200, `{"access_token":`, nil, false, "malformed_token_response", ""},
		{"GCP rate limit", "gcp", 429, `{"error":"rate_limit_exceeded"}`, nil, false, "rate_limited", "rate_limit_exceeded"},
		{"GCP network", "gcp", 0, "", errors.New(secret), false, "transport_error", ""},
		{"GCP redirect", "gcp", 302, "", nil, true, "redirect_refused", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := cloudHTTPClient()
			client.Transport = azureRoundTrip(func(r *http.Request) (*http.Response, error) {
				if test.transportErr != nil {
					return nil, test.transportErr
				}
				result := response(test.status, test.body)
				result.Request = r
				if test.redirect {
					result.Header.Set("Location", "https://attacker.example/credential")
				}
				return result, nil
			})
			var gotCode string
			var err error
			switch test.provider {
			case "aws":
				_, _, gotCode, err = exchangeAWS(context.Background(), client, policy.AWS{RoleARN: "arn:aws:iam::123456789012:role/trustfall", SessionName: "trustfall"}, assertion)
			case "azure":
				_, gotCode, _, err = exchange(context.Background(), client, "00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002", "https://management.azure.com/.default", assertion)
			case "gcp":
				_, _, gotCode, err = exchangeGCP(context.Background(), client, policy.GCP{WorkloadIdentityProvider: "projects/123/locations/global/workloadIdentityPools/p/providers/x", Scope: "https://www.googleapis.com/auth/cloud-platform"}, assertion)
			}
			if err == nil || cloudTransportOutcome(err) != test.wantOutcome || sanitizeProviderCode(gotCode) != test.wantCode {
				t.Fatalf("outcome=%q code=%q err=%v", cloudTransportOutcome(err), gotCode, err)
			}
			finding := evidence.NewFinding("TF-TEST", "provider exchange", "cloud", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, "provider exchange did not complete")
			finding.Evidence = map[string]any{"provider_error_code": sanitizeProviderCode(gotCode), "outcome": cloudTransportOutcome(err), "response_body_recorded": false}
			assertNoSecretsInReportFormats(t, []evidence.Finding{finding}, secret, assertion)
		})
	}
}

func TestCloudTargetUnexpectedResponsesRemainOperationSpecific(t *testing.T) {
	tests := []struct {
		status     int
		expected   []int
		wantStatus evidence.Status
		authorized bool
	}{
		{http.StatusForbidden, []int{http.StatusOK}, evidence.StatusFail, false},
		{http.StatusTeapot, []int{http.StatusOK}, evidence.StatusFail, false},
		{http.StatusTeapot, nil, evidence.StatusInfo, false},
		{http.StatusOK, []int{http.StatusOK}, evidence.StatusPass, true},
	}
	for _, test := range tests {
		finding := cloudTargetFinding("TF-CLOUD-TEST", "Cloud", "target", http.MethodGet, test.status, test.expected, "", map[string]any{"provider": "test"})
		if finding.Status != test.wantStatus || finding.Evidence["operation_authorized"] != test.authorized || finding.Classification != evidence.Verified {
			t.Fatalf("status %d produced %+v", test.status, finding)
		}
	}
}

func TestProviderTransportErrorsCannotEnterAnyReportFormat(t *testing.T) {
	const secret = "SYNTHETIC-TRANSPORT-ERROR-SECRET"
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://vstoken.actions.githubusercontent.com/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")
	client := &http.Client{Transport: azureRoundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New(secret) })}
	providers := []Provider{
		AWS{Client: client, Config: policy.AWS{Enabled: true, Audience: "sts.amazonaws.com"}},
		Azure{Client: client, Config: policy.Azure{Enabled: true, Audience: "api://AzureADTokenExchange"}},
		GCP{Client: client, Config: policy.GCP{Enabled: true, Audience: "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/p/providers/x"}},
	}
	t.Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000001")
	t.Setenv("AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000002")
	for _, provider := range providers {
		t.Run(provider.Name(), func(t *testing.T) {
			findings, err := provider.Assess(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			assertNoSecretsInReportFormats(t, findings, secret, "request-token")
		})
	}
}
