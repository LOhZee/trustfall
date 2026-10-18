package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
)

type GCP struct {
	Config policy.GCP
	Client *http.Client
}

func (g GCP) Name() string  { return "gcp" }
func (g GCP) Enabled() bool { return g.Config.Enabled }

func (g GCP) Assess(ctx context.Context) ([]evidence.Finding, error) {
	client := g.Client
	if client == nil {
		client = cloudHTTPClient()
	}
	assertion, err := githubOIDC(ctx, client, g.Config.Audience)
	if err != nil {
		f := gcpUnknown("GitHub OIDC token issuance did not complete")
		f.Evidence = map[string]any{"provider": "gcp", "outcome": cloudTransportOutcome(err), "raw_tokens_recorded": false}
		return []evidence.Finding{f}, nil
	}
	access, expiresIn, providerCode, err := exchangeGCP(ctx, client, g.Config, assertion)
	if err != nil {
		f := gcpUnknown("GCP workload identity exchange failed")
		f.Evidence = map[string]any{"provider": "gcp", "provider_error_code": sanitizeProviderCode(providerCode), "outcome": cloudTransportOutcome(err), "raw_tokens_recorded": false}
		return []evidence.Finding{f}, nil
	}
	fed := evidence.NewFinding("TF-CLOUD-GCP-001", "GCP workload identity federation", "cloud", evidence.SeverityLow, evidence.Verified, evidence.StatusInfo, "GitHub OIDC assertion was exchanged for a GCP federated access token")
	fed.Implications = "This verifies federation for this workload identity provider and scope at this time, not access to a resource or all GCP permissions."
	fed.Remediation = "Constrain workload identity provider attributes and keep IAM bindings narrowly scoped."
	fed.Evidence = map[string]any{"provider": "gcp", "workload_identity_provider": g.Config.WorkloadIdentityProvider, "audience": g.Config.Audience, "scope": g.Config.Scope, "expires_in_seconds": expiresIn, "raw_tokens_recorded": false}
	out := []evidence.Finding{fed}

	for _, target := range g.Config.Targets {
		method := strings.ToUpper(target.Method)
		if method == "" {
			method = http.MethodGet
		}
		req, reqErr := http.NewRequestWithContext(ctx, method, target.URL, nil)
		if reqErr != nil {
			return out, reqErr
		}
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("Accept", "application/json")
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			out = append(out, gcpTargetUnknown(target, cloudTransportOutcome(requestErr)))
			continue
		}
		resp.Body.Close()
		out = append(out, cloudTargetFinding("TF-CLOUD-GCP-002", "GCP", target.Name, method, resp.StatusCode, target.ExpectedStatus, "", map[string]any{"provider": "gcp"}))
	}
	return out, nil
}

func exchangeGCP(ctx context.Context, client *http.Client, config policy.GCP, assertion string) (string, int, string, error) {
	form := url.Values{
		"audience":             {"//iam.googleapis.com/" + config.WorkloadIdentityProvider},
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":                {config.Scope},
		"subject_token":        {assertion},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:id_token"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.googleapis.com/v1/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, "", cloudError("request_creation_failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", fmt.Errorf("GCP exchange transport: %w", classifyCloudError(err))
	}
	defer resp.Body.Close()
	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := decodeBoundedJSON(resp.Body, 1<<20, &result); err != nil {
		return "", 0, "", cloudError("malformed_token_response")
	}
	if resp.StatusCode != http.StatusOK || result.AccessToken == "" {
		outcome := "credential_exchange_rejected"
		if resp.StatusCode == http.StatusTooManyRequests {
			outcome = "rate_limited"
		}
		return "", 0, result.Error, cloudError(outcome)
	}
	return result.AccessToken, result.ExpiresIn, "", nil
}

func gcpUnknown(message string) evidence.Finding {
	f := evidence.NewFinding("TF-CLOUD-GCP-001", "GCP workload identity federation", "cloud", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, message)
	f.Implications = "The failed operation does not prove that GCP access is absent."
	f.Remediation = "Check explicit OIDC permission, provider attribute conditions, audience and network access."
	return f
}

func gcpTargetUnknown(target policy.GCPTarget, outcome string) evidence.Finding {
	f := evidence.NewFinding("TF-CLOUD-GCP-002", "GCP read-only operation: "+target.Name, "cloud", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, "GCP read-only operation did not complete")
	f.Implications = "Failure does not prove the identity lacks this or other GCP capabilities."
	f.Remediation = "Review GCP request telemetry and retry only within the authorised scope."
	f.Evidence = map[string]any{"provider": "gcp", "target": target.Name, "outcome": outcome, "response_body_recorded": false}
	return f
}
