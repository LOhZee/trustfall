package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
)

type Azure struct {
	Config policy.Azure
	Client *http.Client
}

func (a Azure) Name() string  { return "azure" }
func (a Azure) Enabled() bool { return a.Config.Enabled }

func (a Azure) Assess(ctx context.Context) ([]evidence.Finding, error) {
	client := a.Client
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return fmt.Errorf("redirect refused") }}
	}
	tenant, clientID := os.Getenv("AZURE_TENANT_ID"), os.Getenv("AZURE_CLIENT_ID")
	if !uuidLike(tenant) || !uuidLike(clientID) {
		return []evidence.Finding{azureUnknown("Azure federation was enabled but AZURE_TENANT_ID or AZURE_CLIENT_ID was absent or invalid")}, nil
	}
	assertion, err := githubOIDC(ctx, client, a.Config.Audience)
	if err != nil {
		return []evidence.Finding{azureUnknown("GitHub OIDC token issuance failed: " + evidence.SafeError(err))}, nil
	}
	access, oauthCode, errorCodes, err := exchange(ctx, client, tenant, clientID, a.Config.Scope, assertion)
	assertion = ""
	if err != nil {
		f := azureUnknown("Azure workload identity exchange failed")
		f.Evidence = map[string]any{"provider": "azure", "oauth_error": oauthCode, "oauth_error_codes": errorCodes}
		return []evidence.Finding{f}, nil
	}
	defer func() { access = "" }()
	fed := evidence.NewFinding("TF-CLOUD-AZ-001", "Azure workload identity federation", "cloud", evidence.SeverityLow, evidence.Verified, evidence.StatusInfo, "GitHub OIDC assertion was exchanged for an Azure access token")
	fed.Implications = "This verifies federation for this identity and scope at this time, not access to a resource or all permissions."
	fed.Remediation = "Constrain the federated credential subject and audience and keep Azure role assignments narrowly scoped."
	fed.Evidence = map[string]any{"provider": "azure", "tenant_id": tenant, "client_id": clientID, "scope": a.Config.Scope, "raw_tokens_recorded": false}
	out := []evidence.Finding{fed}
	for _, target := range a.Config.Targets {
		method := strings.ToUpper(target.Method)
		if method == "" {
			method = http.MethodGet
		}
		req, e := http.NewRequestWithContext(ctx, method, target.URL, nil)
		if e != nil {
			return out, e
		}
		req.Header.Set("Authorization", "Bearer "+access)
		req.Header.Set("Accept", "application/json")
		resp, e := client.Do(req)
		if e != nil {
			out = append(out, azureTargetUnknown(target, e))
			continue
		}
		bodyEvidence := summarizeAzureBody(resp, target)
		resp.Body.Close()
		code := resp.Header.Get("x-ms-error-code")
		outcome := "responded"
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			outcome = "allowed"
		} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			outcome = "denied this attempt"
		}
		f := evidence.NewFinding("TF-CLOUD-AZ-002", "Azure read-only operation: "+target.Name, "cloud", evidence.SeverityMedium, evidence.Verified, evidence.StatusInfo, fmt.Sprintf("Azure %s with HTTP %d for the explicitly scoped %s operation", outcome, resp.StatusCode, method))
		f.Implications = "The response verifies only this operation, identity, target and point in time. A denial does not establish absence of other capabilities."
		f.Remediation = "Compare this operation with the expected capability policy and reduce Azure RBAC scope if it exceeds intent."
		f.Evidence = map[string]any{"provider": "azure", "target": target.Name, "method": method, "http_status": resp.StatusCode, "provider_error_code": code, "request_completed": true, "operation_authorized": resp.StatusCode >= 200 && resp.StatusCode < 300, "response_body_recorded": false}
		for key, value := range bodyEvidence {
			f.Evidence[key] = value
		}
		if len(target.ExpectedStatus) > 0 {
			f.Expected = fmt.Sprintf("HTTP status in %v", target.ExpectedStatus)
			if containsInt(target.ExpectedStatus, resp.StatusCode) {
				f.Status = evidence.StatusPass
			} else {
				f.Status = evidence.StatusFail
			}
		}
		out = append(out, f)
	}
	return out, nil
}

func githubOIDC(ctx context.Context, client *http.Client, audience string) (string, error) {
	rawURL, bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if rawURL == "" || bearer == "" {
		return "", fmt.Errorf("OIDC request facilities unavailable")
	}
	u, e := url.Parse(rawURL)
	if e != nil || u.Scheme != "https" || u.User != nil || !isGitHubOIDCHost(u.Hostname()) {
		return "", fmt.Errorf("invalid or untrusted OIDC request URL")
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return "", e
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, e := client.Do(req)
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.CopyN(io.Discard, resp.Body, 4096)
		return "", fmt.Errorf("OIDC endpoint returned HTTP %d", resp.StatusCode)
	}
	var body struct {
		Value string `json:"value"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); e != nil || strings.Count(body.Value, ".") != 2 {
		return "", fmt.Errorf("invalid OIDC response")
	}
	return body.Value, nil
}

func isGitHubOIDCHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "actions.githubusercontent.com" || strings.HasSuffix(host, ".actions.githubusercontent.com")
}
func exchange(ctx context.Context, client *http.Client, tenant, clientID, scope, assertion string) (string, string, []int, error) {
	endpoint := "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token"
	form := url.Values{"client_id": {clientID}, "scope": {scope}, "grant_type": {"client_credentials"}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if e != nil {
		return "", "", nil, e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, e := client.Do(req)
	if e != nil {
		return "", "", nil, e
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		ErrorCodes  []int  `json:"error_codes"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); e != nil {
		return "", "", nil, fmt.Errorf("decode Azure token response")
	}
	if resp.StatusCode != 200 || body.AccessToken == "" {
		return "", body.Error, body.ErrorCodes, fmt.Errorf("Azure token endpoint returned HTTP %d", resp.StatusCode)
	}
	return body.AccessToken, "", nil, nil
}
func azureUnknown(msg string) evidence.Finding {
	f := evidence.NewFinding("TF-CLOUD-AZ-001", "Azure workload identity federation", "cloud", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, msg)
	f.Implications = "The failed operation does not prove that Azure access is absent."
	f.Remediation = "Check explicit OIDC permission, federated subject/audience, identifiers and network access."
	return f
}
func azureTargetUnknown(t policy.AzureTarget, err error) evidence.Finding {
	f := evidence.NewFinding("TF-CLOUD-AZ-002", "Azure read-only operation: "+t.Name, "cloud", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, "Azure request failed: "+evidence.SafeError(err))
	f.Implications = "Failure does not prove the identity lacks this or other capabilities."
	f.Remediation = "Review Azure response telemetry and retry only within the authorised scope."
	f.Evidence = map[string]any{"provider": "azure", "target": t.Name, "response_body_recorded": false}
	return f
}
func uuidLike(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if _, e := strconv.ParseUint(string(c), 16, 4); e != nil {
			return false
		}
	}
	return true
}
func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func summarizeAzureBody(resp *http.Response, target policy.AzureTarget) map[string]any {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !strings.Contains(strings.ToLower(target.URL), "/providers/microsoft.authorization/roleassignments") {
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return nil
	}
	var list struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&list); err != nil {
		return map[string]any{"role_assignment_summary": "response could not be summarized"}
	}
	return map[string]any{"returned_role_assignment_count": len(list.Value), "role_assignment_fields_recorded": false}
}
