package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/LOhZee/trustfall/internal/engine"
	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/probes/userns"
)

type Probe struct{ Client *http.Client }

var errOIDCRedirect = errors.New("OIDC redirect refused")

type oidcOperationError struct{ outcome string }

func (e oidcOperationError) Error() string { return "OIDC operation failed: " + e.outcome }

func (Probe) Metadata() engine.Metadata {
	return engine.Metadata{Name: "runtime-identity", Version: "2", Module: "identity", Requirements: []string{"process environment", "user database"}}
}

func (p Probe) Run(ctx context.Context, cfg engine.Config) ([]evidence.Finding, error) {
	uid, gid := os.Geteuid(), os.Getegid()
	usr, err := user.Current()
	username := "unknown"
	if err == nil {
		username = usr.Username
	}
	uidMap := userns.Inspect("/proc/self/uid_map", nil)
	observedIdentity := fmt.Sprintf("process runs as uid=%d gid=%d", uid, gid)
	if uid == 0 && uidMap.Valid && uidMap.IDZeroMapped && !uidMap.IDZeroMapsToParentZero {
		observedIdentity += " with uid 0 remapped relative to the observed parent user namespace"
	}
	f := evidence.NewFinding("TF-ID-001", "Effective process identity", "identity", evidence.SeverityNote, evidence.Observed, evidence.StatusPass, observedIdentity)
	f.Implications = "The process identity determines direct access inside the job container. The observed map describes only the immediately enclosing user namespace; it does not identify the host's initial user namespace or prove host access."
	f.Remediation = "Use a non-root image user where the workload does not require root."
	f.Evidence = map[string]any{
		"uid":                                uid,
		"gid":                                gid,
		"username":                           username,
		"uid_zero":                           uid == 0,
		"uid_map_available":                  uidMap.Available,
		"uid_map_valid":                      uidMap.Valid,
		"uid_map_entry_count":                uidMap.EntryCount,
		"uid_zero_mapped":                    uidMap.IDZeroMapped,
		"uid_zero_maps_to_parent_uid_zero":   uidMap.IDZeroMapsToParentZero,
		"uid_map_identity_mapping":           uidMap.IdentityMapping,
		"uid_map_error":                      uidMap.ErrorKind,
		"initial_user_namespace_established": false,
	}
	if uid == 0 {
		f.Severity, f.Status = evidence.SeverityMedium, evidence.StatusFail
	}

	metadata := map[string]any{}
	for _, name := range []string{"GITHUB_ACTION", "GITHUB_ACTOR", "GITHUB_EVENT_NAME", "GITHUB_JOB", "GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_OWNER", "GITHUB_RUN_ATTEMPT", "GITHUB_RUN_ID", "GITHUB_RUN_NUMBER", "GITHUB_SHA", "GITHUB_WORKFLOW", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "RUNNER_ARCH", "RUNNER_ENVIRONMENT", "RUNNER_NAME", "RUNNER_OS"} {
		if value, ok := os.LookupEnv(name); ok {
			metadata[strings.ToLower(strings.TrimPrefix(name, "GITHUB_"))] = value
		}
	}
	gm := evidence.NewFinding("TF-ID-002", "GitHub Actions runtime context", "identity", evidence.SeverityNote, evidence.Observed, evidence.StatusInfo, "GitHub-provided non-secret workflow metadata was inspected")
	gm.Implications = "This context identifies the code and workflow associated with the evidence; it does not prove repository trust."
	gm.Remediation = "Retain run provenance with reports and protect workflow definitions."
	gm.Evidence = metadata
	if len(metadata) == 0 {
		gm.Classification, gm.Status, gm.Observed = evidence.Unknown, evidence.StatusUnknown, "GitHub Actions runtime metadata was absent"
	}

	_, requestURL := os.LookupEnv("ACTIONS_ID_TOKEN_REQUEST_URL")
	_, requestToken := os.LookupEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	_, githubToken := os.LookupEnv("GITHUB_TOKEN")
	_, runtimeToken := os.LookupEnv("ACTIONS_RUNTIME_TOKEN")
	_, cacheURL := os.LookupEnv("ACTIONS_CACHE_URL")
	_, resultsURL := os.LookupEnv("ACTIONS_RESULTS_URL")
	fac := evidence.NewFinding("TF-ID-003", "Runtime token facilities", "identity", evidence.SeverityLow, evidence.Observed, evidence.StatusInfo, "credential facilities were checked by environment-variable name only")
	fac.Implications = "Facility presence indicates potential token access, not the token's permissions or successful use."
	fac.Remediation = "Grant GITHUB_TOKEN and id-token permissions only to jobs that require them."
	fac.Evidence = map[string]any{"github_token_variable_present": githubToken, "actions_runtime_token_variable_present": runtimeToken, "actions_cache_url_present": cacheURL, "actions_results_url_present": resultsURL, "oidc_request_url_present": requestURL, "oidc_request_bearer_present": requestToken}

	result := []evidence.Finding{f, gm, fac}
	requestOIDC, _ := cfg.Options["request_oidc"].(bool)
	if !requestOIDC {
		result = append(result, oidcNotTested())
		return result, nil
	}
	if cfg.NoNetwork {
		result = append(result, oidcUnknown("OIDC claim retrieval was requested but network use is disabled"))
		return result, nil
	}
	if !requestURL || !requestToken {
		result = append(result, oidcUnknown("OIDC request facilities are absent; id-token: write may not be granted"))
		return result, nil
	}
	audience := optionString(cfg.Options, "oidc_audience", "trustfall")
	claims, validationErrors, err := p.requestClaims(ctx, audience)
	if err != nil {
		finding := oidcUnknown("OIDC claim retrieval did not complete")
		finding.Evidence = map[string]any{"outcome": oidcOutcome(err), "raw_token_recorded": false}
		result = append(result, finding)
		return result, nil
	}
	cf := evidence.NewFinding("TF-ID-004", "OIDC identity claims", "identity", evidence.SeverityLow, evidence.Verified, evidence.StatusPass, "GitHub OIDC token issuance succeeded and selected claims passed local semantic validation")
	cf.Implications = "This verifies token issuance and locally validates selected claims for the requested audience. TrustFall does not independently verify the JWT signature, and issuance does not prove cloud federation or resource access."
	cf.Remediation = "Constrain federated trust by repository, ref or protected environment, audience, and workflow identity."
	cf.Evidence = claims
	if len(validationErrors) > 0 {
		cf.Severity = evidence.SeverityMedium
		cf.Status = evidence.StatusFail
		cf.Observed = "GitHub OIDC token issuance succeeded, but selected claims failed local semantic validation"
		cf.Evidence["claim_validation_errors"] = validationErrors
	}
	result = append(result, cf)
	return result, nil
}

func oidcNotTested() evidence.Finding {
	f := evidence.NewFinding("TF-ID-004", "OIDC identity claims", "identity", evidence.SeverityNote, evidence.Unknown, evidence.StatusNotApplicable, "OIDC token issuance was not requested in passive assessment mode")
	f.Implications = "The environment-variable check describes whether request facilities are present, but no conclusion can be drawn about token issuance, claim contents, cloud federation, or downstream access."
	f.Remediation = "Use the explicitly OIDC-enabled workflow only for an authorised identity assessment."
	f.Evidence = map[string]any{"token_requested": false, "raw_token_recorded": false}
	return f
}

func oidcUnknown(msg string) evidence.Finding {
	f := evidence.NewFinding("TF-ID-004", "OIDC identity claims", "identity", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, msg)
	f.Implications = "No conclusion can be drawn about token issuance or downstream federation."
	f.Remediation = "Grant id-token: write only for an authorised test, or leave this result unknown."
	f.Evidence = map[string]any{"token_requested": true, "token_issued": false, "raw_token_recorded": false}
	return f
}

func optionString(m map[string]any, key, fallback string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return fallback
}

func (p Probe) requestClaims(ctx context.Context, audience string) (map[string]any, []string, error) {
	endpoint, err := url.Parse(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
	if err != nil || endpoint.Scheme != "https" || endpoint.User != nil || !isGitHubOIDCHost(endpoint.Hostname()) {
		return nil, nil, oidcOperationError{outcome: "invalid_endpoint"}
	}
	q := endpoint.Query()
	q.Set("audience", audience)
	endpoint.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, nil, oidcOperationError{outcome: "request_creation_failed"}
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	client := p.Client
	if client == nil {
		client = oidcHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, oidcOperationError{outcome: oidcTransportOutcome(err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, oidcOperationError{outcome: "issuance_rejected"}
	}
	var payload struct {
		Value string `json:"value"`
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return nil, nil, oidcOperationError{outcome: "malformed_response"}
	}
	defer zeroBytes(body)
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil, oidcOperationError{outcome: "malformed_response"}
	}
	parts := strings.Split(payload.Value, ".")
	if len(parts) != 3 {
		return nil, nil, oidcOperationError{outcome: "malformed_token"}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, oidcOperationError{outcome: "malformed_token"}
	}
	defer zeroBytes(raw)
	var all map[string]any
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, nil, oidcOperationError{outcome: "malformed_token"}
	}
	selected := map[string]any{}
	for _, k := range []string{"iss", "aud", "sub", "repository", "repository_id", "repository_owner", "repository_visibility", "ref", "ref_type", "environment", "workflow", "job_workflow_ref", "runner_environment", "actor", "event_name", "iat", "nbf", "exp"} {
		if v, ok := all[k]; ok {
			selected[k] = v
		}
	}
	if exp, ok := number(all["exp"]); ok {
		if iat, ok := number(all["iat"]); ok {
			selected["lifetime_seconds"] = exp - iat
		}
		selected["expires_at"] = time.Unix(exp, 0).UTC().Format(time.RFC3339)
	}
	selected["signature_verified"] = false
	selected["requested_audience"] = audience
	selected["claim_handling"] = "decoded locally; raw token excluded from evidence and references released after parsing"
	selected["memory_erasure_guaranteed"] = false
	validationErrors := validateClaims(all, audience, time.Now())
	selected["issuer_valid"] = !contains(validationErrors, "issuer is not GitHub Actions")
	selected["audience_valid"] = !contains(validationErrors, "audience does not contain the requested value")
	selected["subject_present"] = !contains(validationErrors, "subject is absent")
	selected["temporal_claims_valid"] = !hasTemporalError(validationErrors)
	selected["raw_token_recorded"] = false
	return selected, validationErrors, nil
}

func oidcHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errOIDCRedirect }}
}

func oidcOutcome(err error) string {
	var operation oidcOperationError
	if errors.As(err, &operation) {
		return operation.outcome
	}
	return oidcTransportOutcome(err)
}

func oidcTransportOutcome(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, errOIDCRedirect):
		return "redirect_refused"
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return "timeout"
	}
	return "transport_error"
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func isGitHubOIDCHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "actions.githubusercontent.com" || strings.HasSuffix(host, ".actions.githubusercontent.com")
}

func validateClaims(claims map[string]any, audience string, now time.Time) []string {
	var problems []string
	if iss, _ := claims["iss"].(string); iss != "https://token.actions.githubusercontent.com" {
		problems = append(problems, "issuer is not GitHub Actions")
	}
	if !audienceContains(claims["aud"], audience) {
		problems = append(problems, "audience does not contain the requested value")
	}
	if sub, _ := claims["sub"].(string); strings.TrimSpace(sub) == "" {
		problems = append(problems, "subject is absent")
	}
	iat, iatOK := number(claims["iat"])
	nbf, nbfOK := number(claims["nbf"])
	exp, expOK := number(claims["exp"])
	if !iatOK || !nbfOK || !expOK {
		problems = append(problems, "temporal claims are incomplete")
		return problems
	}
	nowUnix := now.Unix()
	const skew = int64(60)
	if iat > nowUnix+skew {
		problems = append(problems, "issued-at time is in the future")
	}
	if nbf > nowUnix+skew {
		problems = append(problems, "not-before time is in the future")
	}
	if exp <= nowUnix-skew {
		problems = append(problems, "token is expired")
	}
	if exp <= iat {
		problems = append(problems, "expiration does not follow issued-at time")
	}
	return problems
}

func audienceContains(value any, expected string) bool {
	switch v := value.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func hasTemporalError(values []string) bool {
	for _, value := range values {
		if strings.Contains(value, "time") || strings.Contains(value, "temporal") || strings.Contains(value, "expired") {
			return true
		}
	}
	return false
}

func number(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		x, e := strconv.ParseInt(string(n), 10, 64)
		return x, e == nil
	}
	return 0, false
}
