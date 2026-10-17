package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/trustfall-ci/trustfall/internal/engine"
	"github.com/trustfall-ci/trustfall/internal/evidence"
)

type Probe struct{ Client *http.Client }

func (Probe) Metadata() engine.Metadata {
	return engine.Metadata{Name: "runtime-identity", Version: "1", Module: "identity", Requirements: []string{"process environment", "user database"}}
}

func (p Probe) Run(ctx context.Context, cfg engine.Config) ([]evidence.Finding, error) {
	uid, gid := os.Geteuid(), os.Getegid()
	usr, err := user.Current()
	username := "unknown"
	if err == nil {
		username = usr.Username
	}
	f := evidence.NewFinding("TF-ID-001", "Effective process identity", "identity", evidence.SeverityNote, evidence.Observed, evidence.StatusInfo, fmt.Sprintf("process runs as uid=%d gid=%d", uid, gid))
	f.Implications = "The process identity determines direct filesystem and kernel-interface access inside the job container."
	f.Remediation = "Use a non-root image user where the workload does not require root."
	f.Evidence = map[string]any{"uid": uid, "gid": gid, "username": username, "root": uid == 0}
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
	claims, err := p.requestClaims(ctx, optionString(cfg.Options, "oidc_audience", "trustfall"))
	if err != nil {
		result = append(result, oidcUnknown("OIDC claim retrieval failed: "+evidence.SafeError(err)))
		return result, nil
	}
	cf := evidence.NewFinding("TF-ID-004", "OIDC identity claims", "identity", evidence.SeverityLow, evidence.Verified, evidence.StatusInfo, "GitHub OIDC token issuance succeeded and selected claims were decoded locally")
	cf.Implications = "This verifies token issuance for the requested audience, not access to any cloud resource."
	cf.Remediation = "Constrain federated trust by repository, ref or protected environment, audience, and workflow identity."
	cf.Evidence = claims
	result = append(result, cf)
	return result, nil
}

func oidcUnknown(msg string) evidence.Finding {
	f := evidence.NewFinding("TF-ID-004", "OIDC identity claims", "identity", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, msg)
	f.Implications = "No conclusion can be drawn about token issuance or downstream federation."
	f.Remediation = "Grant id-token: write only for an authorised test, or leave this result unknown."
	return f
}

func optionString(m map[string]any, key, fallback string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return fallback
}

func (p Probe) requestClaims(ctx context.Context, audience string) (map[string]any, error) {
	endpoint, err := url.Parse(os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"))
	if err != nil {
		return nil, fmt.Errorf("invalid OIDC endpoint")
	}
	q := endpoint.Query()
	q.Set("audience", audience)
	endpoint.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("OIDC redirect refused") }}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.CopyN(io.Discard, resp.Body, 4096)
		return nil, fmt.Errorf("OIDC endpoint returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode OIDC response: %w", err)
	}
	parts := strings.Split(payload.Value, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("OIDC response was not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT claims")
	}
	var all map[string]any
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, fmt.Errorf("parse JWT claims")
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
	selected["claim_handling"] = "decoded locally; raw token discarded"
	return selected, nil
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
