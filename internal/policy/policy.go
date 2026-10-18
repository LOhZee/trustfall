package policy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/LOhZee/trustfall/internal/evidence"
	"gopkg.in/yaml.v3"
)

type Policy struct {
	Version      string                 `yaml:"version" json:"version"`
	Mode         string                 `yaml:"mode" json:"mode"`
	FailOn       evidence.Severity      `yaml:"fail_on" json:"fail_on"`
	DenyRules    []string               `yaml:"deny_rules" json:"deny_rules,omitempty"`
	Expectations map[string]Expectation `yaml:"expectations" json:"expectations,omitempty"`
	Identity     Identity               `yaml:"identity" json:"identity"`
	Network      Network                `yaml:"network" json:"network"`
	Cloud        Cloud                  `yaml:"cloud" json:"cloud"`
}

type Expectation struct {
	Status    evidence.Status `yaml:"status" json:"status"`
	Condition string          `yaml:"condition" json:"condition"`
}
type Identity struct {
	RequestOIDC bool   `yaml:"request_oidc" json:"request_oidc"`
	Audience    string `yaml:"audience" json:"audience"`
}
type Network struct {
	Targets     []NetworkTarget `yaml:"targets" json:"targets"`
	Metadata    Metadata        `yaml:"metadata" json:"metadata"`
	Concurrency int             `yaml:"concurrency" json:"concurrency"`
}
type NetworkTarget struct {
	Name            string `yaml:"name" json:"name"`
	Type            string `yaml:"type" json:"type"`
	Address         string `yaml:"address" json:"address"`
	ExpectReachable *bool  `yaml:"expect_reachable" json:"expect_reachable,omitempty"`
}
type Metadata struct {
	Enabled   bool     `yaml:"enabled" json:"enabled"`
	Providers []string `yaml:"providers" json:"providers"`
}
type Cloud struct {
	AWS   AWS   `yaml:"aws" json:"aws"`
	Azure Azure `yaml:"azure" json:"azure"`
	GCP   GCP   `yaml:"gcp" json:"gcp"`
}
type AWS struct {
	Enabled     bool        `yaml:"enabled" json:"enabled"`
	Audience    string      `yaml:"audience" json:"audience"`
	RoleARN     string      `yaml:"role_arn" json:"role_arn"`
	SessionName string      `yaml:"session_name" json:"session_name"`
	Targets     []AWSTarget `yaml:"targets" json:"targets"`
}
type AWSTarget struct {
	Name           string `yaml:"name" json:"name"`
	URL            string `yaml:"url" json:"url"`
	Service        string `yaml:"service" json:"service"`
	Region         string `yaml:"region" json:"region"`
	Method         string `yaml:"method" json:"method"`
	ExpectedStatus []int  `yaml:"expected_status" json:"expected_status"`
}
type Azure struct {
	Enabled  bool          `yaml:"enabled" json:"enabled"`
	Audience string        `yaml:"audience" json:"audience"`
	Scope    string        `yaml:"scope" json:"scope"`
	Targets  []AzureTarget `yaml:"targets" json:"targets"`
}
type AzureTarget struct {
	Name           string `yaml:"name" json:"name"`
	URL            string `yaml:"url" json:"url"`
	Method         string `yaml:"method" json:"method"`
	ExpectedStatus []int  `yaml:"expected_status" json:"expected_status"`
}
type GCP struct {
	Enabled                  bool        `yaml:"enabled" json:"enabled"`
	WorkloadIdentityProvider string      `yaml:"workload_identity_provider" json:"workload_identity_provider"`
	Audience                 string      `yaml:"audience" json:"audience"`
	Scope                    string      `yaml:"scope" json:"scope"`
	Targets                  []GCPTarget `yaml:"targets" json:"targets"`
}
type GCPTarget struct {
	Name           string `yaml:"name" json:"name"`
	URL            string `yaml:"url" json:"url"`
	Method         string `yaml:"method" json:"method"`
	ExpectedStatus []int  `yaml:"expected_status" json:"expected_status"`
}

var awsRoleARN = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
var awsSessionName = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{2,64}$`)
var awsEndpointPart = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var gcpProviderName = regexp.MustCompile(`^projects/[0-9]+/locations/global/workloadIdentityPools/[A-Za-z0-9_-]+/providers/[A-Za-z0-9_-]+$`)

func Builtin(profile string) (Policy, error) {
	p := Policy{Version: "1", Mode: "audit", FailOn: evidence.SeverityHigh, Expectations: map[string]Expectation{}, Network: Network{Concurrency: 4}, Identity: Identity{Audience: "trustfall"}}
	switch profile {
	case "baseline":
		return p, nil
	case "hardened":
		p.Mode = "enforce"
		p.Expectations = map[string]Expectation{
			"TF-ID-001":  {Status: evidence.StatusPass, Condition: "process does not run as root"},
			"TF-ISO-001": {Status: evidence.StatusPass, Condition: "effective capability set is empty"},
			"TF-ISO-002": {Status: evidence.StatusPass, Condition: "seccomp is enabled"},
			"TF-ISO-006": {Status: evidence.StatusPass, Condition: "no sensitive host mounts are present"},
			"TF-ISO-007": {Status: evidence.StatusPass, Condition: "no container runtime socket is exposed"},
		}
		return p, nil
	default:
		return Policy{}, fmt.Errorf("unknown profile %q", profile)
	}
}

func Load(path string) (Policy, error) {
	f, e := os.Open(path)
	if e != nil {
		return Policy{}, e
	}
	defer f.Close()
	return Decode(f)
}
func Decode(r io.Reader) (Policy, error) {
	raw, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	if len(raw) > 1<<20 {
		return Policy{}, fmt.Errorf("policy exceeds 1 MiB")
	}
	var p Policy
	d := yaml.NewDecoder(bytes.NewReader(raw))
	d.KnownFields(true)
	if e := d.Decode(&p); e != nil {
		return p, fmt.Errorf("decode policy: %w", e)
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		if e == nil {
			return p, fmt.Errorf("policy must contain exactly one YAML document")
		}
		return p, fmt.Errorf("decode trailing policy document: %w", e)
	}
	if e := p.Validate(); e != nil {
		return p, e
	}
	return p, nil
}

func (p *Policy) Validate() error {
	if p.Version != "1" {
		return fmt.Errorf("policy version must be \"1\"")
	}
	if p.Mode != "audit" && p.Mode != "enforce" {
		return fmt.Errorf("mode must be audit or enforce")
	}
	if p.FailOn == "" {
		p.FailOn = evidence.SeverityHigh
	}
	if evidence.SeverityRank(p.FailOn) == 0 {
		return fmt.Errorf("invalid fail_on severity %q", p.FailOn)
	}
	for rule, expectation := range p.Expectations {
		if !strings.HasPrefix(rule, "TF-") {
			return fmt.Errorf("expectation rule %q is not a TrustFall rule ID", rule)
		}
		switch expectation.Status {
		case evidence.StatusPass, evidence.StatusFail, evidence.StatusInfo, evidence.StatusUnknown, evidence.StatusNotApplicable:
		default:
			return fmt.Errorf("expectation rule %q has invalid status %q", rule, expectation.Status)
		}
		if expectation.Condition == "" {
			return fmt.Errorf("expectation rule %q requires a condition", rule)
		}
	}
	for _, rule := range p.DenyRules {
		if !strings.HasPrefix(rule, "TF-") {
			return fmt.Errorf("deny rule %q is not a TrustFall rule ID", rule)
		}
	}
	if p.Network.Concurrency == 0 {
		p.Network.Concurrency = 4
	}
	if p.Network.Concurrency < 1 || p.Network.Concurrency > 16 {
		return fmt.Errorf("network concurrency must be between 1 and 16")
	}
	seen := map[string]bool{}
	for i, t := range p.Network.Targets {
		if t.Name == "" || seen[t.Name] {
			return fmt.Errorf("network target %d needs a unique name", i)
		}
		seen[t.Name] = true
		if e := validateNetworkTarget(t); e != nil {
			return fmt.Errorf("network target %q: %w", t.Name, e)
		}
	}
	for _, provider := range p.Network.Metadata.Providers {
		if provider != "aws" && provider != "azure" && provider != "gcp" {
			return fmt.Errorf("unsupported metadata provider %q", provider)
		}
	}
	if p.Network.Metadata.Enabled && len(p.Network.Metadata.Providers) == 0 {
		return fmt.Errorf("network.metadata.enabled requires at least one provider")
	}
	if p.Identity.Audience == "" {
		p.Identity.Audience = "trustfall"
	}
	if len(p.Identity.Audience) > 255 {
		return fmt.Errorf("OIDC audience is too long")
	}
	if p.Cloud.AWS.Enabled {
		if p.Cloud.AWS.Audience == "" {
			p.Cloud.AWS.Audience = "sts.amazonaws.com"
		}
		if p.Cloud.AWS.Audience != "sts.amazonaws.com" {
			return fmt.Errorf("cloud.aws.audience must be sts.amazonaws.com")
		}
		if !awsRoleARN.MatchString(p.Cloud.AWS.RoleARN) {
			return fmt.Errorf("cloud.aws.role_arn must be a valid IAM role ARN")
		}
		if p.Cloud.AWS.SessionName == "" {
			p.Cloud.AWS.SessionName = "trustfall"
		}
		if !awsSessionName.MatchString(p.Cloud.AWS.SessionName) {
			return fmt.Errorf("cloud.aws.session_name must be 2-64 AWS-safe characters")
		}
		if len(p.Cloud.AWS.Targets) == 0 {
			return fmt.Errorf("cloud.aws.enabled requires at least one explicitly scoped target")
		}
		seen := map[string]bool{}
		for _, target := range p.Cloud.AWS.Targets {
			if target.Name == "" || seen[target.Name] {
				return fmt.Errorf("AWS targets need unique non-empty names")
			}
			seen[target.Name] = true
			if err := validateAWSTarget(target); err != nil {
				return fmt.Errorf("AWS target %q: %w", target.Name, err)
			}
		}
	}
	if p.Cloud.Azure.Enabled {
		if p.Cloud.Azure.Audience == "" {
			p.Cloud.Azure.Audience = "api://AzureADTokenExchange"
		}
		if p.Cloud.Azure.Scope == "" {
			p.Cloud.Azure.Scope = "https://management.azure.com/.default"
		}
		if p.Cloud.Azure.Scope != "https://management.azure.com/.default" {
			return fmt.Errorf("cloud.azure.scope must be https://management.azure.com/.default")
		}
		if len(p.Cloud.Azure.Targets) == 0 {
			return fmt.Errorf("cloud.azure.enabled requires at least one explicitly scoped target")
		}
		azureNames := map[string]bool{}
		for _, t := range p.Cloud.Azure.Targets {
			if t.Name == "" || azureNames[t.Name] {
				return fmt.Errorf("Azure targets need unique non-empty names")
			}
			azureNames[t.Name] = true
			u, e := url.Parse(t.URL)
			if e != nil || u.Scheme != "https" || !strings.EqualFold(u.Hostname(), "management.azure.com") || u.User != nil || u.Port() != "" || u.Fragment != "" {
				return fmt.Errorf("Azure target %q must be an https://management.azure.com URL without userinfo", t.Name)
			}
			if hasSecretQuery(u) {
				return fmt.Errorf("Azure target %q must not contain credential-like query parameters", t.Name)
			}
			if t.Method != "" && strings.ToUpper(t.Method) != "GET" && strings.ToUpper(t.Method) != "HEAD" {
				return fmt.Errorf("Azure target %q method must be GET or HEAD", t.Name)
			}
			if err := validateExpectedStatuses(t.ExpectedStatus); err != nil {
				return fmt.Errorf("Azure target %q: %w", t.Name, err)
			}
		}
	}
	if p.Cloud.GCP.Enabled {
		if !gcpProviderName.MatchString(p.Cloud.GCP.WorkloadIdentityProvider) {
			return fmt.Errorf("cloud.gcp.workload_identity_provider must be a full provider resource name using a project number")
		}
		expectedAudience := "https://iam.googleapis.com/" + p.Cloud.GCP.WorkloadIdentityProvider
		if p.Cloud.GCP.Audience == "" {
			p.Cloud.GCP.Audience = expectedAudience
		}
		if p.Cloud.GCP.Audience != expectedAudience {
			return fmt.Errorf("cloud.gcp.audience must equal %s", expectedAudience)
		}
		if p.Cloud.GCP.Scope == "" {
			p.Cloud.GCP.Scope = "https://www.googleapis.com/auth/cloud-platform"
		}
		if p.Cloud.GCP.Scope != "https://www.googleapis.com/auth/cloud-platform" {
			return fmt.Errorf("cloud.gcp.scope must be https://www.googleapis.com/auth/cloud-platform")
		}
		if len(p.Cloud.GCP.Targets) == 0 {
			return fmt.Errorf("cloud.gcp.enabled requires at least one explicitly scoped target")
		}
		seen := map[string]bool{}
		for _, target := range p.Cloud.GCP.Targets {
			if target.Name == "" || seen[target.Name] {
				return fmt.Errorf("GCP targets need unique non-empty names")
			}
			seen[target.Name] = true
			if err := validateGCPTarget(target); err != nil {
				return fmt.Errorf("GCP target %q: %w", target.Name, err)
			}
		}
	}
	return nil
}

func validateAWSTarget(target AWSTarget) error {
	service := strings.ToLower(target.Service)
	region := strings.ToLower(target.Region)
	if service != target.Service || region != target.Region || !awsEndpointPart.MatchString(service) || !awsEndpointPart.MatchString(region) {
		return fmt.Errorf("service and region must be explicit AWS identifiers")
	}
	u, err := url.Parse(target.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return fmt.Errorf("URL must use https without userinfo or a fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	regional := service + "." + region + ".amazonaws.com"
	modern := service + "." + region + ".api.aws"
	global := service + ".amazonaws.com"
	if host != regional && host != modern && !((service == "iam" || service == "sts" || service == "s3") && host == global) {
		return fmt.Errorf("host must match the configured AWS service and region")
	}
	if host == global && region != "us-east-1" {
		return fmt.Errorf("global AWS endpoints must use the us-east-1 signing region")
	}
	if hasSecretQuery(u) {
		return fmt.Errorf("URL must not contain credential-like query parameters")
	}
	if target.Method != "" && strings.ToUpper(target.Method) != "GET" && strings.ToUpper(target.Method) != "HEAD" {
		return fmt.Errorf("method must be GET or HEAD")
	}
	query := u.Query()
	for key := range query {
		if strings.EqualFold(key, "Action") && key != "Action" {
			return fmt.Errorf("AWS query parameter Action must use its canonical case")
		}
	}
	if actions := query["Action"]; len(actions) > 1 {
		return fmt.Errorf("AWS query must not contain multiple Action parameters")
	} else if len(actions) == 1 && !allowedAWSQueryAction(service, actions[0]) {
		return fmt.Errorf("query Action %q is not in TrustFall's read-only allowlist for %s", actions[0], service)
	}
	return validateExpectedStatuses(target.ExpectedStatus)
}

func allowedAWSQueryAction(service, action string) bool {
	allowed := map[string]map[string]bool{
		"sts":           {"GetCallerIdentity": true},
		"iam":           {"GetRole": true, "GetRolePolicy": true, "ListAttachedRolePolicies": true, "ListRolePolicies": true, "ListRoleTags": true},
		"ec2":           {"DescribeInstances": true, "DescribeNetworkInterfaces": true, "DescribeRouteTables": true, "DescribeSecurityGroups": true, "DescribeSubnets": true, "DescribeVpcs": true},
		"s3":            {"GetBucketLocation": true, "GetBucketPolicyStatus": true, "GetPublicAccessBlock": true, "ListBuckets": true},
		"organizations": {"DescribeOrganization": true, "ListAccounts": true, "ListRoots": true},
	}
	return allowed[service][action]
}

func validateGCPTarget(target GCPTarget) error {
	u, err := url.Parse(target.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return fmt.Errorf("URL must use https without userinfo or a fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "googleapis.com" || !strings.HasSuffix(host, ".googleapis.com") {
		return fmt.Errorf("host must be a Google API endpoint")
	}
	if hasSecretQuery(u) {
		return fmt.Errorf("URL must not contain credential-like query parameters")
	}
	if target.Method != "" && strings.ToUpper(target.Method) != "GET" && strings.ToUpper(target.Method) != "HEAD" {
		return fmt.Errorf("method must be GET or HEAD")
	}
	return validateExpectedStatuses(target.ExpectedStatus)
}

func validateExpectedStatuses(statuses []int) error {
	seen := map[int]bool{}
	for _, status := range statuses {
		if status < 100 || status > 599 {
			return fmt.Errorf("invalid expected HTTP status %d", status)
		}
		if seen[status] {
			return fmt.Errorf("duplicate expected HTTP status %d", status)
		}
		seen[status] = true
	}
	return nil
}

func validateNetworkTarget(t NetworkTarget) error {
	switch t.Type {
	case "dns":
		if net.ParseIP(t.Address) != nil || strings.ContainsAny(t.Address, "/:@") {
			return fmt.Errorf("DNS address must be a hostname")
		}
	case "tcp":
		host, port, e := net.SplitHostPort(t.Address)
		if e != nil || host == "" || port == "" {
			return fmt.Errorf("TCP address must be host:port")
		}
	case "https":
		u, e := url.Parse(t.Address)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("HTTPS address must be an https URL without userinfo")
		}
		if hasSecretQuery(u) {
			return fmt.Errorf("HTTPS address must not contain credential-like query parameters")
		}
	default:
		return fmt.Errorf("type must be dns, tcp, or https")
	}
	return nil
}

func hasSecretQuery(u *url.URL) bool {
	for key := range u.Query() {
		k := strings.ToLower(key)
		for _, part := range []string{"token", "secret", "password", "signature", "credential", "access_key", "api_key", "apikey"} {
			if k == part || strings.Contains(k, part) {
				return true
			}
		}
	}
	return false
}

type Evaluation struct{ Violations []string }

func (p Policy) Evaluate(r *evidence.Report) Evaluation {
	deny := map[string]bool{}
	for _, id := range p.DenyRules {
		deny[id] = true
	}
	var violations []string
	for i := range r.Findings {
		f := &r.Findings[i]
		if ex, ok := p.Expectations[f.RuleID]; ok {
			f.Expected = ex.Condition
			if f.Status != ex.Status && f.Status != evidence.StatusUnknown && f.Status != evidence.StatusNotApplicable {
				violations = append(violations, fmt.Sprintf("%s expected %s, observed %s", f.RuleID, ex.Status, f.Status))
			}
		}
		if f.Status == evidence.StatusFail && (deny[f.RuleID] || evidence.SeverityRank(f.Severity) >= evidence.SeverityRank(p.FailOn)) {
			violations = append(violations, fmt.Sprintf("%s is %s", f.RuleID, f.Severity))
		}
	}
	sort.Strings(violations)
	violations = compact(violations)
	return Evaluation{Violations: violations}
}
func compact(in []string) []string {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
