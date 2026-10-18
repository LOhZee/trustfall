package cloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
)

type AWS struct {
	Config policy.AWS
	Client *http.Client
	Now    func() time.Time
}

type awsCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

func (a AWS) Name() string  { return "aws" }
func (a AWS) Enabled() bool { return a.Config.Enabled }

func (a AWS) Assess(ctx context.Context) ([]evidence.Finding, error) {
	client := a.Client
	if client == nil {
		client = cloudHTTPClient()
	}
	assertion, err := githubOIDC(ctx, client, a.Config.Audience)
	if err != nil {
		return []evidence.Finding{awsUnknown("GitHub OIDC token issuance failed: " + evidence.SafeError(err))}, nil
	}
	credentials, principal, providerCode, err := exchangeAWS(ctx, client, a.Config, assertion)
	assertion = ""
	if err != nil {
		f := awsUnknown("AWS workload identity exchange failed")
		f.Evidence = map[string]any{"provider": "aws", "provider_error_code": providerCode, "raw_tokens_recorded": false}
		return []evidence.Finding{f}, nil
	}
	defer credentials.clear()

	fed := evidence.NewFinding("TF-CLOUD-AWS-001", "AWS workload identity federation", "cloud", evidence.SeverityLow, evidence.Verified, evidence.StatusInfo, "GitHub OIDC assertion was exchanged for temporary AWS role credentials")
	fed.Implications = "This verifies federation for this role and point in time, not access to a resource or all AWS permissions."
	fed.Remediation = "Constrain the role trust policy subject and audience and keep attached AWS policies narrowly scoped."
	fed.Evidence = map[string]any{
		"provider": "aws", "role_arn": a.Config.RoleARN, "assumed_principal": principal,
		"expires_at": credentials.Expiration.UTC().Format(time.RFC3339), "raw_tokens_recorded": false, "temporary_credentials_recorded": false,
	}

	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	out := []evidence.Finding{fed}
	for _, target := range a.Config.Targets {
		method := strings.ToUpper(target.Method)
		if method == "" {
			method = http.MethodGet
		}
		req, reqErr := http.NewRequestWithContext(ctx, method, target.URL, nil)
		if reqErr != nil {
			return out, reqErr
		}
		signAWSRequest(req, credentials, target.Service, target.Region, now().UTC())
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			out = append(out, awsTargetUnknown(target, requestErr))
			continue
		}
		resp.Body.Close()
		code := resp.Header.Get("x-amzn-ErrorType")
		if code == "" {
			code = resp.Header.Get("x-amz-error-code")
		}
		if before, _, ok := strings.Cut(code, ":"); ok {
			code = before
		}
		out = append(out, cloudTargetFinding("TF-CLOUD-AWS-002", "AWS", target.Name, method, resp.StatusCode, target.ExpectedStatus, code, map[string]any{
			"provider": "aws", "service": target.Service, "region": target.Region,
		}))
	}
	return out, nil
}

func exchangeAWS(ctx context.Context, client *http.Client, config policy.AWS, assertion string) (awsCredentials, string, string, error) {
	form := url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"Version":          {"2011-06-15"},
		"RoleArn":          {config.RoleARN},
		"RoleSessionName":  {config.SessionName},
		"WebIdentityToken": {assertion},
		"DurationSeconds":  {"900"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://sts.amazonaws.com/", strings.NewReader(form.Encode()))
	if err != nil {
		return awsCredentials{}, "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return awsCredentials{}, "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return awsCredentials{}, "", "", fmt.Errorf("read bounded AWS STS response")
	}
	defer zeroBytes(body)
	if resp.StatusCode != http.StatusOK {
		var failure struct {
			Error struct {
				Code string `xml:"Code"`
			} `xml:"Error"`
		}
		_ = xml.Unmarshal(body, &failure)
		return awsCredentials{}, "", failure.Error.Code, fmt.Errorf("AWS STS returned HTTP %d", resp.StatusCode)
	}
	var result struct {
		Result struct {
			Credentials struct {
				AccessKeyID     string    `xml:"AccessKeyId"`
				SecretAccessKey string    `xml:"SecretAccessKey"`
				SessionToken    string    `xml:"SessionToken"`
				Expiration      time.Time `xml:"Expiration"`
			} `xml:"Credentials"`
			AssumedRoleUser struct {
				ARN string `xml:"Arn"`
			} `xml:"AssumedRoleUser"`
		} `xml:"AssumeRoleWithWebIdentityResult"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		return awsCredentials{}, "", "", fmt.Errorf("decode AWS STS response")
	}
	credentials := awsCredentials{
		AccessKeyID: result.Result.Credentials.AccessKeyID, SecretAccessKey: result.Result.Credentials.SecretAccessKey,
		SessionToken: result.Result.Credentials.SessionToken, Expiration: result.Result.Credentials.Expiration,
	}
	if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" || credentials.SessionToken == "" {
		credentials.clear()
		return awsCredentials{}, "", "", fmt.Errorf("AWS STS response omitted temporary credentials")
	}
	return credentials, result.Result.AssumedRoleUser.ARN, "", nil
}

func signAWSRequest(req *http.Request, credentials awsCredentials, service, region string, now time.Time) {
	date := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z")
	payloadHash := sha256Hex(nil)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-security-token", credentials.SessionToken)
	canonicalHeaders := "host:" + strings.ToLower(req.URL.Host) + "\n" + "x-amz-content-sha256:" + payloadHash + "\n" + "x-amz-date:" + amzDate + "\n" + "x-amz-security-token:" + strings.TrimSpace(credentials.SessionToken) + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
	canonical := strings.Join([]string{req.Method, awsCanonicalPath(req.URL), awsCanonicalQuery(req.URL), canonicalHeaders, signedHeaders, payloadHash}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	kDate := hmacSHA256([]byte("AWS4"+credentials.SecretAccessKey), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+credentials.AccessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func awsCanonicalPath(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	copyURL := *u
	copyURL.RawPath = ""
	return copyURL.EscapedPath()
}

func awsCanonicalQuery(u *url.URL) string {
	values := u.Query()
	type pair struct{ key, value string }
	pairs := make([]pair, 0)
	for key, items := range values {
		for _, value := range items {
			pairs = append(pairs, pair{key: awsEscape(key), value: awsEscape(value)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].key == pairs[j].key {
			return pairs[i].value < pairs[j].value
		}
		return pairs[i].key < pairs[j].key
	})
	parts := make([]string, 0, len(pairs))
	for _, item := range pairs {
		parts = append(parts, item.key+"="+item.value)
	}
	return strings.Join(parts, "&")
}

func awsEscape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func (credentials *awsCredentials) clear() {
	credentials.AccessKeyID = ""
	credentials.SecretAccessKey = ""
	credentials.SessionToken = ""
}

func awsUnknown(message string) evidence.Finding {
	f := evidence.NewFinding("TF-CLOUD-AWS-001", "AWS workload identity federation", "cloud", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, message)
	f.Implications = "The failed operation does not prove that AWS access is absent."
	f.Remediation = "Check explicit OIDC permission, role trust conditions, audience and network access."
	return f
}

func awsTargetUnknown(target policy.AWSTarget, err error) evidence.Finding {
	f := evidence.NewFinding("TF-CLOUD-AWS-002", "AWS read-only operation: "+target.Name, "cloud", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, "AWS request failed: "+evidence.SafeError(err))
	f.Implications = "Failure does not prove the identity lacks this or other AWS capabilities."
	f.Remediation = "Review AWS request telemetry and retry only within the authorised scope."
	f.Evidence = map[string]any{"provider": "aws", "target": target.Name, "service": target.Service, "region": target.Region, "response_body_recorded": false}
	return f
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
