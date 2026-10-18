package cloud

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type AWS struct {
	Config policy.AWS
	Client *http.Client
	Now    func() time.Time
	Signer v4.HTTPSigner
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
		f := awsUnknown("GitHub OIDC token issuance did not complete")
		f.Evidence = map[string]any{"provider": "aws", "outcome": cloudTransportOutcome(err), "raw_tokens_recorded": false}
		return []evidence.Finding{f}, nil
	}
	credentials, principal, providerCode, err := exchangeAWS(ctx, client, a.Config, assertion)
	if err != nil {
		f := awsUnknown("AWS workload identity exchange failed")
		f.Evidence = map[string]any{"provider": "aws", "provider_error_code": sanitizeProviderCode(providerCode), "outcome": cloudTransportOutcome(err), "raw_tokens_recorded": false}
		return []evidence.Finding{f}, nil
	}
	fed := evidence.NewFinding("TF-CLOUD-AWS-001", "AWS workload identity federation", "cloud", evidence.SeverityLow, evidence.Verified, evidence.StatusInfo, "GitHub OIDC assertion was exchanged for temporary AWS role credentials")
	fed.Implications = "This verifies federation for this role and point in time, not access to a resource or all AWS permissions."
	fed.Remediation = "Constrain the role trust policy subject and audience and keep attached AWS policies narrowly scoped."
	fed.Evidence = map[string]any{
		"provider": "aws", "role_arn": a.Config.RoleARN, "assumed_principal": principal,
		"expires_at": credentials.Expires.UTC().Format(time.RFC3339), "raw_tokens_recorded": false, "temporary_credentials_recorded": false,
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
		signer := a.Signer
		if signer == nil {
			signer = v4.NewSigner()
		}
		if signErr := signAWSRequest(ctx, signer, req, credentials, target.Service, target.Region, now().UTC()); signErr != nil {
			out = append(out, awsTargetUnknown(target, "signing_failed"))
			continue
		}
		resp, requestErr := client.Do(req)
		if requestErr != nil {
			out = append(out, awsTargetUnknown(target, cloudTransportOutcome(requestErr)))
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

func exchangeAWS(ctx context.Context, client *http.Client, config policy.AWS, assertion string) (aws.Credentials, string, string, error) {
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
		return aws.Credentials{}, "", "", cloudError("request_creation_failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return aws.Credentials{}, "", "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return aws.Credentials{}, "", "", cloudError("malformed_token_response")
	}
	defer zeroBytes(body)
	if resp.StatusCode != http.StatusOK {
		var failure struct {
			Error struct {
				Code string `xml:"Code"`
			} `xml:"Error"`
		}
		_ = xml.Unmarshal(body, &failure)
		outcome := "credential_exchange_rejected"
		if resp.StatusCode == http.StatusTooManyRequests {
			outcome = "rate_limited"
		}
		return aws.Credentials{}, "", failure.Error.Code, cloudError(outcome)
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
		return aws.Credentials{}, "", "", cloudError("malformed_token_response")
	}
	credentials := aws.Credentials{
		AccessKeyID: result.Result.Credentials.AccessKeyID, SecretAccessKey: result.Result.Credentials.SecretAccessKey,
		SessionToken: result.Result.Credentials.SessionToken, Expires: result.Result.Credentials.Expiration, CanExpire: true, Source: "TrustFallAssumeRoleWithWebIdentity",
	}
	if credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" || credentials.SessionToken == "" {
		return aws.Credentials{}, "", "", cloudError("malformed_token_response")
	}
	return credentials, result.Result.AssumedRoleUser.ARN, "", nil
}

func signAWSRequest(ctx context.Context, signer v4.HTTPSigner, req *http.Request, credentials aws.Credentials, service, region string, now time.Time) error {
	payloadHash := sha256Hex(nil)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	options := []func(*v4.SignerOptions){}
	if service == "s3" {
		options = append(options, func(options *v4.SignerOptions) {
			options.DisableURIPathEscaping = true
		})
	}
	return signer.SignHTTP(ctx, credentials, req, payloadHash, service, region, now, options...)
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func awsUnknown(message string) evidence.Finding {
	f := evidence.NewFinding("TF-CLOUD-AWS-001", "AWS workload identity federation", "cloud", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, message)
	f.Implications = "The failed operation does not prove that AWS access is absent."
	f.Remediation = "Check explicit OIDC permission, role trust conditions, audience and network access."
	return f
}

func awsTargetUnknown(target policy.AWSTarget, outcome string) evidence.Finding {
	f := evidence.NewFinding("TF-CLOUD-AWS-002", "AWS read-only operation: "+target.Name, "cloud", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, "AWS read-only operation did not complete")
	f.Implications = "Failure does not prove the identity lacks this or other AWS capabilities."
	f.Remediation = "Review AWS request telemetry and retry only within the authorised scope."
	f.Evidence = map[string]any{"provider": "aws", "target": target.Name, "service": target.Service, "region": target.Region, "outcome": outcome, "response_body_recorded": false}
	return f
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
