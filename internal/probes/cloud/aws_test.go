package cloud

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
)

func TestAWSFederationAndDeniedTargetAreOperationSpecific(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://vstoken.actions.githubusercontent.com/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "github-request-secret")
	const accessKey = "ASIATESTACCESSKEY"
	const secretKey = "aws-secret-access-key"
	const sessionToken = "aws-session-token"
	client := &http.Client{Transport: azureRoundTrip(func(r *http.Request) (*http.Response, error) {
		response := &http.Response{Request: r, Header: make(http.Header)}
		switch r.URL.Hostname() {
		case "vstoken.actions.githubusercontent.com":
			if r.URL.Query().Get("audience") != "sts.amazonaws.com" {
				t.Fatal("unexpected AWS OIDC audience")
			}
			response.StatusCode = http.StatusOK
			response.Body = io.NopCloser(strings.NewReader(`{"value":"header.claims.signature"}`))
		case "sts.amazonaws.com":
			if r.Method != http.MethodPost {
				t.Fatalf("STS method %s", r.Method)
			}
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			form, err := url.ParseQuery(string(body))
			if err != nil || form.Get("Action") != "AssumeRoleWithWebIdentity" || form.Get("WebIdentityToken") == "" {
				t.Fatal("invalid AWS exchange form")
			}
			response.StatusCode = http.StatusOK
			response.Body = io.NopCloser(strings.NewReader(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>` + accessKey + `</AccessKeyId><SecretAccessKey>` + secretKey + `</SecretAccessKey><SessionToken>` + sessionToken + `</SessionToken><Expiration>2030-01-02T03:04:05Z</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/trustfall/ci</Arn></AssumedRoleUser></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`))
		case "sts.us-east-1.amazonaws.com":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential="+accessKey+"/") {
				t.Fatal("target request was not SigV4 signed")
			}
			if r.Header.Get("x-amz-security-token") != sessionToken {
				t.Fatal("target request omitted the AWS session token")
			}
			response.StatusCode = http.StatusForbidden
			response.Header.Set("x-amzn-ErrorType", "AccessDeniedException:client")
			response.Body = io.NopCloser(strings.NewReader(`<Error><Message>` + secretKey + `</Message></Error>`))
		default:
			t.Fatalf("unexpected host %s", r.URL.Hostname())
		}
		return response, nil
	})}
	provider := AWS{Client: client, Now: func() time.Time { return time.Date(2029, 1, 2, 3, 4, 5, 0, time.UTC) }, Config: policy.AWS{
		Enabled: true, Audience: "sts.amazonaws.com", RoleARN: "arn:aws:iam::123456789012:role/trustfall", SessionName: "trustfall-ci",
		Targets: []policy.AWSTarget{{Name: "caller", URL: "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", Service: "sts", Region: "us-east-1", Method: "GET", ExpectedStatus: []int{200}}},
	}}
	findings, err := provider.Assess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].Classification != evidence.Verified || findings[1].Classification != evidence.Verified || findings[1].Status != evidence.StatusFail {
		t.Fatalf("unexpected findings: %+v", findings)
	}
	if findings[1].Evidence["provider_error_code"] != "AccessDeniedException" || findings[1].Evidence["operation_authorized"] != false {
		t.Fatalf("unexpected target evidence: %+v", findings[1].Evidence)
	}
	encoded, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{accessKey, secretKey, sessionToken, "header.claims.signature", "github-request-secret"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("credential material reached AWS findings")
		}
	}
}

func TestAWSExchangeFailureIsUnknown(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://vstoken.actions.githubusercontent.com/token")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-secret")
	client := &http.Client{Transport: azureRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "vstoken.actions.githubusercontent.com" {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"value":"header.claims.signature"}`)), Header: make(http.Header), Request: r}, nil
		}
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`)), Header: make(http.Header), Request: r}, nil
	})}
	findings, err := (AWS{Client: client, Config: policy.AWS{Enabled: true, Audience: "sts.amazonaws.com", RoleARN: "arn:aws:iam::123456789012:role/trustfall", SessionName: "trustfall"}}).Assess(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Classification != evidence.Unknown || findings[0].Status != evidence.StatusUnknown {
		t.Fatalf("exchange failure was overstated: %+v", findings)
	}
}

func TestAWSCanonicalQuerySortsEncodedKeysAndValues(t *testing.T) {
	u, err := url.Parse("https://sts.us-east-1.amazonaws.com/?z=%20%2F&a=~&a=%20")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := awsCanonicalQuery(u), "a=%20&a=~&z=%20%2F"; got != want {
		t.Fatalf("canonical query %q, want %q", got, want)
	}
}
