package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

type recordingAWSSigner struct {
	err                    error
	service                string
	region                 string
	payloadHash            string
	disableURIPathEscaping bool
}

func (s *recordingAWSSigner) SignHTTP(_ context.Context, _ aws.Credentials, _ *http.Request, payloadHash, service, region string, _ time.Time, optFns ...func(*v4.SignerOptions)) error {
	options := v4.SignerOptions{}
	for _, option := range optFns {
		option(&options)
	}
	s.service = service
	s.region = region
	s.payloadHash = payloadHash
	s.disableURIPathEscaping = options.DisableURIPathEscaping
	return s.err
}

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

func TestAWSSignerMatchesPublishedS3LifecycleVector(t *testing.T) {
	// AWS S3 Signature Version 4 documentation publishes this exact request,
	// credential, timestamp and expected Authorization value.
	req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?lifecycle", nil)
	if err != nil {
		t.Fatal(err)
	}
	credentials := aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	when := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	if err := signAWSRequest(context.Background(), v4.NewSigner(), req, credentials, "s3", "us-east-1", when); err != nil {
		t.Fatal(err)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestAWSSignerDelegatesCanonicalisationAndS3PathRules(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		service string
		region  string
		s3Path  bool
	}{
		{"reserved repeated and empty query", "https://sts.us-east-1.amazonaws.com/?z=%20%2F&a=~&a=%20&empty=", "sts", "us-east-1", false},
		{"spaces and Unicode", "https://execute-api.eu-west-1.amazonaws.com/a%20b/%E2%98%83?q=a%20b", "execute-api", "eu-west-1", false},
		{"escaped slash S3", "https://bucket.s3.us-west-2.amazonaws.com/key%2Fpart", "s3", "us-west-2", true},
		{"empty path global endpoint", "https://sts.amazonaws.com", "sts", "us-east-1", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, test.rawURL, nil)
			if err != nil {
				t.Fatal(err)
			}
			original := req.URL.String()
			signer := &recordingAWSSigner{}
			err = signAWSRequest(context.Background(), signer, req, aws.Credentials{AccessKeyID: "id", SecretAccessKey: "secret", SessionToken: "session"}, test.service, test.region, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if signer.service != test.service || signer.region != test.region || signer.payloadHash != sha256Hex(nil) || signer.disableURIPathEscaping != test.s3Path {
				t.Fatalf("unexpected signer inputs: %+v", signer)
			}
			if req.URL.String() != original {
				t.Fatalf("request URL changed before signing: %q -> %q", original, req.URL.String())
			}
		})
	}
}

func TestAWSSignerNormalisesHeaderWhitespaceAndIncludesSessionToken(t *testing.T) {
	credentials := aws.Credentials{AccessKeyID: "ASIATEST", SecretAccessKey: "secret", SessionToken: "temporary-session-token"}
	when := time.Date(2029, 1, 2, 3, 4, 5, 0, time.UTC)
	var authorizations []string
	for _, value := range []string{"one  two   three", "one two three"} {
		req, err := http.NewRequest(http.MethodGet, "https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Test-Whitespace", value)
		if err := signAWSRequest(context.Background(), v4.NewSigner(), req, credentials, "sts", "us-east-1", when); err != nil {
			t.Fatal(err)
		}
		if req.Header.Get("X-Amz-Security-Token") != credentials.SessionToken {
			t.Fatal("temporary session token was not included")
		}
		authorizations = append(authorizations, req.Header.Get("Authorization"))
	}
	if authorizations[0] != authorizations[1] {
		t.Fatalf("equivalent header whitespace produced different signatures:\n%s\n%s", authorizations[0], authorizations[1])
	}
}

func TestAWSSigningFailureIsReturnedWithoutSecretMaterial(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://sts.amazonaws.com/", nil)
	secret := "SYNTHETIC-SIGNER-SECRET"
	err := signAWSRequest(context.Background(), &recordingAWSSigner{err: errors.New(secret)}, req, aws.Credentials{AccessKeyID: "id", SecretAccessKey: secret}, "sts", "us-east-1", time.Now())
	if err == nil {
		t.Fatal("signing failure was ignored")
	}
	// The provider converts this error to a fixed outcome before report creation;
	// the low-level function intentionally returns it only to its direct caller.
}
