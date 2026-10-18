package network

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"testing"

	"github.com/LOhZee/trustfall/internal/engine"
	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
)

type closeOnlyBody struct {
	read   bool
	closed bool
}

func (b *closeOnlyBody) Read([]byte) (int, error) {
	b.read = true
	return 0, errors.New("body must not be read")
}
func (b *closeOnlyBody) Close() error { b.closed = true; return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

type resolverFunc func(context.Context, string) ([]string, error)

func (f resolverFunc) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f(ctx, host)
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func boolPointer(value bool) *bool { return &value }

func runTCPResult(t *testing.T, target policy.NetworkTarget, dialErr error) evidence.Finding {
	t.Helper()
	dialer := dialerFunc(func(context.Context, string, string) (net.Conn, error) {
		if dialErr != nil {
			return nil, dialErr
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	})
	findings, err := (Probe{Targets: []policy.NetworkTarget{target}, Dialer: dialer}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return findings[0]
}

func TestNetworkExpectationsUseOnlyExplicitBoundedEvidence(t *testing.T) {
	tests := []struct {
		name     string
		target   policy.NetworkTarget
		dialErr  error
		status   evidence.Status
		class    evidence.Classification
		outcome  string
		severity evidence.Severity
	}{
		{"positive success", policy.NetworkTarget{Name: "target", Type: "tcp", Address: "example.com:443", ExpectReachable: boolPointer(true)}, nil, evidence.StatusPass, evidence.Verified, "tcp_connected", evidence.SeverityLow},
		{"negative mismatch", policy.NetworkTarget{Name: "target", Type: "tcp", Address: "example.com:443", ExpectReachable: boolPointer(false), NegativeEvidence: "connection_refused"}, nil, evidence.StatusFail, evidence.Verified, "tcp_connected", evidence.SeverityMedium},
		{"positive refused", policy.NetworkTarget{Name: "target", Type: "tcp", Address: "example.com:443", ExpectReachable: boolPointer(true)}, syscall.ECONNREFUSED, evidence.StatusFail, evidence.Verified, "connection_refused", evidence.SeverityMedium},
		{"explicit negative refused", policy.NetworkTarget{Name: "target", Type: "tcp", Address: "example.com:443", ExpectReachable: boolPointer(false), NegativeEvidence: "connection_refused"}, syscall.ECONNREFUSED, evidence.StatusPass, evidence.Verified, "connection_refused", evidence.SeverityNote},
		{"negative lacks evidence policy", policy.NetworkTarget{Name: "target", Type: "tcp", Address: "example.com:443", ExpectReachable: boolPointer(false)}, syscall.ECONNREFUSED, evidence.StatusInfo, evidence.Verified, "connection_refused", evidence.SeverityNote},
		{"timeout is inconclusive", policy.NetworkTarget{Name: "target", Type: "tcp", Address: "example.com:443", ExpectReachable: boolPointer(false), NegativeEvidence: "connection_refused"}, timeoutError{}, evidence.StatusUnknown, evidence.Unknown, "timeout", evidence.SeverityNote},
		{"cancelled is inconclusive", policy.NetworkTarget{Name: "target", Type: "tcp", Address: "example.com:443", ExpectReachable: boolPointer(false), NegativeEvidence: "connection_refused"}, context.Canceled, evidence.StatusUnknown, evidence.Unknown, "cancelled", evidence.SeverityNote},
		{"unavailable is inconclusive", policy.NetworkTarget{Name: "target", Type: "tcp", Address: "example.com:443", ExpectReachable: boolPointer(false), NegativeEvidence: "connection_refused"}, errors.New("route unavailable"), evidence.StatusUnknown, evidence.Unknown, "unavailable", evidence.SeverityNote},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			finding := runTCPResult(t, test.target, test.dialErr)
			if finding.Status != test.status || finding.Classification != test.class || finding.Severity != test.severity || finding.Evidence["outcome"] != test.outcome {
				t.Fatalf("unexpected result: %+v", finding)
			}
			if finding.Evidence["broader_isolation_established"] != false {
				t.Fatalf("broader isolation was overstated: %+v", finding.Evidence)
			}
		})
	}
}

func TestDNSNXDOMAINPassesOnlyWhenExplicitlyPermitted(t *testing.T) {
	resolver := resolverFunc(func(context.Context, string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "missing.example", IsNotFound: true}
	})
	target := policy.NetworkTarget{Name: "missing", Type: "dns", Address: "missing.example", ExpectReachable: boolPointer(false), NegativeEvidence: "dns_nxdomain"}
	findings, err := (Probe{Targets: []policy.NetworkTarget{target}, Resolver: resolver}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != evidence.StatusPass || findings[0].Evidence["outcome"] != "dns_nxdomain" {
		t.Fatalf("unexpected result: %+v", findings[0])
	}
}

func TestTLSVerificationFailureIsDistinctAndNotNegativeIsolationEvidence(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Head", URL: "https://example.com", Err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: "example.com"}}
	})}
	findings, _ := (Probe{Targets: []policy.NetworkTarget{{Name: "tls", Type: "https", Address: "https://example.com", ExpectReachable: boolPointer(false), NegativeEvidence: "connection_refused"}}, Client: client}).Run(context.Background(), engine.Config{})
	if findings[0].Evidence["outcome"] != "tls_verification_failed" || findings[0].Status == evidence.StatusPass {
		t.Fatalf("TLS failure was treated as isolation: %+v", findings[0])
	}
}

func TestHTTPResponseRecordsReachabilityAndAuthorizationSeparately(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("ignored")), Header: make(http.Header), Request: r}, nil
			})}
			findings, err := (Probe{Targets: []policy.NetworkTarget{{Name: "allowed", Type: "https", Address: "https://example.com", ExpectReachable: boolPointer(true)}}, Client: client}).Run(context.Background(), engine.Config{})
			if err != nil {
				t.Fatal(err)
			}
			finding := findings[0]
			if finding.Status != evidence.StatusPass || finding.Evidence["outcome"] != "http_response" || finding.Evidence["http_status"] != status {
				t.Fatalf("HTTP response was not treated as bounded reachability: %+v", finding)
			}
			if (status == http.StatusUnauthorized || status == http.StatusForbidden) && finding.Evidence["http_outcome"] != "authorization_denied" {
				t.Fatalf("authorization denial was not distinguished: %+v", finding.Evidence)
			}
		})
	}
}

func TestDefaultHTTPSClientRefusesCrossOriginRedirect(t *testing.T) {
	client := defaultHTTPClient()
	client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "example.com" {
			return &http.Response{StatusCode: http.StatusFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{"https://attacker.example/"}}, Request: r}, nil
		}
		t.Fatal("cross-origin redirect was followed")
		return nil, nil
	})
	findings, err := (Probe{Targets: []policy.NetworkTarget{{Name: "redirect", Type: "https", Address: "https://example.com"}}, Client: client}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Classification != evidence.Unknown || findings[0].Evidence["outcome"] != "redirect_refused" {
		t.Fatalf("redirect failure was overstated: %+v", findings[0])
	}
}

func TestDefaultHTTPSClientRefusesSameHostDifferentPort(t *testing.T) {
	client := defaultHTTPClient()
	client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Port() == "" {
			return &http.Response{StatusCode: http.StatusFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{"https://example.com:8443/"}}, Request: r}, nil
		}
		t.Fatal("different-port redirect was followed")
		return nil, nil
	})
	findings, _ := (Probe{Targets: []policy.NetworkTarget{{Name: "redirect", Type: "https", Address: "https://example.com"}}, Client: client}).Run(context.Background(), engine.Config{})
	if findings[0].Evidence["outcome"] != "redirect_refused" || findings[0].Status != evidence.StatusUnknown {
		t.Fatalf("different-port redirect was not refused: %+v", findings[0])
	}
}

func TestMetadataHTTPStatusesNeverImplyCredentialAccess(t *testing.T) {
	for _, status := range []int{200, 400, 401, 403, 404, 405} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			body := &closeOnlyBody{}
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodHead {
					t.Fatalf("method %s", r.Method)
				}
				return &http.Response{StatusCode: status, Body: body, Header: make(http.Header), Request: r}, nil
			})}
			findings, err := (MetadataProbe{Enabled: true, Providers: []string{"aws"}, Client: client}).Run(context.Background(), engine.Config{})
			if err != nil {
				t.Fatal(err)
			}
			finding := findings[0]
			if body.read || !body.closed {
				t.Fatalf("metadata body handling read=%t closed=%t", body.read, body.closed)
			}
			if finding.Status != evidence.StatusInfo || finding.Severity != evidence.SeverityNote || finding.Evidence["service_identified"] != false || finding.Evidence["metadata_retrieved"] != false || finding.Evidence["credential_exposure_tested"] != false {
				t.Fatalf("status %d was overstated: %+v", status, finding)
			}
		})
	}
}

func TestMetadataGCPMarkerIdentifiesServiceWithoutClaimingExposure(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: &closeOnlyBody{}, Header: http.Header{"Metadata-Flavor": []string{"Google"}}, Request: r}, nil
	})}
	findings, _ := (MetadataProbe{Enabled: true, Providers: []string{"gcp"}, Client: client}).Run(context.Background(), engine.Config{})
	finding := findings[0]
	if finding.Status != evidence.StatusInfo || finding.Severity != evidence.SeverityLow || finding.Evidence["service_identified"] != true || finding.Evidence["credential_path_requested"] != false {
		t.Fatalf("GCP evidence was misclassified: %+v", finding)
	}
}

func TestMetadataProxyIndicatorsPreventServiceIdentification(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: &closeOnlyBody{}, Header: http.Header{"Metadata-Flavor": []string{"Google"}, "Via": []string{"proxy.example"}}, Request: r}, nil
	})}
	findings, _ := (MetadataProbe{Enabled: true, Providers: []string{"gcp"}, Client: client}).Run(context.Background(), engine.Config{})
	if findings[0].Evidence["service_identified"] != false || findings[0].Evidence["intermediary_indicated"] != true {
		t.Fatalf("proxy response was misidentified: %+v", findings[0])
	}
}

func TestMetadataFailuresAndRedirectsRemainUnknown(t *testing.T) {
	tests := []struct {
		name    string
		client  *http.Client
		outcome string
	}{
		{"connection failure", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, syscall.ECONNREFUSED })}, "connection_refused"},
		{"timeout", &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, timeoutError{} })}, "timeout"},
		{"redirect", func() *http.Client {
			client := metadataHTTPClient()
			client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": []string{"http://example.com/"}}, Request: r}, nil
			})
			return client
		}(), "redirect_refused"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := (MetadataProbe{Enabled: true, Providers: []string{"azure"}, Client: test.client}).Run(context.Background(), engine.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if findings[0].Classification != evidence.Unknown || findings[0].Status != evidence.StatusUnknown || findings[0].Evidence["outcome"] != test.outcome {
				t.Fatalf("metadata failure was overstated: %+v", findings[0])
			}
		})
	}
}

func TestMetadataDefaultClientDisablesProxy(t *testing.T) {
	client := metadataHTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("metadata client can use environment proxy: %#v", client.Transport)
	}
}

var _ io.Reader = (*closeOnlyBody)(nil)
