package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/LOhZee/trustfall/internal/engine"
	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
)

type closeOnlyBody struct{ read bool }

func (b *closeOnlyBody) Read([]byte) (int, error) {
	b.read = true
	return 0, errors.New("body must not be read")
}
func (b *closeOnlyBody) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}
func TestNetworkTimeoutIsUnknown(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	findings, err := (Probe{Targets: []policy.NetworkTarget{{Name: "allowed", Type: "https", Address: "https://example.com"}}, Client: client}).Run(ctx, engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Classification != evidence.Unknown || findings[0].Status != evidence.StatusUnknown {
		t.Fatalf("failure was overstated: %+v", findings[0])
	}
}
func TestPermissionDeniedIsUnknown(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("permission denied") })}
	findings, _ := (Probe{Targets: []policy.NetworkTarget{{Name: "allowed", Type: "https", Address: "https://example.com"}}, Client: client}).Run(context.Background(), engine.Config{})
	if findings[0].Status != evidence.StatusUnknown {
		t.Fatalf("got %+v", findings[0])
	}
}

func TestHTTPDenialVerifiesReachabilityNotAuthentication(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader("denied")), Header: make(http.Header), Request: r}, nil
	})}
	findings, err := (Probe{Targets: []policy.NetworkTarget{{Name: "allowed", Type: "https", Address: "https://example.com"}}, Client: client}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Classification != evidence.Verified || findings[0].Status != evidence.StatusInfo {
		t.Fatalf("HTTP response did not remain a reachability-only result: %+v", findings[0])
	}
}

func TestUnexpectedReachabilityFailsOnlyTheExplicitExpectation(t *testing.T) {
	expectUnreachable := false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header), Request: r}, nil
	})}
	findings, err := (Probe{Targets: []policy.NetworkTarget{{Name: "blocked", Type: "https", Address: "https://example.com", ExpectReachable: &expectUnreachable}}, Client: client}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Classification != evidence.Verified || findings[0].Status != evidence.StatusFail || findings[0].Severity != evidence.SeverityMedium {
		t.Fatalf("unexpected expectation result: %+v", findings[0])
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
	if findings[0].Classification != evidence.Unknown || !strings.Contains(findings[0].Observed, "redirect refused") {
		t.Fatalf("redirect failure was overstated: %+v", findings[0])
	}
}

func TestTCPProbeVerifiesOneLocalConnection(t *testing.T) {
	dialer := dialerFunc(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "example.com:443" {
			t.Fatalf("unexpected dial %s %s", network, address)
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	})
	findings, err := (Probe{Targets: []policy.NetworkTarget{{Name: "allowed", Type: "tcp", Address: "example.com:443"}}, Dialer: dialer}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Classification != evidence.Verified || findings[0].Status != evidence.StatusInfo {
		t.Fatalf("TCP connection not verified: %+v", findings[0])
	}
}

func TestMetadataHeadDoesNotReadBody(t *testing.T) {
	body := &closeOnlyBody{}
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodHead {
			t.Fatalf("method %s", r.Method)
		}
		return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header), Request: r}, nil
	})}
	findings, err := (MetadataProbe{Enabled: true, Providers: []string{"aws"}, Client: client}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if body.read {
		t.Fatal("metadata response body was read")
	}
	if findings[0].Classification != evidence.Verified {
		t.Fatalf("finding: %+v", findings[0])
	}
}

func TestMetadataTransportFailureRemainsUnknown(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("network denied") })}
	findings, err := (MetadataProbe{Enabled: true, Providers: []string{"gcp"}, Client: client}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Classification != evidence.Unknown || findings[0].Status != evidence.StatusUnknown || findings[0].Evidence["response_body_read"] != false {
		t.Fatalf("metadata failure was overstated: %+v", findings[0])
	}
}

var _ io.Reader = (*closeOnlyBody)(nil)
