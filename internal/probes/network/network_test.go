package network

import (
	"context"
	"errors"
	"github.com/trustfall-ci/trustfall/internal/engine"
	"github.com/trustfall-ci/trustfall/internal/evidence"
	"github.com/trustfall-ci/trustfall/internal/policy"
	"io"
	"net/http"
	"testing"
	"time"
)

type closeOnlyBody struct{ read bool }

func (b *closeOnlyBody) Read([]byte) (int, error) {
	b.read = true
	return 0, errors.New("body must not be read")
}
func (b *closeOnlyBody) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
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

var _ io.Reader = (*closeOnlyBody)(nil)
