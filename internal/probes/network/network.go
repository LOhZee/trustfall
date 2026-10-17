package network

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/trustfall-ci/trustfall/internal/engine"
	"github.com/trustfall-ci/trustfall/internal/evidence"
	"github.com/trustfall-ci/trustfall/internal/policy"
)

type Probe struct {
	Targets     []policy.NetworkTarget
	Concurrency int
	Client      *http.Client
	Resolver    *net.Resolver
	Dialer      *net.Dialer
}

func (Probe) Metadata() engine.Metadata {
	return engine.Metadata{Name: "allowlisted-network", Version: "1", Module: "network", Network: true, Active: true, Requirements: []string{"explicit target allowlist"}}
}
func (p Probe) Run(ctx context.Context, _ engine.Config) ([]evidence.Finding, error) {
	if len(p.Targets) == 0 {
		f := evidence.NewFinding("TF-NET-000", "Configured network targets", "network", evidence.SeverityNote, evidence.Unknown, evidence.StatusNotApplicable, "no network targets were explicitly configured")
		f.Implications = "Network egress was not tested."
		f.Remediation = "Add only authorised destinations to policy.network.targets."
		return []evidence.Finding{f}, nil
	}
	limit := p.Concurrency
	if limit < 1 {
		limit = 4
	}
	if limit > 16 {
		limit = 16
	}
	sem := make(chan struct{}, limit)
	out := make([]evidence.Finding, len(p.Targets))
	var wg sync.WaitGroup
	for i, t := range p.Targets {
		wg.Add(1)
		go func(i int, t policy.NetworkTarget) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out[i] = failed(t, ctx.Err())
				return
			}
			out[i] = p.test(ctx, t)
		}(i, t)
	}
	wg.Wait()
	return out, nil
}
func (p Probe) test(ctx context.Context, t policy.NetworkTarget) evidence.Finding {
	start := time.Now()
	var detail map[string]any
	var err error
	switch t.Type {
	case "dns":
		r := p.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		var addrs []string
		addrs, err = r.LookupHost(ctx, t.Address)
		detail = map[string]any{"resolved_address_count": len(addrs)}
	case "tcp":
		d := p.Dialer
		if d == nil {
			d = &net.Dialer{Timeout: 3 * time.Second}
		}
		var c net.Conn
		c, err = d.DialContext(ctx, "tcp", t.Address)
		if err == nil {
			_ = c.Close()
		}
		detail = map[string]any{}
	case "https":
		client := p.Client
		if client == nil {
			client = &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				if req.URL.Scheme != "https" || req.URL.Hostname() != via[0].URL.Hostname() {
					return fmt.Errorf("cross-origin redirect refused")
				}
				return nil
			}}
		}
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodHead, t.Address, nil)
		if err == nil {
			var resp *http.Response
			resp, err = client.Do(req)
			if err == nil {
				io.CopyN(io.Discard, resp.Body, 1024)
				resp.Body.Close()
				detail = map[string]any{"http_status": resp.StatusCode, "final_origin": origin(resp.Request.URL)}
			}
		}
	}
	if err != nil {
		return failed(t, err)
	}
	f := evidence.NewFinding("TF-NET-001", "Allowlisted network reachability: "+t.Name, "network", evidence.SeverityLow, evidence.Verified, evidence.StatusInfo, "the configured "+t.Type+" operation succeeded")
	f.Implications = "This proves only the specific operation and destination under the tested conditions; it does not prove authenticated access or broad network reachability."
	f.Remediation = "Restrict egress to required destinations and compare the result with the workload's intended access."
	detail["target"] = t.Name
	detail["type"] = t.Type
	detail["duration_ms"] = time.Since(start).Milliseconds()
	f.Evidence = detail
	if t.ExpectReachable != nil {
		f.Expected = fmt.Sprintf("reachable=%t", *t.ExpectReachable)
		if *t.ExpectReachable {
			f.Status = evidence.StatusPass
		} else {
			f.Status = evidence.StatusFail
			f.Severity = evidence.SeverityMedium
		}
	}
	return f
}
func failed(t policy.NetworkTarget, err error) evidence.Finding {
	f := evidence.NewFinding("TF-NET-001", "Allowlisted network reachability: "+t.Name, "network", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, "the configured operation did not succeed: "+evidence.SafeError(err))
	f.Implications = "A failed point-in-time request does not establish that the destination or broader network is unreachable."
	f.Remediation = "Check destination, DNS, TLS and runner egress policy before drawing a conclusion."
	f.Evidence = map[string]any{"target": t.Name, "type": t.Type}
	return f
}
func origin(u *url.URL) string { return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) }

type MetadataProbe struct {
	Enabled   bool
	Providers []string
	Client    *http.Client
}

func (MetadataProbe) Metadata() engine.Metadata {
	return engine.Metadata{Name: "cloud-metadata-reachability", Version: "1", Module: "network", Network: true, Active: true, Requirements: []string{"explicit metadata opt-in"}}
}
func (p MetadataProbe) Run(ctx context.Context, _ engine.Config) ([]evidence.Finding, error) {
	if !p.Enabled {
		f := evidence.NewFinding("TF-NET-002", "Cloud metadata endpoint reachability", "network", evidence.SeverityNote, evidence.Unknown, evidence.StatusNotApplicable, "metadata probing was not enabled")
		f.Implications = "Metadata reachability is unknown."
		f.Remediation = "Enable only for an authorised assessment."
		return []evidence.Finding{f}, nil
	}
	endpoints := map[string]string{"aws": "http://169.254.169.254/latest/meta-data/", "azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "gcp": "http://metadata.google.internal/computeMetadata/v1/"}
	var out []evidence.Finding
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }}
	}
	for _, provider := range p.Providers {
		endpoint := endpoints[provider]
		req, _ := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
		if provider == "azure" {
			req.Header.Set("Metadata", "true")
		}
		if provider == "gcp" {
			req.Header.Set("Metadata-Flavor", "Google")
		}
		resp, err := client.Do(req)
		if err != nil {
			out = append(out, metadataUnknown(provider, err))
			continue
		}
		resp.Body.Close()
		f := evidence.NewFinding("TF-NET-002", "Cloud metadata endpoint: "+provider, "network", evidence.SeverityHigh, evidence.Verified, evidence.StatusFail, fmt.Sprintf("metadata endpoint responded to a body-free HEAD request with HTTP %d", resp.StatusCode))
		f.Implications = "Endpoint reachability may expose instance identity or credentials depending on provider controls; no credential path or response body was requested."
		f.Remediation = "Block metadata access from jobs that do not require it and enforce provider-specific session protections."
		f.Evidence = map[string]any{"target": provider, "http_status": resp.StatusCode, "method": "HEAD", "response_body_read": false}
		out = append(out, f)
	}
	return out, nil
}
func metadataUnknown(provider string, err error) evidence.Finding {
	f := evidence.NewFinding("TF-NET-002", "Cloud metadata endpoint: "+provider, "network", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, "metadata HEAD request failed: "+evidence.SafeError(err))
	f.Implications = "Failure does not prove metadata is universally unreachable."
	f.Remediation = "Validate with provider-native network controls if this boundary matters."
	f.Evidence = map[string]any{"target": provider, "response_body_read": false}
	return f
}
