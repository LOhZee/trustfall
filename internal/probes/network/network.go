package network

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LOhZee/trustfall/internal/engine"
	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
)

var (
	errCrossOriginRedirect = errors.New("cross-origin redirect refused")
	errTooManyRedirects    = errors.New("too many redirects")
	errMetadataRedirect    = errors.New("metadata redirect refused")
)

type Probe struct {
	Targets     []policy.NetworkTarget
	Concurrency int
	Client      *http.Client
	Resolver    hostResolver
	Dialer      contextDialer
}

type hostResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func (Probe) Metadata() engine.Metadata {
	return engine.Metadata{Name: "allowlisted-network", Version: "2", Module: "network", Network: true, Active: true, Requirements: []string{"explicit target allowlist"}}
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
				out[i] = failed(t, classifyNetworkError(ctx.Err()), 0)
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
	detail := map[string]any{}
	var err error
	var outcome string
	switch t.Type {
	case "dns":
		r := p.Resolver
		if r == nil {
			r = net.DefaultResolver
		}
		var addrs []string
		addrs, err = r.LookupHost(ctx, t.Address)
		detail["resolved_address_count"] = len(addrs)
		outcome = "dns_resolved"
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
		outcome = "tcp_connected"
	case "https":
		client := p.Client
		if client == nil {
			client = defaultHTTPClient()
		}
		var req *http.Request
		req, err = http.NewRequestWithContext(ctx, http.MethodHead, t.Address, nil)
		if err == nil {
			var resp *http.Response
			resp, err = client.Do(req)
			if err == nil {
				resp.Body.Close()
				detail["http_status"] = resp.StatusCode
				detail["final_origin"] = origin(resp.Request.URL)
				detail["http_outcome"] = httpOutcome(resp.StatusCode)
			}
		}
		outcome = "http_response"
	default:
		err = fmt.Errorf("unsupported network probe type %q", t.Type)
	}
	if err != nil {
		return failed(t, classifyNetworkError(err), time.Since(start))
	}

	f := evidence.NewFinding("TF-NET-001", "Allowlisted network reachability: "+t.Name, "network", evidence.SeverityLow, evidence.Verified, evidence.StatusInfo, "the configured "+t.Type+" operation succeeded")
	f.Implications = "This proves only the specific operation and destination under the tested conditions; it does not prove authenticated access or broad network reachability."
	f.Remediation = "Restrict egress to required destinations and compare the result with the workload's intended access."
	detail["target"] = t.Name
	detail["type"] = t.Type
	detail["outcome"] = outcome
	detail["operation_succeeded"] = true
	detail["broader_isolation_established"] = false
	detail["duration_ms"] = time.Since(start).Milliseconds()
	f.Evidence = detail
	applyExpectation(&f, t, true, outcome)
	return f
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return errTooManyRedirects
		}
		if req.URL.Scheme != "https" || origin(req.URL) != origin(via[0].URL) {
			return errCrossOriginRedirect
		}
		return nil
	}}
}

type networkError struct {
	outcome     string
	description string
	conclusive  bool
}

func classifyNetworkError(err error) networkError {
	switch {
	case err == nil:
		return networkError{}
	case errors.Is(err, context.Canceled):
		return networkError{outcome: "cancelled", description: "the configured operation was cancelled"}
	case errors.Is(err, context.DeadlineExceeded):
		return networkError{outcome: "timeout", description: "the configured operation timed out"}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return networkError{outcome: "dns_nxdomain", description: "DNS reported that the tested name does not exist", conclusive: true}
		}
		if dnsErr.IsTimeout {
			return networkError{outcome: "timeout", description: "the DNS operation timed out"}
		}
		return networkError{outcome: "dns_failure", description: "the DNS operation failed"}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return networkError{outcome: "timeout", description: "the configured operation timed out"}
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return networkError{outcome: "connection_refused", description: "the tested connection attempt was refused", conclusive: true}
	}
	if isTLSVerificationError(err) {
		return networkError{outcome: "tls_verification_failed", description: "TLS peer verification failed for the tested HTTPS operation", conclusive: true}
	}
	if errors.Is(err, errCrossOriginRedirect) || errors.Is(err, errTooManyRedirects) || errors.Is(err, errMetadataRedirect) {
		return networkError{outcome: "redirect_refused", description: "the HTTP redirect was refused by the probe"}
	}
	if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return networkError{outcome: "policy_denied", description: "the local operation was denied by an explicit permission boundary", conclusive: true}
	}
	return networkError{outcome: "unavailable", description: "the configured operation did not complete"}
}

func isTLSVerificationError(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalid)
}

func failed(t policy.NetworkTarget, result networkError, duration time.Duration) evidence.Finding {
	class := evidence.Unknown
	status := evidence.StatusUnknown
	if result.conclusive {
		class = evidence.Verified
		status = evidence.StatusInfo
	}
	f := evidence.NewFinding("TF-NET-001", "Allowlisted network reachability: "+t.Name, "network", evidence.SeverityNote, class, status, result.description)
	f.Implications = "This is the outcome of one bounded operation. It does not establish that the destination is unreachable through every route, protocol, identity, or future execution."
	f.Remediation = "Check the exact outcome against an explicit policy; do not treat an ambiguous failure as proof of isolation."
	f.Evidence = map[string]any{
		"target":                        t.Name,
		"type":                          t.Type,
		"outcome":                       result.outcome,
		"operation_succeeded":           false,
		"broader_isolation_established": false,
		"duration_ms":                   duration.Milliseconds(),
	}
	applyExpectation(&f, t, false, result.outcome)
	return f
}

func applyExpectation(f *evidence.Finding, t policy.NetworkTarget, succeeded bool, outcome string) {
	if t.ExpectReachable == nil {
		return
	}
	f.Expected = fmt.Sprintf("reachable=%t", *t.ExpectReachable)
	if *t.ExpectReachable {
		if succeeded {
			f.Status = evidence.StatusPass
			return
		}
		if outcome == "dns_nxdomain" || outcome == "connection_refused" || outcome == "tls_verification_failed" || outcome == "policy_denied" {
			f.Status = evidence.StatusFail
			f.Severity = evidence.SeverityMedium
		}
		return
	}
	if succeeded {
		f.Status = evidence.StatusFail
		f.Severity = evidence.SeverityMedium
		return
	}
	if t.NegativeEvidence != "" && outcome == t.NegativeEvidence {
		f.Status = evidence.StatusPass
		f.Severity = evidence.SeverityNote
		f.Observed = "the explicitly permitted negative evidence was observed for this bounded operation"
	}
}

func httpOutcome(status int) string {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "authorization_denied"
	case http.StatusTooManyRequests:
		return "rate_limited"
	default:
		return "response_received"
	}
}

func origin(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

type MetadataProbe struct {
	Enabled   bool
	Providers []string
	Client    *http.Client
}

func (MetadataProbe) Metadata() engine.Metadata {
	return engine.Metadata{Name: "cloud-metadata-reachability", Version: "2", Module: "network", Network: true, Active: true, Requirements: []string{"explicit metadata opt-in"}}
}

func (p MetadataProbe) Run(ctx context.Context, _ engine.Config) ([]evidence.Finding, error) {
	if !p.Enabled {
		f := evidence.NewFinding("TF-NET-002", "Cloud metadata endpoint reachability", "network", evidence.SeverityNote, evidence.Unknown, evidence.StatusNotApplicable, "metadata probing was not enabled")
		f.Implications = "Metadata reachability is unknown."
		f.Remediation = "Enable only for an authorised assessment."
		return []evidence.Finding{f}, nil
	}
	endpoints := map[string]string{
		"aws":   "http://169.254.169.254/latest/meta-data/",
		"azure": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		"gcp":   "http://metadata.google.internal/computeMetadata/v1/",
	}
	client := p.Client
	if client == nil {
		client = metadataHTTPClient()
	}
	out := make([]evidence.Finding, 0, len(p.Providers))
	for _, provider := range p.Providers {
		endpoint, ok := endpoints[provider]
		if !ok {
			out = append(out, metadataUnknown(provider, networkError{outcome: "unavailable", description: "the metadata provider is unsupported"}))
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
		if err != nil {
			out = append(out, metadataUnknown(provider, classifyNetworkError(err)))
			continue
		}
		if provider == "azure" {
			req.Header.Set("Metadata", "true")
		}
		if provider == "gcp" {
			req.Header.Set("Metadata-Flavor", "Google")
		}
		resp, err := client.Do(req)
		if err != nil {
			out = append(out, metadataUnknown(provider, classifyNetworkError(err)))
			continue
		}
		resp.Body.Close()
		out = append(out, metadataResponse(provider, resp))
	}
	return out, nil
}

func metadataHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Link-local metadata probes must not be redirected through environment
	// proxies. A proxy response is not evidence from the metadata service.
	transport.Proxy = nil
	return &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errMetadataRedirect
		},
	}
}

func metadataResponse(provider string, resp *http.Response) evidence.Finding {
	intermediary := hasIntermediaryHeaders(resp.Header)
	identified := provider == "gcp" && strings.EqualFold(resp.Header.Get("Metadata-Flavor"), "Google") && !intermediary
	observed := fmt.Sprintf("a body-free HEAD request received HTTP %d; the responding service was not identified", resp.StatusCode)
	severity := evidence.SeverityNote
	if identified {
		observed = fmt.Sprintf("the GCP Metadata-Flavor response marker identified a metadata service response to the body-free HEAD request (HTTP %d)", resp.StatusCode)
		severity = evidence.SeverityLow
	} else if intermediary {
		observed = fmt.Sprintf("a body-free HEAD request received HTTP %d with intermediary/proxy response indicators", resp.StatusCode)
	}
	f := evidence.NewFinding("TF-NET-002", "Cloud metadata endpoint: "+provider, "network", severity, evidence.Verified, evidence.StatusInfo, observed)
	f.Implications = "This proves only the recorded HTTP interaction. It does not prove metadata retrieval, credential exposure, or authenticated cloud access."
	f.Remediation = "If metadata access is not intended, validate provider-native network controls separately; do not infer exposure from an unidentifiable response."
	f.Evidence = metadataEvidence(provider)
	f.Evidence["http_status"] = resp.StatusCode
	f.Evidence["outcome"] = "http_response"
	f.Evidence["http_outcome"] = httpOutcome(resp.StatusCode)
	f.Evidence["service_identified"] = identified
	f.Evidence["intermediary_indicated"] = intermediary
	if identified {
		f.Evidence["identification_basis"] = "Metadata-Flavor: Google response header"
	} else {
		f.Evidence["identification_basis"] = "insufficient response evidence"
	}
	return f
}

func metadataUnknown(provider string, result networkError) evidence.Finding {
	f := evidence.NewFinding("TF-NET-002", "Cloud metadata endpoint: "+provider, "network", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, result.description)
	f.Implications = "The bounded request did not identify a metadata service. Failure does not prove metadata is universally unreachable."
	f.Remediation = "Validate with provider-native network controls if this boundary matters."
	f.Evidence = metadataEvidence(provider)
	f.Evidence["outcome"] = result.outcome
	f.Evidence["service_identified"] = false
	f.Evidence["identification_basis"] = "no identifying response"
	return f
}

func metadataEvidence(provider string) map[string]any {
	evidenceMap := map[string]any{
		"target":                        provider,
		"method":                        http.MethodHead,
		"response_body_read":            false,
		"metadata_retrieved":            false,
		"credential_path_requested":     false,
		"credential_exposure_tested":    false,
		"proxy_disabled_by_default":     true,
		"broader_isolation_established": false,
	}
	switch provider {
	case "aws":
		evidenceMap["provider_request_control"] = "IMDSv2 session token not requested"
		evidenceMap["provider_request_header_sent"] = false
	case "azure":
		evidenceMap["provider_request_control"] = "Metadata request header"
		evidenceMap["provider_request_header_sent"] = true
	case "gcp":
		evidenceMap["provider_request_control"] = "Metadata-Flavor request header"
		evidenceMap["provider_request_header_sent"] = true
	}
	return evidenceMap
}

func hasIntermediaryHeaders(header http.Header) bool {
	for _, name := range []string{"Via", "Forwarded", "X-Forwarded-For", "Proxy-Authenticate", "Proxy-Connection"} {
		if header.Get(name) != "" {
			return true
		}
	}
	return false
}
