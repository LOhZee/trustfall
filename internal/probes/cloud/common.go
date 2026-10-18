package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/LOhZee/trustfall/internal/evidence"
)

var errCloudRedirect = errors.New("cloud redirect refused")
var providerCodePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)

type cloudOperationError struct{ outcome string }

func (e cloudOperationError) Error() string { return "cloud operation failed: " + e.outcome }

func classifyCloudError(err error) error {
	return cloudOperationError{outcome: cloudTransportOutcome(err)}
}

func cloudError(outcome string) error { return cloudOperationError{outcome: outcome} }

func cloudHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Credential-bearing cloud requests must never be forwarded through an
	// ambient HTTP(S)_PROXY configuration.
	transport.Proxy = nil
	return &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errCloudRedirect }}
}

func cloudTransportOutcome(err error) string {
	var operationError cloudOperationError
	if errors.As(err, &operationError) {
		return operationError.outcome
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, errCloudRedirect):
		return "redirect_refused"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "transport_error"
}

func decodeBoundedJSON(body io.Reader, limit int64, target any) error {
	raw, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return fmt.Errorf("read bounded response")
	}
	defer zeroBytes(raw)
	if int64(len(raw)) > limit {
		return fmt.Errorf("response exceeds size limit")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("decode response")
	}
	return nil
}

func sanitizeProviderCode(code string) string {
	code = strings.TrimSpace(code)
	if code == "" {
		return ""
	}
	if !providerCodePattern.MatchString(code) {
		return "unrecognized"
	}
	return code
}

func cloudTargetFinding(ruleID, provider, name, method string, status int, expected []int, providerCode string, extra map[string]any) evidence.Finding {
	outcome := "responded"
	authorized := status >= 200 && status < 300
	if authorized {
		outcome = "allowed"
	} else if status == http.StatusUnauthorized || status == http.StatusForbidden {
		outcome = "denied this attempt"
	}
	f := evidence.NewFinding(ruleID, provider+" read-only operation: "+name, "cloud", evidence.SeverityMedium, evidence.Verified, evidence.StatusInfo, fmt.Sprintf("%s %s with HTTP %d for the explicitly scoped %s operation", provider, outcome, status, method))
	f.Implications = "The response verifies only this operation, identity, target and point in time. A denial does not establish absence of other capabilities."
	f.Remediation = "Compare this operation with the expected capability policy and reduce cloud permissions if it exceeds intent."
	f.Evidence = map[string]any{"provider": extra["provider"], "target": name, "method": method, "http_status": status, "provider_error_code": sanitizeProviderCode(providerCode), "request_completed": true, "operation_authorized": authorized, "response_body_recorded": false}
	for key, value := range extra {
		f.Evidence[key] = value
	}
	if len(expected) > 0 {
		f.Expected = fmt.Sprintf("HTTP status in %v", expected)
		if containsInt(expected, status) {
			f.Status = evidence.StatusPass
		} else {
			f.Status = evidence.StatusFail
		}
	}
	return f
}
