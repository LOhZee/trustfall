package cloud

import (
	"fmt"
	"net/http"
	"time"

	"github.com/LOhZee/trustfall/internal/evidence"
)

func cloudHTTPClient() *http.Client {
	return &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect refused") }}
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
	f.Evidence = map[string]any{"provider": extra["provider"], "target": name, "method": method, "http_status": status, "provider_error_code": providerCode, "request_completed": true, "operation_authorized": authorized, "response_body_recorded": false}
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
