package evidence

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var jwtPattern = regexp.MustCompile(`(?i)\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b`)
var querySecretPattern = regexp.MustCompile(`(?i)([?&][^=&\s"']*(?:token|secret|api_?key|signature|password|credential|access_?key)[^=&\s"']*=)[^&\s"']+`)

func sensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, needle := range []string{"token", "secret", "password", "passwd", "credential", "authorization", "assertion", "cookie", "private_key"} {
		if strings.Contains(k, needle) {
			return true
		}
	}
	return false
}

func RedactString(s string) string {
	s = jwtPattern.ReplaceAllString(s, "[REDACTED_JWT]")
	s = querySecretPattern.ReplaceAllString(s, "${1}[REDACTED]")
	if u, err := url.Parse(s); err == nil && u.User != nil {
		u.User = url.User("[REDACTED]")
		s = u.String()
	}
	return s
}

func RedactMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		if sensitiveKey(k) {
			// Boolean presence/handling markers such as
			// github_token_variable_present and raw_tokens_recorded are evidence,
			// not credential material. Never preserve a string or structured value
			// under a credential-like key.
			if marker, ok := v.(bool); ok {
				out[k] = marker
			} else {
				out[k] = "[REDACTED]"
			}
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

func redactValue(v any) any {
	switch x := v.(type) {
	case string:
		return RedactString(x)
	case map[string]any:
		return RedactMap(x)
	case map[string]string:
		nested := make(map[string]any, len(x))
		for k, value := range x {
			nested[k] = value
		}
		return RedactMap(nested)
	case []string:
		out := make([]string, len(x))
		for i := range x {
			out[i] = RedactString(x[i])
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = redactValue(x[i])
		}
		return out
	case []map[string]any:
		out := make([]map[string]any, len(x))
		for i := range x {
			out[i] = RedactMap(x[i])
		}
		return out
	default:
		return v
	}
}

func SafeError(err error) string {
	if err == nil {
		return ""
	}
	return RedactString(fmt.Sprintf("%v", err))
}
