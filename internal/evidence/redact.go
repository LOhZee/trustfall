package evidence

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var jwtPattern = regexp.MustCompile(`(?i)\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b`)
var querySecretPattern = regexp.MustCompile(`(?i)([?&](?:token|secret|api_?key|signature|sig|password)=)[^&\s"']+`)

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
			out[k] = "[REDACTED]"
			continue
		}
		switch x := v.(type) {
		case string:
			out[k] = RedactString(x)
		case map[string]any:
			out[k] = RedactMap(x)
		case map[string]string:
			nested := make(map[string]any, len(x))
			for nk, nv := range x {
				nested[nk] = nv
			}
			out[k] = RedactMap(nested)
		case []string:
			y := make([]string, len(x))
			for i := range x {
				y[i] = RedactString(x[i])
			}
			out[k] = y
		case []any:
			y := make([]any, len(x))
			for i := range x {
				if s, ok := x[i].(string); ok {
					y[i] = RedactString(s)
				} else {
					y[i] = x[i]
				}
			}
			out[k] = y
		case []map[string]any:
			y := make([]map[string]any, len(x))
			for i := range x {
				y[i] = RedactMap(x[i])
			}
			out[k] = y
		default:
			out[k] = v
		}
	}
	return out
}

func SafeError(err error) string {
	if err == nil {
		return ""
	}
	return RedactString(fmt.Sprintf("%v", err))
}
