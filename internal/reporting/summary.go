package reporting

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/trustfall-ci/trustfall/internal/evidence"
)

func WriteSummary(w io.Writer, r evidence.Report, violations []string) error {
	counts := map[evidence.Status]int{}
	for _, f := range r.Findings {
		counts[f.Status]++
	}
	_, err := fmt.Fprintf(w, "## TrustFall runtime assessment\n\nProfile: `%s` · Findings: %d · Failed: %d · Unknown: %d\n\n| Rule | Severity | Evidence | Status | Observation |\n|---|---|---|---|---|\n", escape(r.Run.Profile), len(r.Findings), counts[evidence.StatusFail], counts[evidence.StatusUnknown])
	if err != nil {
		return err
	}
	for _, f := range r.Findings {
		if _, err = fmt.Fprintf(w, "| `%s` | %s | %s | %s | %s |\n", escape(f.RuleID), f.Severity, f.Classification, f.Status, escape(f.Observed)); err != nil {
			return err
		}
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		if _, err = fmt.Fprint(w, "\n### Policy violations\n\n"); err != nil {
			return err
		}
		for _, v := range violations {
			if _, err = fmt.Fprintf(w, "- %s\n", escape(v)); err != nil {
				return err
			}
		}
	}
	_, err = fmt.Fprintln(w, "\n> Unknown is not secure. A successful test proves only the operation that succeeded.")
	return err
}
func escape(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
