package reporting

import (
	"encoding/json"
	"io"

	"github.com/trustfall-ci/trustfall/internal/evidence"
)

func WriteJSON(w io.Writer, r evidence.Report) error {
	if err := r.Normalize(); err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
func ReadJSON(r io.Reader) (evidence.Report, error) {
	var report evidence.Report
	err := json.NewDecoder(io.LimitReader(r, 16<<20)).Decode(&report)
	if err != nil {
		return report, err
	}
	err = report.Normalize()
	return report, err
}
