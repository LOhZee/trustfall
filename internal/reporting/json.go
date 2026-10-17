package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/LOhZee/trustfall/internal/evidence"
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
	const maxReportBytes = 16 << 20
	raw, err := io.ReadAll(io.LimitReader(r, maxReportBytes+1))
	if err != nil {
		return report, fmt.Errorf("read report: %w", err)
	}
	if len(raw) > maxReportBytes {
		return report, fmt.Errorf("report exceeds 16 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&report); err != nil {
		return report, fmt.Errorf("decode report: %w", err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return report, fmt.Errorf("report must contain exactly one JSON document")
		}
		return report, fmt.Errorf("decode trailing report content: %w", err)
	}
	err = report.Normalize()
	return report, err
}
