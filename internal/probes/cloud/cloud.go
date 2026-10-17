package cloud

import (
	"context"

	"github.com/LOhZee/trustfall/internal/engine"
	"github.com/LOhZee/trustfall/internal/evidence"
)

// Provider is intentionally operation-oriented: a successful request proves only
// the operation a provider records, never a synthesized global permission set.
type Provider interface {
	Name() string
	Enabled() bool
	Assess(context.Context) ([]evidence.Finding, error)
}

type Probe struct{ Providers []Provider }

func (Probe) Metadata() engine.Metadata {
	return engine.Metadata{Name: "effective-cloud-capabilities", Version: "1", Module: "cloud", Network: true, Active: true, Requirements: []string{"explicit provider opt-in", "workload identity", "explicit read-only targets"}}
}
func (p Probe) Run(ctx context.Context, _ engine.Config) ([]evidence.Finding, error) {
	var out []evidence.Finding
	enabled := 0
	for _, provider := range p.Providers {
		if !provider.Enabled() {
			continue
		}
		enabled++
		findings, err := provider.Assess(ctx)
		out = append(out, findings...)
		if err != nil {
			return out, err
		}
	}
	if enabled == 0 {
		f := evidence.NewFinding("TF-CLOUD-000", "Active cloud capability assessment", "cloud", evidence.SeverityNote, evidence.Unknown, evidence.StatusNotApplicable, "no cloud provider was explicitly enabled")
		f.Implications = "Cloud capabilities were not tested."
		f.Remediation = "Enable a provider only with a narrowly scoped identity and explicit read-only targets."
		out = append(out, f)
	}
	return out, nil
}
