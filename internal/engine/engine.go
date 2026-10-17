package engine

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/trustfall-ci/trustfall/internal/evidence"
)

type Config struct {
	Profile      string
	NoNetwork    bool
	ProbeTimeout time.Duration
	Logger       *slog.Logger
	Options      map[string]any
}

type Metadata struct {
	Name         string
	Version      string
	Module       string
	Network      bool
	Active       bool
	Requirements []string
}

type Probe interface {
	Metadata() Metadata
	Run(context.Context, Config) ([]evidence.Finding, error)
}

type Engine struct{ Probes []Probe }

func (e Engine) Run(ctx context.Context, cfg Config, version, mode string) (evidence.Report, []error) {
	start := time.Now().UTC()
	r := evidence.Report{SchemaVersion: evidence.SchemaVersion, Tool: "trustfall", Run: evidence.RunMetadata{ID: fmt.Sprintf("%d", start.UnixNano()), StartedAt: start, Profile: cfg.Profile, PolicyMode: mode, NetworkDenied: cfg.NoNetwork, ToolVersion: version}}
	var errs []error
	for _, p := range e.Probes {
		m := p.Metadata()
		if cfg.NoNetwork && m.Network {
			f := evidence.NewFinding("TF-ENGINE-002", m.Name+" skipped", m.Module, evidence.SeverityNote, evidence.Unknown, evidence.StatusNotApplicable, "network probes were disabled by --no-network")
			f.Implications = "No conclusion can be drawn about this network boundary."
			f.Remediation = "Run an explicitly authorised assessment without --no-network if verification is required."
			f.Probe = probeMetadata(m, 0, false)
			r.Findings = append(r.Findings, f)
			continue
		}
		timeout := cfg.ProbeTimeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		pctx, cancel := context.WithTimeout(ctx, timeout)
		begin := time.Now()
		findings, err := p.Run(pctx, cfg)
		dur := time.Since(begin)
		timedOut := pctx.Err() == context.DeadlineExceeded
		cancel()
		if err != nil {
			errs = append(errs, fmt.Errorf("probe %s: %w", m.Name, err))
			f := evidence.NewFinding("TF-ENGINE-001", m.Name+" probe incomplete", m.Module, evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, "probe could not complete: "+evidence.SafeError(err))
			f.Implications = "The boundary is unknown; absence of a result is not evidence of isolation."
			f.Remediation = "Review runner permissions and diagnostic logs, then repeat the assessment."
			f.Probe = probeMetadata(m, dur, timedOut)
			findings = append(findings, f)
		}
		for i := range findings {
			findings[i].Probe = probeMetadata(m, dur, timedOut)
		}
		r.Findings = append(r.Findings, findings...)
	}
	r.Run.CompletedAt = time.Now().UTC()
	if err := r.Normalize(); err != nil {
		errs = append(errs, fmt.Errorf("normalize report: %w", err))
	}
	return r, errs
}

func probeMetadata(m Metadata, d time.Duration, timeout bool) evidence.ProbeMetadata {
	return evidence.ProbeMetadata{Name: m.Name, Version: m.Version, Duration: d, TimedOut: timeout, Network: m.Network, Active: m.Active, Requirements: m.Requirements}
}
