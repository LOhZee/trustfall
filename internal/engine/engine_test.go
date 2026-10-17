package engine

import (
	"context"
	"errors"
	"github.com/LOhZee/trustfall/internal/evidence"
	"testing"
	"time"
)

type blockingProbe struct{}

func (blockingProbe) Metadata() Metadata {
	return Metadata{Name: "block", Version: "1", Module: "identity"}
}
func (blockingProbe) Run(ctx context.Context, _ Config) ([]evidence.Finding, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func TestTimeoutProducesUnknownOperationalEvidence(t *testing.T) {
	r, errs := (Engine{Probes: []Probe{blockingProbe{}}}).Run(context.Background(), Config{Profile: "baseline", ProbeTimeout: time.Millisecond}, "test", "audit")
	if len(errs) != 1 || !errors.Is(errs[0], context.DeadlineExceeded) {
		t.Fatalf("errors: %v", errs)
	}
	if len(r.Findings) != 1 || r.Findings[0].Classification != evidence.Unknown || !r.Findings[0].Probe.TimedOut {
		t.Fatalf("findings: %+v", r.Findings)
	}
}
