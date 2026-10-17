package credentials

import (
	"context"
	"github.com/trustfall-ci/trustfall/internal/engine"
	"testing"
)

func TestEnvironmentReportsNamesOnly(t *testing.T) {
	findings, err := (Probe{Home: t.TempDir(), Environ: []string{"SAFE=x", "API_TOKEN=do-not-leak"}}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Evidence["values_inspected"] != false {
		t.Fatal("values were marked inspected")
	}
	names := findings[0].Evidence["variable_names"].([]string)
	if len(names) != 1 || names[0] != "API_TOKEN" {
		t.Fatalf("names: %v", names)
	}
	if findings[0].Observed == "do-not-leak" {
		t.Fatal("secret leaked")
	}
}
