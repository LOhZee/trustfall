package credentials

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/LOhZee/trustfall/internal/engine"
	"github.com/LOhZee/trustfall/internal/evidence"
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

func TestKnownCredentialLocationPresenceIsInferredNotUsability(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("not-inspected"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := (Probe{Home: t.TempDir(), Environ: []string{}, Paths: []string{path}}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	got := findings[1]
	if got.Classification != evidence.Inferred || got.Status != evidence.StatusFail || got.Evidence["credential_usability_tested"] != false {
		t.Fatalf("credential presence overstated: %+v", got)
	}
}

func TestMissingCredentialLocationIsNotAnExposure(t *testing.T) {
	findings, err := (Probe{Home: t.TempDir(), Environ: []string{}, Paths: []string{filepath.Join(t.TempDir(), "absent")}}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[1].Status != evidence.StatusPass {
		t.Fatalf("absent bounded location: %+v", findings[1])
	}
}

func TestPermissionDeniedCredentialLocationIsUnknown(t *testing.T) {
	denied := filepath.Join(t.TempDir(), "denied")
	findings, err := (Probe{
		Home:    t.TempDir(),
		Environ: []string{},
		Paths:   []string{denied},
		Lstat: func(path string) (os.FileInfo, error) {
			if path == denied {
				return nil, os.ErrPermission
			}
			return nil, os.ErrNotExist
		},
	}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[1].Status != evidence.StatusUnknown || findings[1].Classification != evidence.Unknown {
		t.Fatalf("permission denial became absence: %+v", findings[1])
	}
}
