package isolation

import (
	"context"
	"github.com/LOhZee/trustfall/internal/engine"
	"github.com/LOhZee/trustfall/internal/evidence"
	"os"
	"path/filepath"
	"testing"
)

func TestUnavailableProcIsUnknown(t *testing.T) {
	findings, err := (Probe{ProcRoot: filepath.Join(t.TempDir(), "missing")}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Classification != evidence.Unknown || findings[0].Status != evidence.StatusUnknown {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}
func TestCapabilityDecode(t *testing.T) {
	got, err := decodeCaps("0000000000200000")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "CAP_SYS_ADMIN" {
		t.Fatalf("got %v", got)
	}
}
func TestFixtureStatus(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "self", "attr"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "self", "status"), []byte("CapEff:\t0\nCapPrm:\t0\nCapBnd:\t0\nSeccomp:\t2\nNoNewPrivs:\t1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "self", "mountinfo"), []byte("1 2 0:1 / / rw - overlay overlay rw\n"), 0o600)
	findings, err := (Probe{ProcRoot: root}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != evidence.StatusPass {
		t.Fatalf("capabilities not pass: %+v", findings[0])
	}
}

func TestMissingEffectiveCapabilitiesIsUnknown(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "self", "attr"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "self", "status"), []byte("CapPrm:\t0\nCapBnd:\t0\nSeccomp:\t2\nNoNewPrivs:\t1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "self", "mountinfo"), nil, 0o600)
	findings, err := (Probe{ProcRoot: root}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Status != evidence.StatusUnknown || findings[0].Classification != evidence.Unknown {
		t.Fatalf("missing capabilities became secure: %+v", findings[0])
	}
}

func TestNoNewPrivilegesDisabledIsFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "self", "attr"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "self", "status"), []byte("CapEff:\t0\nCapPrm:\t0\nCapBnd:\t0\nSeccomp:\t2\nNoNewPrivs:\t0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "self", "mountinfo"), nil, 0o600)
	findings, err := (Probe{ProcRoot: root}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if findings[1].Status != evidence.StatusFail {
		t.Fatalf("disabled no-new-privileges not reported: %+v", findings[1])
	}
}

func TestUIDMappingReportsParentNamespaceWithoutClaimingHostIdentity(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "self", "attr"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"status":    "Uid:\t0\t0\t0\t0\nCapEff:\t0\nCapPrm:\t0\nCapBnd:\t0\nSeccomp:\t2\nNoNewPrivs:\t1\n",
		"uid_map":   "1 200001 10\n0 100000 1\n",
		"gid_map":   "0 100000 65536\n",
		"mountinfo": "1 2 0:1 / / rw - overlay overlay rw\n",
	}
	for name, value := range files {
		if err := os.WriteFile(filepath.Join(root, "self", name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := (Probe{ProcRoot: root}).Run(context.Background(), engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	var mapping, privileged evidence.Finding
	for _, finding := range findings {
		switch finding.RuleID {
		case "TF-ISO-004":
			mapping = finding
		case "TF-ISO-008":
			privileged = finding
		}
	}
	if mapping.Status != evidence.StatusInfo || mapping.Evidence["uid_map_entry_count"] != 2 || mapping.Evidence["uid_zero_maps_to_parent_uid_zero"] != false || mapping.Evidence["initial_user_namespace_established"] != false {
		t.Fatalf("mapping evidence was overstated: %+v", mapping)
	}
	if privileged.Severity != evidence.SeverityMedium || privileged.Evidence["initial_user_namespace_established"] != false {
		t.Fatalf("privileged finding was overstated: %+v", privileged)
	}
}

func TestPermissionDeniedHostResourceIsUnknown(t *testing.T) {
	finding := sensitiveHostResourceFinding([]string{"/denied"}, func(string) (os.FileInfo, error) {
		return nil, os.ErrPermission
	})
	if finding.Status != evidence.StatusUnknown || finding.Classification != evidence.Unknown {
		t.Fatalf("permission denial became a secure result: %+v", finding)
	}
	paths, ok := finding.Evidence["uninspectable_paths"].([]string)
	if !ok || len(paths) != 1 || paths[0] != "/denied" {
		t.Fatalf("permission-denied evidence missing: %#v", finding.Evidence)
	}
}
