package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExitCodes(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"version", "--json"}, &out, &errOut); code != exitOK {
		t.Fatalf("version exit %d: %s", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"validate", "--policy", "missing"}, &out, &errOut); code != exitUsage {
		t.Fatalf("invalid policy exit %d", code)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"compare", "missing-a.json", "missing-b.json"}, &out, &errOut); code != exitOperational {
		t.Fatalf("operational exit %d", code)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"assess", "--profile", "baseline", "--no-network", "--output", filepath.Join(t.TempDir(), "audit.json")}, &out, &errOut); code != exitOK {
		t.Fatalf("audit exit %d: %s", code, errOut.String())
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	contents := "version: '1'\nmode: enforce\nfail_on: critical\nexpectations:\n  TF-CRED-003:\n    status: pass\n    condition: git configuration should be absent\n"
	if e := os.WriteFile(path, []byte(contents), 0o600); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	errOut.Reset()
	code := run([]string{"assess", "--profile", "custom", "--policy", path, "--no-network"}, &out, &errOut)
	if code != exitPolicy {
		t.Fatalf("policy exit %d stderr=%s", code, errOut.String())
	}
}
