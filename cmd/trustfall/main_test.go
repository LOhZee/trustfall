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
	contents := "version: '1'\nmode: enforce\nfail_on: critical\nexpectations:\n  TF-ID-001:\n    status: fail\n    condition: process must run as root for this deliberately failing test\n"
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

func TestOIDCAndTimeoutArgumentsFailClosed(t *testing.T) {
	for _, args := range [][]string{
		{"assess", "--oidc-audience", "trustfall", "--no-network"},
		{"assess", "--timeout", "6m", "--no-network"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut); code != exitUsage {
			t.Fatalf("args %v returned %d, stderr=%s", args, code, errOut.String())
		}
	}
}
