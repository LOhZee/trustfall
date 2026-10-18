package userns

import (
	"errors"
	"os"
	"testing"
)

func TestParseIDMap(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantErr    bool
		entries    int
		zeroMapped bool
		parentZero bool
		identity   bool
	}{
		{"empty", "", true, 0, false, false, false},
		{"malformed fields", "0 0", true, 0, false, false, false},
		{"malformed number", "zero 0 1", true, 0, false, false, false},
		{"zero length", "0 0 0", true, 0, false, false, false},
		{"overlapping inside", "0 100000 10\n5 200000 10", true, 0, false, false, false},
		{"overlapping parent", "0 100000 10\n100 100005 10", true, 0, false, false, false},
		{"unmapped zero", "1 100001 65535", false, 1, false, false, false},
		{"identity", "0 0 65536", false, 1, true, true, true},
		{"remapped zero", "0 100000 65536", false, 1, true, false, false},
		{"multiple mappings", "1 200001 10\n0 100000 1\n20 300020 5", false, 3, true, false, false},
		{"inside overflow", "18446744073709551615 0 2", true, 0, false, false, false},
		{"parent overflow", "0 18446744073709551615 2", true, 0, false, false, false},
		{"maximum singleton", "18446744073709551615 18446744073709551615 1", false, 1, false, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Parse(test.raw)
			if (err != nil) != test.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %t", err, test.wantErr)
			}
			if test.wantErr {
				return
			}
			if got.EntryCount != test.entries || got.IDZeroMapped != test.zeroMapped || got.IDZeroMapsToParentZero != test.parentZero || got.IdentityMapping != test.identity {
				t.Fatalf("Parse() = %+v", got)
			}
		})
	}
}

func TestInspectDistinguishesPermissionAndMalformedData(t *testing.T) {
	denied := Inspect("/proc/self/uid_map", func(string) ([]byte, error) { return nil, os.ErrPermission })
	if denied.Available || denied.Valid || denied.ErrorKind != "permission_denied" {
		t.Fatalf("permission result = %+v", denied)
	}
	malformed := Inspect("/proc/self/uid_map", func(string) ([]byte, error) { return []byte("bad"), nil })
	if !malformed.Available || malformed.Valid || malformed.ErrorKind != "malformed_mapping" {
		t.Fatalf("malformed result = %+v", malformed)
	}
	other := Inspect("/proc/self/uid_map", func(string) ([]byte, error) { return nil, errors.New("gone") })
	if other.ErrorKind != "read_failed" {
		t.Fatalf("read error result = %+v", other)
	}
}
