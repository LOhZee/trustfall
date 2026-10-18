// Package userns parses Linux user-namespace ID maps without claiming that the
// immediately enclosing namespace is the host's initial user namespace.
package userns

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

type Mapping struct {
	Available              bool
	Valid                  bool
	EntryCount             int
	IDZeroMapped           bool
	IDZeroMapsToParentZero bool
	IdentityMapping        bool
	ErrorKind              string
	Raw                    string
}

type entry struct {
	inside    uint64
	parent    uint64
	endInside uint64
	endParent uint64
}

// Inspect reads and parses a procfs ID-map file. The injectable reader exists
// so permission and malformed-interface behavior can be tested deterministically.
func Inspect(path string, readFile func(string) ([]byte, error)) Mapping {
	if readFile == nil {
		readFile = os.ReadFile
	}
	raw, err := readFile(path)
	if err != nil {
		kind := "read_failed"
		if errors.Is(err, os.ErrPermission) {
			kind = "permission_denied"
		}
		return Mapping{ErrorKind: kind}
	}
	result, err := Parse(string(raw))
	result.Available = true
	result.Raw = strings.TrimSpace(string(raw))
	if err != nil {
		result.ErrorKind = "malformed_mapping"
		return result
	}
	result.Valid = true
	return result
}

// Parse validates every entry in a Linux uid_map or gid_map. Ranges are
// inclusive internally to make uint64 overflow checks explicit.
func Parse(raw string) (Mapping, error) {
	var result Mapping
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return result, fmt.Errorf("ID map is empty")
	}
	lines := strings.Split(trimmed, "\n")
	entries := make([]entry, 0, len(lines))
	result.IdentityMapping = true
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return Mapping{}, fmt.Errorf("ID map entry %d must have exactly three fields", i+1)
		}
		inside, errInside := strconv.ParseUint(fields[0], 10, 64)
		parent, errParent := strconv.ParseUint(fields[1], 10, 64)
		length, errLength := strconv.ParseUint(fields[2], 10, 64)
		if errInside != nil || errParent != nil || errLength != nil {
			return Mapping{}, fmt.Errorf("ID map entry %d contains an invalid unsigned integer", i+1)
		}
		if length == 0 {
			return Mapping{}, fmt.Errorf("ID map entry %d has zero length", i+1)
		}
		span := length - 1
		if inside > math.MaxUint64-span || parent > math.MaxUint64-span {
			return Mapping{}, fmt.Errorf("ID map entry %d range overflows uint64", i+1)
		}
		current := entry{inside: inside, parent: parent, endInside: inside + span, endParent: parent + span}
		for _, previous := range entries {
			if overlaps(current.inside, current.endInside, previous.inside, previous.endInside) {
				return Mapping{}, fmt.Errorf("ID map entry %d overlaps an inside-namespace range", i+1)
			}
			if overlaps(current.parent, current.endParent, previous.parent, previous.endParent) {
				return Mapping{}, fmt.Errorf("ID map entry %d overlaps a parent-namespace range", i+1)
			}
		}
		entries = append(entries, current)
		if inside != parent {
			result.IdentityMapping = false
		}
		if inside == 0 {
			result.IDZeroMapped = true
			result.IDZeroMapsToParentZero = parent == 0
		}
	}
	result.EntryCount = len(entries)
	return result, nil
}

func overlaps(aStart, aEnd, bStart, bEnd uint64) bool {
	return aStart <= bEnd && bStart <= aEnd
}
