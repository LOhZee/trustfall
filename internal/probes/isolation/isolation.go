package isolation

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/LOhZee/trustfall/internal/engine"
	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/probes/userns"
)

type Probe struct {
	ProcRoot          string
	SocketPaths       []string
	WritablePaths     []string
	HostResourcePaths []string
}

func (Probe) Metadata() engine.Metadata {
	return engine.Metadata{Name: "container-isolation", Version: "2", Module: "isolation", Requirements: []string{"Linux procfs"}}
}

var capNames = []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE"}

func (p Probe) Run(_ context.Context, _ engine.Config) ([]evidence.Finding, error) {
	root := p.ProcRoot
	if root == "" {
		root = "/proc"
	}
	status, err := parseKV(root + "/self/status")
	if err != nil {
		f := evidence.NewFinding("TF-ISO-000", "Container security interfaces", "isolation", evidence.SeverityNote, evidence.Unknown, evidence.StatusUnknown, "process security interfaces were unavailable: "+evidence.SafeError(err))
		f.Implications = "Container isolation cannot be assessed from missing or inaccessible interfaces; this is not a passing result."
		f.Remediation = "Expose read-only procfs security metadata to the assessment process where appropriate."
		return []evidence.Finding{f}, nil
	}
	var out []evidence.Finding
	capEvidence := map[string]any{}
	for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapAmb"} {
		raw := status[field]
		names, err := decodeCaps(raw)
		if err != nil {
			capEvidence[strings.ToLower(field)] = map[string]any{"raw": raw, "decode_error": err.Error()}
		} else {
			capEvidence[strings.ToLower(field)] = names
		}
	}
	effective, effectiveErr := decodeCaps(status["CapEff"])
	permitted, permittedErr := decodeCaps(status["CapPrm"])
	bounding, boundingErr := decodeCaps(status["CapBnd"])
	cf := evidence.NewFinding("TF-ISO-001", "Linux process capabilities", "isolation", evidence.SeverityNote, evidence.Observed, evidence.StatusPass, fmt.Sprintf("%d effective, %d permitted and %d bounding Linux capabilities observed", len(effective), len(permitted), len(bounding)))
	cf.Implications = "Capabilities expand the kernel operations available to the container process; they do not alone prove host access."
	cf.Remediation = "Run the container with --cap-drop=ALL and add back only a demonstrated requirement."
	cf.Evidence = capEvidence
	if effectiveErr != nil || permittedErr != nil || boundingErr != nil {
		cf.Classification, cf.Status = evidence.Unknown, evidence.StatusUnknown
		cf.Observed = "one or more core Linux capability sets were unavailable or could not be decoded"
	} else if len(effective) > 0 {
		cf.Severity, cf.Status = evidence.SeverityMedium, evidence.StatusFail
	}
	out = append(out, cf)

	sec := status["Seccomp"]
	secText := map[string]string{"0": "disabled", "1": "strict", "2": "filter"}[sec]
	if secText == "" {
		secText = "unavailable"
	}
	noNewPrivs, noNewPrivsPresent := status["NoNewPrivs"]
	sf := evidence.NewFinding("TF-ISO-002", "Seccomp and no-new-privileges", "isolation", evidence.SeverityMedium, evidence.Observed, evidence.StatusPass, "seccomp mode is "+secText+" and no-new-privileges is enabled")
	sf.Implications = "Seccomp reduces syscall exposure; its presence does not prove the filter is sufficiently restrictive."
	sf.Remediation = "Use the runtime default or a reviewed restrictive seccomp profile and set no-new-privileges."
	sf.Evidence = map[string]any{"seccomp_mode": secText, "seccomp_filters": status["Seccomp_filters"], "no_new_privileges": noNewPrivs == "1", "no_new_privileges_available": noNewPrivsPresent}
	if sec == "" || !noNewPrivsPresent {
		sf.Status, sf.Classification = evidence.StatusUnknown, evidence.Unknown
		sf.Observed = "seccomp or no-new-privileges state was unavailable"
	} else if sec == "0" {
		sf.Status = evidence.StatusFail
		sf.Observed = "seccomp was disabled"
	} else if sec != "1" && sec != "2" {
		sf.Status, sf.Classification = evidence.StatusUnknown, evidence.Unknown
		sf.Observed = "seccomp mode could not be interpreted"
	} else if noNewPrivs != "1" {
		sf.Status = evidence.StatusFail
		sf.Observed = "seccomp was enabled but no-new-privileges was not enabled"
	}
	out = append(out, sf)

	lf := evidence.NewFinding("TF-ISO-003", "Linux security module context", "isolation", evidence.SeverityNote, evidence.Observed, evidence.StatusInfo, "process security context was inspected")
	lf.Implications = "A confinement label may reduce access, but label presence alone does not demonstrate policy strength."
	lf.Remediation = "Apply and test an AppArmor or SELinux policy appropriate for the runner."
	if b, err := os.ReadFile(root + "/self/attr/current"); err == nil {
		lf.Evidence = map[string]any{"current": strings.TrimSpace(string(b))}
	} else {
		lf.Classification, lf.Status, lf.Observed = evidence.Unknown, evidence.StatusUnknown, "security module context unavailable: "+evidence.SafeError(err)
	}
	out = append(out, lf)

	uf := evidence.NewFinding("TF-ISO-004", "User namespace mappings", "isolation", evidence.SeverityNote, evidence.Observed, evidence.StatusInfo, "user namespace ID maps were inspected")
	uf.Implications = "Identity mapping describes the relationship to the immediately enclosing user namespace. It does not establish that namespace as the host's initial user namespace or prove containment."
	uf.Remediation = "Prefer rootless/user-namespaced containers where supported and validate the effective mapping."
	uidMap := userns.Inspect(root+"/self/uid_map", nil)
	gidMap := userns.Inspect(root+"/self/gid_map", nil)
	uf.Evidence = map[string]any{
		"uid_map_available":                  uidMap.Available,
		"uid_map_valid":                      uidMap.Valid,
		"uid_map_entry_count":                uidMap.EntryCount,
		"uid_zero_mapped":                    uidMap.IDZeroMapped,
		"uid_zero_maps_to_parent_uid_zero":   uidMap.IDZeroMapsToParentZero,
		"uid_map_identity_mapping":           uidMap.IdentityMapping,
		"uid_map_error":                      uidMap.ErrorKind,
		"gid_map_available":                  gidMap.Available,
		"gid_map_valid":                      gidMap.Valid,
		"gid_map_entry_count":                gidMap.EntryCount,
		"gid_zero_mapped":                    gidMap.IDZeroMapped,
		"gid_zero_maps_to_parent_gid_zero":   gidMap.IDZeroMapsToParentZero,
		"gid_map_identity_mapping":           gidMap.IdentityMapping,
		"gid_map_error":                      gidMap.ErrorKind,
		"initial_user_namespace_established": false,
	}
	if uidMap.Available {
		uf.Evidence["uid_map"] = uidMap.Raw
	}
	if gidMap.Available {
		uf.Evidence["gid_map"] = gidMap.Raw
	}
	if !uidMap.Valid || !gidMap.Valid {
		uf.Classification, uf.Status = evidence.Unknown, evidence.StatusUnknown
		uf.Observed = "one or more user namespace ID mappings were unavailable or malformed"
	}
	out = append(out, uf)

	cg := evidence.NewFinding("TF-ISO-005", "Cgroup membership", "isolation", evidence.SeverityNote, evidence.Observed, evidence.StatusInfo, "cgroup membership was inspected")
	cg.Implications = "Cgroup membership describes resource-control placement, not the effectiveness of its limits."
	cg.Remediation = "Set explicit CPU, memory and process limits where supported."
	if b, err := os.ReadFile(root + "/self/cgroup"); err == nil {
		cg.Evidence = map[string]any{"membership": strings.Split(strings.TrimSpace(string(b)), "\n")}
	} else {
		cg.Classification, cg.Status, cg.Observed = evidence.Unknown, evidence.StatusUnknown, "cgroup interface unavailable"
	}
	out = append(out, cg)

	mf, err := inspectMounts(root + "/self/mountinfo")
	if err != nil {
		mf.Classification, mf.Status, mf.Observed = evidence.Unknown, evidence.StatusUnknown, "mount information unavailable: "+err.Error()
	}
	out = append(out, mf)

	sockets := p.SocketPaths
	if sockets == nil {
		sockets = []string{"/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/crio/crio.sock", "/run/podman/podman.sock"}
	}
	var present, writable, inspectionErrors []string
	for _, path := range sockets {
		if _, err := os.Lstat(path); err == nil {
			present = append(present, path)
			if syscall.Access(path, 2) == nil {
				writable = append(writable, path)
			}
		} else if !os.IsNotExist(err) {
			inspectionErrors = append(inspectionErrors, path)
		}
	}
	rf := evidence.NewFinding("TF-ISO-007", "Container runtime socket exposure", "isolation", evidence.SeverityCritical, evidence.Observed, evidence.StatusPass, "no known container runtime sockets were visible")
	rf.Implications = "A writable runtime socket can often control sibling containers or the host; visibility alone does not verify successful control."
	rf.Remediation = "Do not mount container runtime sockets into assessment or build jobs."
	rf.Evidence = map[string]any{"present_paths": present, "writable_paths": writable, "uninspectable_paths": inspectionErrors}
	if len(present) > 0 {
		rf.Status, rf.Observed = evidence.StatusFail, "one or more container runtime sockets were visible"
	} else if len(inspectionErrors) > 0 {
		rf.Classification, rf.Status, rf.Observed = evidence.Unknown, evidence.StatusUnknown, "one or more runtime socket paths could not be inspected"
	}
	out = append(out, rf)

	uidFields := strings.Fields(status["Uid"])
	euidRoot := len(uidFields) > 1 && uidFields[1] == "0"
	hasSysAdmin := false
	for _, name := range effective {
		if name == "CAP_SYS_ADMIN" {
			hasSysAdmin = true
		}
	}
	pf := evidence.NewFinding("TF-ISO-008", "Privileged execution indicators", "isolation", evidence.SeverityHigh, evidence.Observed, evidence.StatusPass, "no strong privileged-container indicator was observed")
	pf.Implications = "Root identity or CAP_SYS_ADMIN increases attack surface, but neither alone verifies a container escape or host access. A remap relative to the parent user namespace does not identify the host's initial namespace."
	pf.Remediation = "Use a non-root image user, drop all capabilities and set no-new-privileges."
	pf.Evidence = map[string]any{"effective_uid_root": euidRoot, "cap_sys_admin": hasSysAdmin, "no_new_privileges": status["NoNewPrivs"] == "1", "uid_map_available": uidMap.Available, "uid_map_valid": uidMap.Valid, "uid_zero_mapped": uidMap.IDZeroMapped, "uid_zero_maps_to_parent_uid_zero": uidMap.IDZeroMapsToParentZero, "initial_user_namespace_established": false}
	if euidRoot || hasSysAdmin {
		pf.Status, pf.Observed = evidence.StatusFail, "one or more privileged execution indicators were observed"
		if euidRoot && uidMap.Valid && uidMap.IDZeroMapped && !uidMap.IDZeroMapsToParentZero && !hasSysAdmin {
			pf.Severity = evidence.SeverityMedium
			pf.Observed = "uid 0 was remapped relative to the observed parent user namespace; initial-namespace root authority was not established"
		}
	}
	out = append(out, pf)

	pathSet := map[string]bool{}
	writablePaths := p.WritablePaths
	if writablePaths == nil {
		writablePaths = []string{os.Getenv("GITHUB_WORKSPACE"), os.Getenv("RUNNER_TEMP"), os.Getenv("TMPDIR"), "/workspace", "/work", "/tmp", "/proc", "/sys", "/dev"}
	}
	for _, path := range writablePaths {
		if path == "" || pathSet[path] {
			continue
		}
		pathSet[path] = true
	}
	paths := make([]map[string]any, 0, len(pathSet))
	for path := range pathSet {
		if info, err := os.Stat(path); err == nil {
			paths = append(paths, map[string]any{"path": path, "directory": info.IsDir(), "writable_by_process": syscall.Access(path, 2) == nil})
		}
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i]["path"].(string) < paths[j]["path"].(string) })
	wf := evidence.NewFinding("TF-ISO-009", "Relevant writable paths", "isolation", evidence.SeverityNote, evidence.Observed, evidence.StatusInfo, "selected workspace, temporary and kernel-facing paths were checked for process write access")
	wf.Implications = "Writable workspace and temporary paths are expected; writable kernel or host paths can weaken isolation."
	wf.Remediation = "Keep system mounts read-only and scope writable mounts to the job workspace or a dedicated temporary directory."
	wf.Evidence = map[string]any{"paths": paths}
	out = append(out, wf)

	resourcePaths := p.HostResourcePaths
	if resourcePaths == nil {
		resourcePaths = []string{"/dev/kmsg", "/dev/mem", "/dev/kvm", "/proc/kcore", "/sys/kernel/debug"}
	}
	hf := sensitiveHostResourceFinding(resourcePaths, os.Lstat)
	out = append(out, hf)
	return out, nil
}

func sensitiveHostResourceFinding(paths []string, lstat func(string) (os.FileInfo, error)) evidence.Finding {
	resources, uninspectableResources, accessible := inspectSensitiveHostResources(paths, lstat)
	hf := evidence.NewFinding("TF-ISO-010", "Sensitive host resource access", "isolation", evidence.SeverityHigh, evidence.Observed, evidence.StatusPass, "no selected sensitive host device or kernel path was accessible")
	hf.Implications = "Access to host devices or kernel debug interfaces can materially weaken the container boundary; accessibility does not itself prove escape."
	hf.Remediation = "Do not expose host devices or kernel debug filesystems to CI jobs."
	hf.Evidence = map[string]any{"resources": resources, "uninspectable_paths": uninspectableResources, "contents_inspected": false}
	if accessible {
		hf.Status, hf.Observed = evidence.StatusFail, "one or more selected sensitive host resources were accessible"
	} else if len(uninspectableResources) > 0 {
		hf.Classification, hf.Status, hf.Observed = evidence.Unknown, evidence.StatusUnknown, "one or more selected sensitive host resource paths could not be inspected"
	}
	return hf
}

func inspectSensitiveHostResources(paths []string, lstat func(string) (os.FileInfo, error)) ([]map[string]any, []string, bool) {
	var resources []map[string]any
	var uninspectable []string
	accessible := false
	for _, path := range paths {
		info, err := lstat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				uninspectable = append(uninspectable, path)
			}
			continue
		}
		readable, writable := syscall.Access(path, 4) == nil, syscall.Access(path, 2) == nil
		resources = append(resources, map[string]any{"path": path, "mode": info.Mode().String(), "readable_by_process": readable, "writable_by_process": writable})
		accessible = accessible || readable || writable
	}
	return resources, uninspectable, accessible
}

func parseKV(path string) (map[string]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	m := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		p := strings.SplitN(s.Text(), ":", 2)
		if len(p) == 2 {
			m[p[0]] = strings.TrimSpace(p[1])
		}
	}
	return m, s.Err()
}
func decodeCaps(raw string) ([]string, error) {
	if raw == "" {
		return nil, fmt.Errorf("unavailable")
	}
	n, e := strconv.ParseUint(raw, 16, 64)
	if e != nil {
		return nil, e
	}
	var out []string
	for i, name := range capNames {
		if n&(uint64(1)<<i) != 0 {
			out = append(out, name)
		}
	}
	return out, nil
}

func inspectMounts(path string) (evidence.Finding, error) {
	f := evidence.NewFinding("TF-ISO-006", "Sensitive filesystem mounts", "isolation", evidence.SeverityHigh, evidence.Observed, evidence.StatusPass, "no known sensitive host mounts were identified")
	f.Implications = "Host or runtime mounts can bypass assumptions about container filesystem isolation."
	f.Remediation = "Mount only required paths read-only and never expose the host root or runtime control sockets."
	h, err := os.Open(path)
	if err != nil {
		return f, err
	}
	defer h.Close()
	var sensitive []map[string]any
	s := bufio.NewScanner(h)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 10 {
			continue
		}
		sep := -1
		for i, x := range fields {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(fields) {
			continue
		}
		mount := strings.ReplaceAll(fields[4], `\040`, " ")
		source := fields[sep+2]
		risk := mount == "/" && source == "/" || strings.Contains(source, "docker.sock") || strings.Contains(source, "containerd.sock") || strings.HasPrefix(mount, "/host")
		if risk {
			sensitive = append(sensitive, map[string]any{"mount_point": mount, "source": source, "options": fields[5]})
		}
	}
	if err := s.Err(); err != nil {
		return f, err
	}
	f.Evidence = map[string]any{"sensitive_mounts": sensitive}
	if len(sensitive) > 0 {
		f.Status, f.Observed = evidence.StatusFail, "potentially sensitive mounts were observed"
	}
	return f, nil
}
