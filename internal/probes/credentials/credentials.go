package credentials

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/trustfall-ci/trustfall/internal/engine"
	"github.com/trustfall-ci/trustfall/internal/evidence"
)

type Probe struct {
	Home    string
	Environ []string
}

func (Probe) Metadata() engine.Metadata {
	return engine.Metadata{Name: "credential-exposure", Version: "1", Module: "credentials", Requirements: []string{"environment variable names", "filesystem metadata"}}
}

var credentialName = regexp.MustCompile(`(?i)(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|CLIENT_?SECRET|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|CONNECTION_STRING|AUTH_SOCK)$`)

func (p Probe) Run(ctx context.Context, _ engine.Config) ([]evidence.Finding, error) {
	env := p.Environ
	if env == nil {
		env = os.Environ()
	}
	var names []string
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if credentialName.MatchString(name) || name == "ACTIONS_ID_TOKEN_REQUEST_TOKEN" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	ef := evidence.NewFinding("TF-CRED-001", "Credential-bearing environment variables", "credentials", evidence.SeverityMedium, evidence.Observed, evidence.StatusPass, "no credential-pattern environment variable names were present")
	ef.Implications = "Environment credentials are readable by the current process and may be inherited by child processes; names do not establish value validity or scope."
	ef.Remediation = "Pass credentials only to the step that requires them and prefer short-lived, narrowly scoped tokens."
	ef.Evidence = map[string]any{"variable_names": names, "values_inspected": false}
	if len(names) > 0 {
		ef.Status, ef.Observed = evidence.StatusFail, fmt.Sprintf("%d credential-pattern environment variable names were present", len(names))
	}

	home := p.Home
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	paths := []string{filepath.Join(home, ".aws", "credentials"), filepath.Join(home, ".azure", "accessTokens.json"), filepath.Join(home, ".config", "gcloud", "application_default_credentials.json"), filepath.Join(home, ".docker", "config.json"), filepath.Join(home, ".kube", "config"), filepath.Join(home, ".git-credentials"), "/var/run/secrets/kubernetes.io/serviceaccount/token"}
	var files []map[string]any
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		item := map[string]any{"path": path, "mode": info.Mode().Perm().String(), "size_bytes": info.Size(), "readable_by_process": syscall.Access(path, 4) == nil}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			item["uid"], item["gid"] = st.Uid, st.Gid
		}
		files = append(files, item)
	}
	ff := evidence.NewFinding("TF-CRED-002", "Known credential file locations", "credentials", evidence.SeverityHigh, evidence.Observed, evidence.StatusPass, "no known credential files were present")
	ff.Implications = "Readable authentication material may let this workload exercise the material's authority; file presence does not establish validity."
	ff.Remediation = "Avoid mounting broad credential stores and use ephemeral, workload-scoped credentials."
	ff.Evidence = map[string]any{"files": files, "contents_inspected": false}
	if len(files) > 0 {
		ff.Status, ff.Observed = evidence.StatusFail, "one or more known credential files were present"
	}

	var gitFiles []map[string]any
	for _, path := range []string{filepath.Join(home, ".gitconfig"), filepath.Join(home, ".config", "git", "config"), ".git/config"} {
		if info, err := os.Lstat(path); err == nil {
			gitFiles = append(gitFiles, map[string]any{"path": path, "mode": info.Mode().Perm().String(), "size_bytes": info.Size()})
		}
	}
	settingNames := []string{}
	gitAvailable := true
	cmd := exec.CommandContext(ctx, "git", "config", "--name-only", "--get-regexp", `^credential\.`)
	if output, err := cmd.Output(); err == nil {
		seen := map[string]bool{}
		for _, name := range strings.Fields(string(output)) {
			if len(name) <= 200 && strings.HasPrefix(strings.ToLower(name), "credential.") {
				parts := strings.Split(name, ".")
				safeName := "credential." + parts[len(parts)-1]
				if !seen[safeName] {
					settingNames = append(settingNames, safeName)
					seen[safeName] = true
				}
			}
		}
		sort.Strings(settingNames)
	} else if _, ok := err.(*exec.ExitError); !ok {
		gitAvailable = false
	}
	gf := evidence.NewFinding("TF-CRED-003", "Git credential configuration", "credentials", evidence.SeverityLow, evidence.Inferred, evidence.StatusInfo, "Git credential setting names and configuration file presence were inspected without reading values")
	gf.Implications = "Git configuration can reference credential helpers or authenticated remotes; file presence alone does not prove credential access."
	gf.Remediation = "Use credential.persistCredentials: false where checkout credentials are unnecessary after checkout."
	gf.Evidence = map[string]any{"configuration_files": gitFiles, "credential_setting_names": settingNames, "git_available": gitAvailable, "values_inspected": false}
	return []evidence.Finding{ef, ff, gf}, nil
}
