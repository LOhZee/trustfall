package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/LOhZee/trustfall/internal/compare"
	"github.com/LOhZee/trustfall/internal/engine"
	"github.com/LOhZee/trustfall/internal/evidence"
	"github.com/LOhZee/trustfall/internal/policy"
	"github.com/LOhZee/trustfall/internal/probes/cloud"
	"github.com/LOhZee/trustfall/internal/probes/credentials"
	"github.com/LOhZee/trustfall/internal/probes/identity"
	"github.com/LOhZee/trustfall/internal/probes/isolation"
	"github.com/LOhZee/trustfall/internal/probes/network"
	"github.com/LOhZee/trustfall/internal/reporting"
)

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

const (
	exitOK          = 0
	exitUsage       = 1
	exitPolicy      = 2
	exitOperational = 3
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	switch args[0] {
	case "version":
		return versionCommand(args[1:], stdout, stderr)
	case "doctor":
		return doctorCommand(args[1:], stdout, stderr)
	case "assess":
		return assessCommand(args[1:], stdout, stderr)
	case "compare":
		return compareCommand(args[1:], stdout, stderr)
	case "validate":
		return validateCommand(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		return usage(stdout)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return usage(stderr)
	}
}
func usage(w io.Writer) int {
	fmt.Fprintln(w, "TrustFall — Your pipeline says it’s isolated. Let’s find out.\n\nUsage:\n  trustfall version [--json]\n  trustfall doctor\n  trustfall assess [--profile baseline|hardened|custom] [--request-oidc] [options]\n  trustfall compare [--output path] BASELINE.json CANDIDATE.json\n  trustfall validate --policy trustfall.yaml\n\nExit codes: 0 success/audit, 1 usage, 2 policy violation, 3 operational error")
	return exitUsage
}
func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(stderr)
	return f
}

func versionCommand(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("version", stderr)
	asJSON := fs.Bool("json", false, "write machine-readable version")
	if fs.Parse(args) != nil {
		return exitUsage
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(map[string]string{"version": version, "commit": commit, "build_date": buildDate, "go": runtime.Version()})
	} else {
		fmt.Fprintf(stdout, "trustfall %s (commit %s, built %s, %s)\n", version, commit, buildDate, runtime.Version())
	}
	return exitOK
}
func doctorCommand(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("doctor", stderr)
	if fs.Parse(args) != nil {
		return exitUsage
	}
	checks := []map[string]any{{"name": "linux", "ok": runtime.GOOS == "linux"}, {"name": "proc_status", "ok": readable("/proc/self/status")}, {"name": "proc_mountinfo", "ok": readable("/proc/self/mountinfo")}}
	ok := true
	for _, c := range checks {
		if v, _ := c["ok"].(bool); !v {
			ok = false
		}
	}
	_ = json.NewEncoder(stdout).Encode(map[string]any{"tool": "trustfall", "ready": ok, "checks": checks})
	if !ok {
		return exitOperational
	}
	return exitOK
}
func readable(path string) bool {
	f, e := os.Open(path)
	if e != nil {
		return false
	}
	f.Close()
	return true
}

func assessCommand(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("assess", stderr)
	profile := fs.String("profile", "baseline", "baseline, hardened, or custom")
	policyPath := fs.String("policy", "", "custom policy YAML")
	output := fs.String("output", "-", "JSON/text output path or -")
	sarifPath := fs.String("sarif", "", "SARIF output path")
	summaryPath := fs.String("summary", "", "job summary output path")
	failOn := fs.String("fail-on", "", "enable enforcement at severity threshold")
	timeout := fs.Duration("timeout", 5*time.Second, "timeout per probe")
	format := fs.String("format", "json", "json or text")
	verbose := fs.Bool("verbose", false, "enable debug logs")
	noNetwork := fs.Bool("no-network", false, "disable all network and cloud probes")
	requestOIDC := fs.Bool("request-oidc", false, "request and inspect a GitHub Actions OIDC token")
	oidcAudience := fs.String("oidc-audience", "", "OIDC audience (requires --request-oidc)")
	if fs.Parse(args) != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "assess accepts no positional arguments")
		return exitUsage
	}
	if *timeout <= 0 || *timeout > 5*time.Minute {
		fmt.Fprintln(stderr, "--timeout must be positive and no greater than 5m")
		return exitUsage
	}
	if *oidcAudience != "" && !*requestOIDC {
		fmt.Fprintln(stderr, "--oidc-audience requires --request-oidc")
		return exitUsage
	}
	if len(*oidcAudience) > 255 {
		fmt.Fprintln(stderr, "--oidc-audience must not exceed 255 characters")
		return exitUsage
	}
	if *format != "json" && *format != "text" {
		fmt.Fprintln(stderr, "--format must be json or text")
		return exitUsage
	}
	stdoutOutputs := 0
	for _, path := range []string{*output, *sarifPath, *summaryPath} {
		if path == "-" {
			stdoutOutputs++
		}
	}
	if stdoutOutputs > 1 {
		fmt.Fprintln(stderr, "only one of --output, --sarif, and --summary may write to stdout")
		return exitUsage
	}
	if *output == "" {
		fmt.Fprintln(stderr, "--output must not be empty")
		return exitUsage
	}
	var pol policy.Policy
	var err error
	if *profile == "custom" {
		if *policyPath == "" {
			fmt.Fprintln(stderr, "--profile custom requires --policy")
			return exitUsage
		}
		pol, err = policy.Load(*policyPath)
	} else {
		pol, err = policy.Builtin(*profile)
		if err == nil && *policyPath != "" {
			fmt.Fprintln(stderr, "--policy is only accepted with --profile custom")
			return exitUsage
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "policy error: %v\n", err)
		return exitUsage
	}
	if *failOn != "" {
		severity := evidence.Severity(*failOn)
		if evidence.SeverityRank(severity) == 0 {
			fmt.Fprintf(stderr, "invalid --fail-on severity %q\n", *failOn)
			return exitUsage
		}
		pol.Mode = "enforce"
		pol.FailOn = severity
	}
	if *requestOIDC {
		pol.Identity.RequestOIDC = true
		if *oidcAudience != "" {
			pol.Identity.Audience = *oidcAudience
		}
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: level}))
	probes := []engine.Probe{identity.Probe{}, isolation.Probe{}, credentials.Probe{}, network.Probe{Targets: pol.Network.Targets, Concurrency: pol.Network.Concurrency}, network.MetadataProbe{Enabled: pol.Network.Metadata.Enabled, Providers: pol.Network.Metadata.Providers}, cloud.Probe{Providers: []cloud.Provider{cloud.Azure{Config: pol.Cloud.Azure}}}}
	e := engine.Engine{Probes: probes}
	cfg := engine.Config{Profile: *profile, NoNetwork: *noNetwork, ProbeTimeout: *timeout, Logger: logger, Options: map[string]any{"request_oidc": pol.Identity.RequestOIDC, "oidc_audience": pol.Identity.Audience}}
	report, probeErrors := e.Run(context.Background(), cfg, version, pol.Mode)
	evaluation := pol.Evaluate(&report)
	if err = writeReport(*output, *format, report, stdout); err != nil {
		fmt.Fprintf(stderr, "write report: %v\n", err)
		return exitOperational
	}
	if *sarifPath != "" {
		if err = withOutput(*sarifPath, false, stdout, func(w io.Writer) error { return reporting.WriteSARIF(w, report) }); err != nil {
			fmt.Fprintf(stderr, "write SARIF: %v\n", err)
			return exitOperational
		}
	}
	if *summaryPath != "" {
		if err = withOutput(*summaryPath, true, stdout, func(w io.Writer) error { return reporting.WriteSummary(w, report, evaluation.Violations) }); err != nil {
			fmt.Fprintf(stderr, "write summary: %v\n", err)
			return exitOperational
		}
	}
	for _, e := range probeErrors {
		logger.Error("probe operational error", "error", evidence.SafeError(e))
	}
	if len(probeErrors) > 0 {
		return exitOperational
	}
	if pol.Mode == "enforce" && len(evaluation.Violations) > 0 {
		for _, v := range evaluation.Violations {
			logger.Warn("policy violation", "violation", v)
		}
		return exitPolicy
	}
	return exitOK
}
func writeReport(path, format string, r evidence.Report, stdout io.Writer) error {
	return withOutput(path, false, stdout, func(w io.Writer) error {
		if format == "json" {
			return reporting.WriteJSON(w, r)
		}
		for _, f := range r.Findings {
			if _, e := fmt.Fprintf(w, "%-16s %-8s %-14s %-16s %s\n", f.RuleID, f.Severity, f.Classification, f.Status, f.Observed); e != nil {
				return e
			}
		}
		return nil
	})
}
func withOutput(path string, appendMode bool, stdout io.Writer, fn func(io.Writer) error) error {
	if path == "-" {
		return fn(stdout)
	}
	flags := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}
	f, e := os.OpenFile(path, flags, 0o600)
	if e != nil {
		return e
	}
	if e = fn(f); e != nil {
		f.Close()
		return e
	}
	return f.Close()
}

func compareCommand(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("compare", stderr)
	output := fs.String("output", "-", "output path")
	if fs.Parse(args) != nil {
		return exitUsage
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "compare requires BASELINE.json and CANDIDATE.json")
		return exitUsage
	}
	a, e := readReport(fs.Arg(0))
	if e != nil {
		fmt.Fprintf(stderr, "read baseline: %v\n", e)
		return exitOperational
	}
	b, e := readReport(fs.Arg(1))
	if e != nil {
		fmt.Fprintf(stderr, "read candidate: %v\n", e)
		return exitOperational
	}
	result := compare.Reports(a, b)
	e = withOutput(*output, false, stdout, func(w io.Writer) error { enc := json.NewEncoder(w); enc.SetIndent("", "  "); return enc.Encode(result) })
	if e != nil {
		fmt.Fprintf(stderr, "write comparison: %v\n", e)
		return exitOperational
	}
	return exitOK
}
func readReport(path string) (evidence.Report, error) {
	f, e := os.Open(path)
	if e != nil {
		return evidence.Report{}, e
	}
	defer f.Close()
	return reporting.ReadJSON(f)
}
func validateCommand(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("validate", stderr)
	path := fs.String("policy", "", "policy YAML")
	if fs.Parse(args) != nil {
		return exitUsage
	}
	if *path == "" || fs.NArg() != 0 {
		fmt.Fprintln(stderr, "validate requires --policy PATH")
		return exitUsage
	}
	p, e := policy.Load(*path)
	if e != nil {
		fmt.Fprintf(stderr, "invalid policy: %v\n", e)
		return exitUsage
	}
	fmt.Fprintf(stdout, "valid TrustFall policy version %s (%s mode)\n", p.Version, p.Mode)
	return exitOK
}
