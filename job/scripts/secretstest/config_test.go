package secretstest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	gitleaksVersion = "8.30.1"
	gitleaksImage   = "ghcr.io/gitleaks/gitleaks"
	gitleaksDigest  = "sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
)

type toolchainLock struct {
	SecurityTools struct {
		Gitleaks struct {
			Version     string `json:"version"`
			Source      string `json:"source"`
			Image       string `json:"image"`
			ImageDigest string `json:"imageDigest"`
		} `json:"gitleaks"`
	} `json:"securityTools"`
}

func TestGitleaksIsVersionAndDigestLocked(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "job", "toolchains.lock.json"))
	if err != nil {
		t.Fatalf("read toolchains lock: %v", err)
	}
	var lock toolchainLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatalf("decode toolchains lock: %v", err)
	}
	got := lock.SecurityTools.Gitleaks
	if got.Version != gitleaksVersion || got.Source != "gitleaks.io" {
		t.Fatalf("Gitleaks version/source = %q/%q, want %s/gitleaks.io", got.Version, got.Source, gitleaksVersion)
	}
	if got.Image != gitleaksImage || got.ImageDigest != gitleaksDigest {
		t.Fatalf("Gitleaks image lock = %q@%q, want %q@%q", got.Image, got.ImageDigest, gitleaksImage, gitleaksDigest)
	}
}

func TestSecretScanCoversCurrentTreeAndFullGitHistory(t *testing.T) {
	root := repositoryRoot(t)
	scriptRaw, err := os.ReadFile(filepath.Join(root, "job", "scripts", "secretstest", "run.sh"))
	if err != nil {
		t.Fatalf("read secret scan harness: %v", err)
	}
	script := string(scriptRaw)
	for _, required := range []string{
		`gitleaks git`,
		`gitleaks dir`,
		`--redact`,
		`docker pull "$image_ref"`,
		`RepoDigests`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("secret scan harness is missing invariant %q", required)
		}
	}
	if strings.Contains(script, "baseline") || strings.Contains(script, "--exit-code 0") {
		t.Fatal("secret scan harness contains a bypass/baseline path")
	}

	workflowRaw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "verify-secrets.yml"))
	if err != nil {
		t.Fatalf("read secret scan workflow: %v", err)
	}
	workflow := string(workflowRaw)
	for _, required := range []string{
		"permissions:\n  contents: read",
		"fetch-depth: 0",
		"persist-credentials: false",
		"test \"$checked_sha\" = \"$GITHUB_SHA\"",
		"bash job/scripts/secretstest/run.sh",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("secret scan workflow is missing invariant %q", required)
		}
	}
	if strings.Contains(workflow, "secrets.") || strings.Contains(workflow, "GITHUB_TOKEN:") {
		t.Fatal("secret scan workflow depends on injected repository credentials")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve secret scan test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
}
