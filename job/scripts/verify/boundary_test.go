package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyRepositoryAcceptsProductOnlyUnderJobAndProviderMetadata(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRepoFiles(t, root, map[string]string{
		"AGENTS.md":                  "repository contract\n",
		"README.md":                  "Machina\n",
		".github/workflows/ci.yml":   "name: ci\n",
		"job/cmd/api/main.go":        "package main\n",
		"job/contracts/platform.yml": "openapi: 3.1.1\n",
	})

	if err := VerifyRepository(root); err != nil {
		t.Fatalf("VerifyRepository() returned error for valid tree: %v", err)
	}
}

func TestVerifyRepositoryRejectsProductOutsideJob(t *testing.T) {
	t.Parallel()

	cases := []string{
		"cmd/api/main.go",
		"internal/tenant/service.go",
		"package.json",
		"deploy/main.tf",
		"tests/isolation.test.ts",
	}

	for _, path := range cases {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeRepoFiles(t, root, map[string]string{
				"AGENTS.md": "contract\n",
				"README.md": "Machina\n",
				path:        "product artifact\n",
			})

			err := VerifyRepository(root)
			if err == nil {
				t.Fatalf("VerifyRepository() accepted product outside /job: %s", path)
			}
			if !strings.Contains(err.Error(), path) {
				t.Fatalf("error %q does not identify offending path %q", err, path)
			}
		})
	}
}

func TestVerifyRepositoryRejectsForgeControlPlaneNamespace(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRepoFiles(t, root, map[string]string{
		"AGENTS.md":                    "contract\n",
		"README.md":                    "Machina\n",
		".forge/private/evidence.json": "{}\n",
	})

	err := VerifyRepository(root)
	if err == nil {
		t.Fatal("VerifyRepository() accepted prohibited .forge control-plane material")
	}
	if !strings.Contains(err.Error(), ".forge/private/evidence.json") {
		t.Fatalf("error %q does not identify prohibited path", err)
	}
}

func writeRepoFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for path, content := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}
