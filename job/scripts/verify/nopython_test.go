package verify

import (
	"strings"
	"testing"
)

func TestVerifyRepositoryRejectsPythonSourceArtifacts(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRepoFiles(t, root, map[string]string{
		"AGENTS.md":              "contract\n",
		"README.md":              "Machina\n",
		"job/tools/migrate.py":   "print('forbidden')\n",
	})

	err := VerifyRepository(root)
	if err == nil {
		t.Fatal("VerifyRepository() accepted .py artifact")
	}
	if !strings.Contains(err.Error(), "job/tools/migrate.py") {
		t.Fatalf("error %q does not identify Python artifact", err)
	}
}

func TestVerifyRepositoryRejectsPythonShebang(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRepoFiles(t, root, map[string]string{
		"AGENTS.md":            "contract\n",
		"README.md":            "Machina\n",
		"job/scripts/check":     "#!/usr/bin/env python3\nprint('forbidden')\n",
	})

	err := VerifyRepository(root)
	if err == nil {
		t.Fatal("VerifyRepository() accepted Python shebang")
	}
	if !strings.Contains(err.Error(), "job/scripts/check") {
		t.Fatalf("error %q does not identify Python shebang artifact", err)
	}
}

func TestVerifyRepositoryRejectsPythonInvocationInWorkflow(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"python":  "name: ci\njobs:\n  bad:\n    steps:\n      - run: python job/tools/check\n",
		"python3": "name: ci\njobs:\n  bad:\n    steps:\n      - run: |\n          python3 job/tools/check\n",
	}

	for name, workflow := range cases {
		name, workflow := name, workflow
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeRepoFiles(t, root, map[string]string{
				"AGENTS.md":                "contract\n",
				"README.md":                "Machina\n",
				".github/workflows/ci.yml": workflow,
			})

			err := VerifyRepository(root)
			if err == nil {
				t.Fatalf("VerifyRepository() accepted %s invocation in workflow", name)
			}
			if !strings.Contains(err.Error(), ".github/workflows/ci.yml") {
				t.Fatalf("error %q does not identify workflow", err)
			}
		})
	}
}

func TestVerifyRepositoryRejectsPythonBaseImage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRepoFiles(t, root, map[string]string{
		"AGENTS.md":                    "contract\n",
		"README.md":                    "Machina\n",
		"job/deploy/containers/Dockerfile": "FROM python:3.13-alpine\n",
	})

	err := VerifyRepository(root)
	if err == nil {
		t.Fatal("VerifyRepository() accepted Python container base image")
	}
	if !strings.Contains(err.Error(), "job/deploy/containers/Dockerfile") {
		t.Fatalf("error %q does not identify Dockerfile", err)
	}
}

func TestVerifyRepositoryAllowsDocumentationThatMentionsPythonProhibition(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRepoFiles(t, root, map[string]string{
		"AGENTS.md":                       "contract\n",
		"README.md":                       "Machina\n",
		"job/docs/engineering/policy.md":   "Python is prohibited in repository-owned tooling.\n",
	})

	if err := VerifyRepository(root); err != nil {
		t.Fatalf("VerifyRepository() rejected harmless documentation mention: %v", err)
	}
}
