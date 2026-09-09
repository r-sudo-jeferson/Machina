package verify

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestConstructionRepositorySatisfiesBoundaryAndNoPythonPolicy(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not resolve verifier test path")
	}

	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
	if err := VerifyRepository(repositoryRoot); err != nil {
		t.Fatalf("construction repository violates mandatory policy: %v", err)
	}
}
