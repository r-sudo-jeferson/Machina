package verify

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

var allowedRootFiles = map[string]struct{}{
	"AGENTS.md": {},
	"README.md": {},
}

var allowedRootDirs = map[string]struct{}{
	".github": {},
	"job":     {},
}

// VerifyRepository enforces the public construction repository boundary and
// repository-owned language restrictions. It fails closed on the first
// offending artifact and never mutates the repository.
func VerifyRepository(root string) error {
	if strings.TrimSpace(root) == "" {
		return errors.New("repository root is required")
	}

	if err := verifyBoundary(root); err != nil {
		return err
	}
	return verifyNoPython(root)
}

func verifyBoundary(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk repository: %w", walkErr)
		}
		if path == root {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("resolve repository path %q: %w", path, err)
		}
		rel = filepath.ToSlash(rel)

		parts := strings.Split(rel, "/")
		top := parts[0]
		if top == ".git" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if len(parts) == 1 && !entry.IsDir() {
			if _, ok := allowedRootFiles[top]; ok {
				return nil
			}
			return fmt.Errorf("repository boundary violation: product or unsupported root artifact %q must live under /job", rel)
		}

		if _, ok := allowedRootDirs[top]; !ok {
			// Git does not track empty directories. Continue through an invalid
			// directory so the error identifies the concrete tracked artifact,
			// not merely its first path segment.
			if entry.IsDir() {
				return nil
			}
			return fmt.Errorf("repository boundary violation: path %q is outside allowed /job or provider metadata boundary", rel)
		}

		return nil
	})
}
