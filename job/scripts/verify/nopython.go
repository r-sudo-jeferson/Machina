package verify

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var prohibitedPythonBasenames = map[string]struct{}{
	".python-version":  {},
	"pipfile":          {},
	"pipfile.lock":     {},
	"poetry.lock":      {},
	"pyproject.toml":   {},
	"pytest.ini":       {},
	"requirements.txt": {},
	"setup.cfg":        {},
	"tox.ini":          {},
	"uv.lock":          {},
}

var pythonCommandPattern = regexp.MustCompile(`(?i)(?:^|[;&|]\s*|run:\s*|["']\s*)(?:(?:env|sudo)\s+)*python(?:3(?:\.\d+)*)?(?:\s|$)`)

func verifyNoPython(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk repository for no-Python policy: %w", walkErr)
		}
		if path == root || entry.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("resolve repository path %q: %w", path, err)
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, ".git/") {
			return nil
		}

		lowerName := strings.ToLower(entry.Name())
		ext := strings.ToLower(filepath.Ext(lowerName))
		if ext == ".py" || ext == ".pyi" || ext == ".pyw" {
			return fmt.Errorf("no-Python policy violation: prohibited Python artifact %q", rel)
		}
		if _, prohibited := prohibitedPythonBasenames[lowerName]; prohibited {
			return fmt.Errorf("no-Python policy violation: prohibited Python ecosystem artifact %q", rel)
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %q for no-Python policy: %w", rel, err)
		}
		if hasPythonShebang(content) {
			return fmt.Errorf("no-Python policy violation: Python shebang in %q", rel)
		}
		if isWorkflow(rel) && hasPythonCommand(content) {
			return fmt.Errorf("no-Python policy violation: Python invocation in workflow %q", rel)
		}
		if isOperationalScript(rel, entry.Name()) && hasPythonCommand(content) {
			return fmt.Errorf("no-Python policy violation: Python invocation in operational artifact %q", rel)
		}
		if isContainerFile(entry.Name()) && hasPythonBaseImage(content) {
			return fmt.Errorf("no-Python policy violation: Python base image in %q", rel)
		}

		return nil
	})
}

func hasPythonShebang(content []byte) bool {
	first, _, _ := strings.Cut(string(content), "\n")
	first = strings.ToLower(strings.TrimSpace(first))
	if !strings.HasPrefix(first, "#!") {
		return false
	}
	return strings.Contains(first, "/python") || strings.Contains(first, "env python")
}

func hasPythonCommand(content []byte) bool {
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if pythonCommandPattern.MatchString(line) {
			return true
		}
	}
	return false
}

func isWorkflow(rel string) bool {
	lower := strings.ToLower(rel)
	return strings.HasPrefix(lower, ".github/workflows/") && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml"))
}

func isOperationalScript(rel, name string) bool {
	lowerRel := strings.ToLower(rel)
	lowerName := strings.ToLower(name)
	if strings.Contains(lowerRel, "/scripts/") || strings.HasPrefix(lowerRel, "job/scripts/") {
		return true
	}
	if lowerName == "makefile" || lowerName == "taskfile.yml" || lowerName == "taskfile.yaml" || lowerName == "package.json" {
		return true
	}
	for _, ext := range []string{".sh", ".bash", ".zsh", ".fish"} {
		if strings.HasSuffix(lowerName, ext) {
			return true
		}
	}
	return false
}

func isContainerFile(name string) bool {
	lower := strings.ToLower(name)
	return lower == "dockerfile" || lower == "containerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasPrefix(lower, "containerfile.")
}

func hasPythonBaseImage(content []byte) bool {
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "FROM") {
			continue
		}
		idx := 1
		for idx < len(fields) && strings.HasPrefix(fields[idx], "--") {
			idx++
		}
		if idx >= len(fields) {
			continue
		}
		image := strings.ToLower(fields[idx])
		if image == "python" || strings.HasPrefix(image, "python:") || strings.HasSuffix(image, "/python") || strings.Contains(image, "/python:") {
			return true
		}
	}
	return false
}
