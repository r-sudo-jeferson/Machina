package contracts

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const contractDigestManifestPath = "contracts/checksums.sha256"

var contractDigestPaths = []string{
	"contracts/ai/context-tool.result.schema.json",
	"contracts/ai/context-tool.schema.json",
	"contracts/events/v1/envelope.schema.json",
	"contracts/modules/core.manifest.json",
	"contracts/openapi/platform.yaml",
	"contracts/proto/authz/v1/authz.proto",
}

func ValidateContractDigests(jobRoot string) error {
	manifestPath := filepath.Join(jobRoot, contractDigestManifestPath)
	manifest, err := os.Open(manifestPath)
	if err != nil {
		return fmt.Errorf("open digest manifest: %w", err)
	}
	defer manifest.Close()

	expected, err := parseContractDigestManifest(manifest)
	if err != nil {
		return err
	}

	paths := append([]string(nil), contractDigestPaths...)
	slices.Sort(paths)
	if len(expected) != len(paths) {
		return fmt.Errorf("digest manifest has %d entries; want %d", len(expected), len(paths))
	}

	var violations []error
	for _, rel := range paths {
		want, ok := expected[rel]
		if !ok {
			violations = append(violations, fmt.Errorf("digest manifest missing %s", rel))
			continue
		}
		path := filepath.Join(jobRoot, filepath.FromSlash(rel))
		info, err := os.Lstat(path)
		if err != nil {
			violations = append(violations, fmt.Errorf("stat %s: %w", rel, err))
			continue
		}
		if !info.Mode().IsRegular() {
			violations = append(violations, fmt.Errorf("contract %s is not a regular file", rel))
			continue
		}
		got, err := sha256File(path)
		if err != nil {
			violations = append(violations, fmt.Errorf("hash %s: %w", rel, err))
			continue
		}
		if got != want {
			violations = append(violations, fmt.Errorf("digest mismatch for %s: got %s want %s", rel, got, want))
		}
	}

	for rel := range expected {
		if !slices.Contains(paths, rel) {
			violations = append(violations, fmt.Errorf("digest manifest contains unapproved contract %s", rel))
		}
	}
	return errors.Join(violations...)
}

func parseContractDigestManifest(r io.Reader) (map[string]string, error) {
	entries := make(map[string]string, len(contractDigestPaths))
	scanner := bufio.NewScanner(r)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			return nil, fmt.Errorf("digest manifest line %d is blank", lineNumber)
		}
		parts := strings.Split(line, "  ")
		if len(parts) != 2 || len(parts[0]) != sha256.Size*2 || parts[1] == "" {
			return nil, fmt.Errorf("digest manifest line %d has invalid format", lineNumber)
		}
		digest := strings.ToLower(parts[0])
		if _, err := hex.DecodeString(digest); err != nil {
			return nil, fmt.Errorf("digest manifest line %d has invalid SHA-256: %w", lineNumber, err)
		}
		rel := filepath.ToSlash(filepath.Clean(parts[1]))
		if rel != parts[1] || filepath.IsAbs(parts[1]) || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
			return nil, fmt.Errorf("digest manifest line %d has unsafe path %q", lineNumber, parts[1])
		}
		if _, exists := entries[rel]; exists {
			return nil, fmt.Errorf("digest manifest duplicates %s", rel)
		}
		entries[rel] = digest
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read digest manifest: %w", err)
	}
	if lineNumber == 0 {
		return nil, fmt.Errorf("digest manifest is empty")
	}
	return entries, nil
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
