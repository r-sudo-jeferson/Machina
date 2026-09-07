package contracts

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMCHS001ContractSetValidates(t *testing.T) {
	t.Parallel()

	root := jobRoot(t)
	if err := ValidateAll(root); err != nil {
		t.Fatalf("ValidateAll() rejected MCH-S001 contract set: %v", err)
	}
}

func TestContractDigestManifestValidates(t *testing.T) {
	t.Parallel()

	if err := ValidateContractDigests(jobRoot(t)); err != nil {
		t.Fatalf("ValidateContractDigests() rejected canonical contracts: %v", err)
	}
}

func TestContractDigestManifestRejectsTamperedContract(t *testing.T) {
	t.Parallel()

	root := copyContractTree(t)
	path := filepath.Join(root, "contracts", "ai", "context-tool.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ValidateContractDigests(root); err == nil {
		t.Fatal("digest validation accepted a tampered contract")
	}
}

func TestContextToolInputRejectsCallerSuppliedTenantID(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join(jobRoot(t), "contracts", "ai", "context-tool.schema.json")
	instance := map[string]any{
		"question":  "Where am I and what can I do?",
		"tenant_id": "00000000-0000-0000-0000-000000000999",
	}

	err := ValidateJSONSchemaInstance(schemaPath, instance)
	if err == nil {
		t.Fatal("context tool schema accepted caller-controlled tenant_id")
	}
	if !strings.Contains(err.Error(), "tenant_id") && !strings.Contains(err.Error(), "additionalProperties") {
		t.Fatalf("error %q does not explain rejected tenant_id", err)
	}
}

func TestContextToolInputAcceptsReadOnlyQuestion(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join(jobRoot(t), "contracts", "ai", "context-tool.schema.json")
	instance := map[string]any{
		"question": "Where am I and what can I do?",
	}

	if err := ValidateJSONSchemaInstance(schemaPath, instance); err != nil {
		t.Fatalf("context tool schema rejected valid read-only input: %v", err)
	}
}

func TestContextToolInputRejectsUnknownCapability(t *testing.T) {
	t.Parallel()

	schemaPath := filepath.Join(jobRoot(t), "contracts", "ai", "context-tool.schema.json")
	instance := map[string]any{
		"question": "Run a command",
		"command":  "curl https://example.invalid",
	}

	if err := ValidateJSONSchemaInstance(schemaPath, instance); err == nil {
		t.Fatal("context tool schema accepted an undeclared execution capability")
	}
}

func copyContractTree(t *testing.T) string {
	t.Helper()

	source := filepath.Join(jobRoot(t), "contracts")
	root := t.TempDir()
	destination := filepath.Join(root, "contracts")
	if err := os.CopyFS(destination, os.DirFS(source)); err != nil {
		t.Fatalf("copy contracts: %v", err)
	}
	return root
}

func jobRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not resolve contract test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}
