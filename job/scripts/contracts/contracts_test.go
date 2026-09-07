package contracts

import (
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

func jobRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not resolve contract test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}
