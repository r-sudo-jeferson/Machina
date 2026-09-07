package contracts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bufbuild/protocompile"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	openAPIPath       = "contracts/openapi/platform.yaml"
	authzProtoPath    = "contracts/proto/authz/v1/authz.proto"
	contextInputPath  = "contracts/ai/context-tool.schema.json"
	contextResultPath = "contracts/ai/context-tool.result.schema.json"
	eventEnvelopePath = "contracts/events/v1/envelope.schema.json"
	coreManifestPath  = "contracts/modules/core.manifest.json"
)

func ValidateAll(jobRoot string) error {
	if err := validateOpenAPI(filepath.Join(jobRoot, openAPIPath)); err != nil {
		return fmt.Errorf("OpenAPI contract: %w", err)
	}
	if err := validateAuthzProto(filepath.Join(jobRoot, "contracts", "proto")); err != nil {
		return fmt.Errorf("authorization protobuf contract: %w", err)
	}
	for _, rel := range []string{contextInputPath, contextResultPath, eventEnvelopePath} {
		if err := validateJSONSchema(filepath.Join(jobRoot, rel)); err != nil {
			return fmt.Errorf("JSON Schema %s: %w", rel, err)
		}
	}
	if err := validateCoreManifest(filepath.Join(jobRoot, coreManifestPath)); err != nil {
		return fmt.Errorf("core manifest: %w", err)
	}

	// The Ask tool must remain server-context-owned. This sentinel is part of
	// contract validation so a future schema change cannot silently admit a
	// caller-controlled tenant selector.
	if err := ValidateJSONSchemaInstance(filepath.Join(jobRoot, contextInputPath), map[string]any{
		"question":  "Where am I?",
		"tenant_id": "00000000-0000-0000-0000-000000000999",
	}); err == nil {
		return fmt.Errorf("context tool input permits caller-controlled tenant_id")
	}

	return nil
}

func ValidateJSONSchemaInstance(schemaPath string, instance any) error {
	schema, err := compileLocalJSONSchema(schemaPath)
	if err != nil {
		return err
	}
	if err := schema.Validate(instance); err != nil {
		return fmt.Errorf("instance validation: %w", err)
	}
	return nil
}

func validateJSONSchema(path string) error {
	_, err := compileLocalJSONSchema(path)
	return err
}

func compileLocalJSONSchema(path string) (*jsonschema.Schema, error) {
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(jsonschema.SchemeURLLoader{
		"file": jsonschema.FileLoader{},
	})
	schema, err := compiler.Compile(path)
	if err != nil {
		return nil, fmt.Errorf("compile %s: %w", filepath.ToSlash(path), err)
	}
	return schema, nil
}

func validateOpenAPI(path string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("validator panic rejected safely: %v", recovered)
		}
	}()

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	doc, err := loader.LoadFromFile(path)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	if doc.OpenAPI != "3.1.1" {
		return fmt.Errorf("openapi version %q; want 3.1.1", doc.OpenAPI)
	}
	if err := doc.Validate(context.Background()); err != nil {
		return fmt.Errorf("validate: %w", err)
	}
	if doc.Components == nil {
		return fmt.Errorf("components are required")
	}
	if _, ok := doc.Components.Schemas["Problem"]; !ok {
		return fmt.Errorf("RFC 9457 Problem schema is required")
	}
	if _, ok := doc.Components.Responses["Problem"]; !ok {
		return fmt.Errorf("RFC 9457 Problem response is required")
	}
	if _, ok := doc.Components.Parameters["IdempotencyKey"]; !ok {
		return fmt.Errorf("Idempotency-Key parameter is required")
	}
	if _, ok := doc.Components.Parameters["CSRFToken"]; !ok {
		return fmt.Errorf("X-CSRF-Token parameter is required")
	}
	if _, ok := doc.Components.Headers["ETag"]; !ok {
		return fmt.Errorf("ETag response header is required")
	}
	if _, ok := doc.Components.SecuritySchemes["sessionCookie"]; !ok {
		return fmt.Errorf("server-side session cookie security scheme is required")
	}

	for _, pathName := range []string{
		"/v1/session",
		"/v1/tenants",
		"/v1/tenant-switch",
		"/v1/invitations/{token}/accept",
		"/v1/context",
		"/v1/ask/context",
	} {
		if doc.Paths == nil || doc.Paths.Value(pathName) == nil {
			return fmt.Errorf("required path %s is missing", pathName)
		}
	}

	for _, pathName := range []string{
		"/v1/tenants",
		"/v1/tenant-switch",
		"/v1/invitations/{token}/accept",
	} {
		operation := doc.Paths.Value(pathName).Post
		if operation == nil {
			return fmt.Errorf("required POST operation %s is missing", pathName)
		}
		if !hasParameterRef(operation.Parameters, "#/components/parameters/IdempotencyKey") {
			return fmt.Errorf("POST %s must require Idempotency-Key", pathName)
		}
		if !hasParameterRef(operation.Parameters, "#/components/parameters/CSRFToken") {
			return fmt.Errorf("POST %s must require X-CSRF-Token", pathName)
		}
	}

	ask := doc.Paths.Value("/v1/ask/context").Post
	if ask == nil || !hasParameterRef(ask.Parameters, "#/components/parameters/CSRFToken") {
		return fmt.Errorf("POST /v1/ask/context must require X-CSRF-Token")
	}

	return nil
}

func hasParameterRef(parameters openapi3.Parameters, ref string) bool {
	for _, parameter := range parameters {
		if parameter != nil && parameter.Ref == ref {
			return true
		}
	}
	return false
}

func validateAuthzProto(protoRoot string) error {
	resolver := protocompile.WithStandardImports(&protocompile.SourceResolver{
		ImportPaths: []string{protoRoot},
	})
	compiler := protocompile.Compiler{Resolver: resolver}
	files, err := compiler.Compile(context.Background(), "authz/v1/authz.proto")
	if err != nil {
		return err
	}
	if len(files) != 1 || files[0] == nil {
		return fmt.Errorf("compiler returned no authorization descriptor")
	}

	fd := files[0]
	service := fd.Services().ByName("AuthorizationService")
	if service == nil || service.Methods().ByName("Decide") == nil {
		return fmt.Errorf("AuthorizationService.Decide is required")
	}

	request := fd.Messages().ByName("DecisionRequest")
	if request == nil {
		return fmt.Errorf("DecisionRequest is required")
	}
	for _, field := range []string{
		"subject_id",
		"tenant_id",
		"workspace_id",
		"action",
		"resource_type",
		"resource_id",
		"required_policy_version",
		"correlation_id",
	} {
		if request.Fields().ByName(protoreflect.Name(field)) == nil {
			return fmt.Errorf("DecisionRequest.%s is required", field)
		}
	}

	response := fd.Messages().ByName("DecisionResponse")
	if response == nil {
		return fmt.Errorf("DecisionResponse is required")
	}
	for _, field := range []string{
		"decision_id",
		"allowed",
		"policy_version",
		"reason_codes",
		"diagnostic_ref",
		"policy_snapshot_hash",
	} {
		if response.Fields().ByName(protoreflect.Name(field)) == nil {
			return fmt.Errorf("DecisionResponse.%s is required", field)
		}
	}
	return nil
}

type coreManifest struct {
	SchemaVersion int      `json:"schemaVersion"`
	ID            string   `json:"id"`
	Version       string   `json:"version"`
	Kind          string   `json:"kind"`
	Capabilities  []string `json:"capabilities"`
	Navigation    []struct {
		ID                 string `json:"id"`
		LabelKey           string `json:"labelKey"`
		Route              string `json:"route"`
		RequiredCapability string `json:"requiredCapability"`
	} `json:"navigation"`
	AskTools []struct {
		ID                 string `json:"id"`
		RiskTier           string `json:"riskTier"`
		ReadOnly           bool   `json:"readOnly"`
		InputSchema        string `json:"inputSchema"`
		ResultSchema       string `json:"resultSchema"`
		RequiredCapability string `json:"requiredCapability"`
	} `json:"askTools"`
}

func validateCoreManifest(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var manifest coreManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return err
	}
	if manifest.SchemaVersion != 1 || manifest.ID != "machina.core" || manifest.Version != "1.0.0" || manifest.Kind != "platform-core" {
		return fmt.Errorf("unexpected core manifest identity")
	}
	for _, capability := range []string{"context.read", "ask.context.read", "tenant.switch"} {
		if !slices.Contains(manifest.Capabilities, capability) {
			return fmt.Errorf("required capability %q is missing", capability)
		}
	}
	if len(manifest.Navigation) != 1 {
		return fmt.Errorf("S001 must expose exactly one core navigation entry, got %d", len(manifest.Navigation))
	}
	nav := manifest.Navigation[0]
	if nav.ID != "context" || nav.LabelKey != "nav.context" || nav.Route != "/context" || nav.RequiredCapability != "context.read" {
		return fmt.Errorf("core context navigation must remain capability-gated and deterministic")
	}
	if len(manifest.AskTools) != 1 {
		return fmt.Errorf("S001 must expose exactly one Ask tool, got %d", len(manifest.AskTools))
	}
	tool := manifest.AskTools[0]
	if tool.ID != "context.read" || tool.RiskTier != "R0" || !tool.ReadOnly || tool.RequiredCapability != "ask.context.read" {
		return fmt.Errorf("context.read Ask tool must remain R0, read-only, and capability-gated")
	}
	if tool.InputSchema != "../ai/context-tool.schema.json" || tool.ResultSchema != "../ai/context-tool.result.schema.json" {
		return fmt.Errorf("context.read Ask tool schema references are invalid")
	}
	return nil
}
