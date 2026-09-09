package keycloaktest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	previewRealmName        = "machina-preview"
	previewClientID         = "machina-web"
	clientSecretPlaceholder = "${MACHINA_KEYCLOAK_CLIENT_SECRET}"
	redirectURIPlaceholder  = "${MACHINA_KEYCLOAK_REDIRECT_URI}"
)

type realmConfig struct {
	Realm               string         `json:"realm"`
	Enabled             bool           `json:"enabled"`
	RegistrationAllowed bool           `json:"registrationAllowed"`
	Clients             []clientConfig `json:"clients"`
	Users               []any          `json:"users"`
}

type clientConfig struct {
	ClientID                  string            `json:"clientId"`
	Protocol                  string            `json:"protocol"`
	Enabled                   bool              `json:"enabled"`
	PublicClient              bool              `json:"publicClient"`
	ClientAuthenticatorType   string            `json:"clientAuthenticatorType"`
	Secret                    string            `json:"secret"`
	StandardFlowEnabled       bool              `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool              `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool              `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool              `json:"serviceAccountsEnabled"`
	FullScopeAllowed          bool              `json:"fullScopeAllowed"`
	RedirectURIs              []string          `json:"redirectUris"`
	WebOrigins                []string          `json:"webOrigins"`
	Attributes                map[string]string `json:"attributes"`
}

type toolchainLock struct {
	PlatformDependencies struct {
		Keycloak struct {
			Version     string `json:"version"`
			Source      string `json:"source"`
			Image       string `json:"image"`
			ImageDigest string `json:"imageDigest"`
		} `json:"keycloak"`
	} `json:"platformDependencies"`
}

func TestPreviewRealmIsFailClosedAndSecretFree(t *testing.T) {
	realmPath := filepath.Join(jobRoot(t), "deploy", "keycloak", "machina-preview-realm.json")
	raw, err := os.ReadFile(realmPath)
	if err != nil {
		t.Fatalf("read preview realm: %v", err)
	}

	var realm realmConfig
	if err := json.Unmarshal(raw, &realm); err != nil {
		t.Fatalf("decode preview realm: %v", err)
	}
	if realm.Realm != previewRealmName || !realm.Enabled {
		t.Fatalf("realm identity/enabled = %q/%v, want %q/true", realm.Realm, realm.Enabled, previewRealmName)
	}
	if realm.RegistrationAllowed {
		t.Fatal("preview realm enabled uncontrolled self-registration")
	}
	if len(realm.Users) != 0 {
		t.Fatal("preview realm committed users; integration identities must be ephemeral")
	}
	if len(realm.Clients) != 1 {
		t.Fatalf("preview realm clients = %d, want exactly one S001 BFF client", len(realm.Clients))
	}

	client := realm.Clients[0]
	if client.ClientID != previewClientID || client.Protocol != "openid-connect" || !client.Enabled {
		t.Fatalf("preview client identity/protocol/enabled = %q/%q/%v", client.ClientID, client.Protocol, client.Enabled)
	}
	if client.PublicClient || client.ClientAuthenticatorType != "client-secret" {
		t.Fatalf("preview client confidentiality = public:%v authenticator:%q", client.PublicClient, client.ClientAuthenticatorType)
	}
	if client.Secret != clientSecretPlaceholder {
		t.Fatalf("preview client secret must be the runtime placeholder %q", clientSecretPlaceholder)
	}
	if !client.StandardFlowEnabled || client.ImplicitFlowEnabled || client.DirectAccessGrantsEnabled || client.ServiceAccountsEnabled {
		t.Fatalf("preview client flows = standard:%v implicit:%v direct:%v service:%v", client.StandardFlowEnabled, client.ImplicitFlowEnabled, client.DirectAccessGrantsEnabled, client.ServiceAccountsEnabled)
	}
	if client.FullScopeAllowed {
		t.Fatal("preview client enabled fullScopeAllowed")
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != redirectURIPlaceholder {
		t.Fatalf("preview redirect URIs = %#v, want exact runtime placeholder", client.RedirectURIs)
	}
	if len(client.WebOrigins) != 0 {
		t.Fatalf("BFF preview client unexpectedly exposes browser web origins: %#v", client.WebOrigins)
	}
	if client.Attributes["pkce.code.challenge.method"] != "S256" {
		t.Fatalf("preview client PKCE method = %q, want S256", client.Attributes["pkce.code.challenge.method"])
	}
	if strings.Contains(string(raw), "client-secret-value") || strings.Contains(string(raw), "password-value") {
		t.Fatal("preview realm contains a committed credential sentinel")
	}
}

func TestKeycloakOCIImageIsVersionAndDigestLocked(t *testing.T) {
	lockPath := filepath.Join(jobRoot(t), "toolchains.lock.json")
	raw, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read toolchain lock: %v", err)
	}
	var lock toolchainLock
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatalf("decode toolchain lock: %v", err)
	}

	keycloak := lock.PlatformDependencies.Keycloak
	if keycloak.Version != "26.7.3" || keycloak.Source != "keycloak.org" {
		t.Fatalf("Keycloak version/source = %q/%q, want 26.7.3/keycloak.org", keycloak.Version, keycloak.Source)
	}
	if keycloak.Image != "quay.io/keycloak/keycloak" {
		t.Fatalf("Keycloak OCI image = %q, want official Quay image", keycloak.Image)
	}
	if !strings.HasPrefix(keycloak.ImageDigest, "sha256:") || len(keycloak.ImageDigest) != len("sha256:")+64 {
		t.Fatalf("Keycloak OCI digest = %q, want full sha256 digest", keycloak.ImageDigest)
	}
	for _, r := range strings.TrimPrefix(keycloak.ImageDigest, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("Keycloak OCI digest contains non-lowercase-hex rune %q", r)
		}
	}
}

func TestKeycloakHarnessExercisesRealOutageAndSameContainerRestart(t *testing.T) {
	scriptPath := filepath.Join(jobRoot(t), "scripts", "keycloaktest", "run.sh")
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read Keycloak integration harness: %v", err)
	}
	script := string(raw)

	required := []string{
		`docker stop --timeout 15 "$CONTAINER"`,
		`docker start "$CONTAINER"`,
		`MACHINA_EXPECT_KEYCLOAK_UNAVAILABLE=1`,
		`container_id="$(docker inspect "$CONTAINER" --format '{{.Id}}')"`,
		`restarted_container_id="$(docker inspect "$CONTAINER" --format '{{.Id}}')"`,
		`[[ "$restarted_container_id" == "$container_id" ]]`,
		`wait_for_keycloak_ready 'restart'`,
		`^TestKeycloakOIDC(ProviderIntegration|AuthorizationCodePKCEIntegration)$`,
	}
	for _, fragment := range required {
		if !strings.Contains(script, fragment) {
			t.Fatalf("Keycloak integration harness is missing reliability invariant %q", fragment)
		}
	}

	if strings.Contains(script, `docker run --detach --rm \
  --name "$CONTAINER"`) {
		t.Fatal("Keycloak provider container uses --rm and cannot prove restart of the same container identity")
	}
	if !strings.Contains(script, `docker run --detach \
  --name "$CONTAINER"`) {
		t.Fatal("Keycloak provider container is not explicitly retained for bounded restart evidence")
	}
	if strings.Contains(script, "GITHUB_TOKEN") || strings.Contains(script, "ghp_") || strings.Contains(script, "github_pat_") {
		t.Fatal("Keycloak integration harness contains repository credential material")
	}
}

func jobRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve config test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}
