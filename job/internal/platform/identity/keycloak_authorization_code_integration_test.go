package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
	"golang.org/x/net/html"
)

const (
	keycloakIntegrationPostLoginRedirect = "https://app.example.test/home"
	keycloakIntegrationAdminUsernameEnv   = "MACHINA_KEYCLOAK_ADMIN_USERNAME"
	keycloakIntegrationAdminPasswordEnv   = "MACHINA_KEYCLOAK_ADMIN_PASSWORD"
)

type keycloakOIDCTestAttempt struct {
	row       sqlcgen.ConsumeOIDCAuthorizationAttemptRow
	expiresAt time.Time
}

type keycloakOIDCTestAttemptStore struct {
	mu       sync.Mutex
	attempts map[[32]byte]keycloakOIDCTestAttempt
}

func newKeycloakOIDCTestAttemptStore() *keycloakOIDCTestAttemptStore {
	return &keycloakOIDCTestAttemptStore{attempts: make(map[[32]byte]keycloakOIDCTestAttempt)}
}

func (s *keycloakOIDCTestAttemptStore) Create(
	ctx context.Context,
	state string,
	nonce string,
	pkceVerifier string,
	redirectURI string,
	expiresAt time.Time,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if state == "" || nonce == "" || pkceVerifier == "" || redirectURI == "" {
		return ErrMissingOIDCAuthorizationAttemptInput
	}

	stateHash := HashToken(state)
	nonceHash := HashToken(nonce)
	attempt := keycloakOIDCTestAttempt{
		row: sqlcgen.ConsumeOIDCAuthorizationAttemptRow{
			NonceHash:    append([]byte(nil), nonceHash[:]...),
			PkceVerifier: pkceVerifier,
			RedirectUri:  redirectURI,
		},
		expiresAt: expiresAt.UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.attempts[stateHash]; exists {
		return errors.New("duplicate OIDC authorization state in test attempt store")
	}
	s.attempts[stateHash] = attempt
	return nil
}

func (s *keycloakOIDCTestAttemptStore) Consume(ctx context.Context, state string) (sqlcgen.ConsumeOIDCAuthorizationAttemptRow, error) {
	if err := ctx.Err(); err != nil {
		return sqlcgen.ConsumeOIDCAuthorizationAttemptRow{}, err
	}
	if state == "" {
		return sqlcgen.ConsumeOIDCAuthorizationAttemptRow{}, ErrMissingOIDCAuthorizationAttemptInput
	}

	stateHash := HashToken(state)
	s.mu.Lock()
	attempt, exists := s.attempts[stateHash]
	if exists {
		delete(s.attempts, stateHash)
	}
	s.mu.Unlock()

	if !exists || !time.Now().UTC().Before(attempt.expiresAt) {
		return sqlcgen.ConsumeOIDCAuthorizationAttemptRow{}, ErrOIDCAuthorizationAttemptUnavailable
	}
	return attempt.row, nil
}

type keycloakCallback struct {
	code  string
	state string
}

func TestKeycloakOIDCAuthorizationCodePKCEIntegration(t *testing.T) {
	if os.Getenv("MACHINA_RUN_KEYCLOAK_INTEGRATION") != "1" {
		t.Skip("MACHINA_RUN_KEYCLOAK_INTEGRATION is not enabled")
	}

	clientSecret := os.Getenv("MACHINA_KEYCLOAK_CLIENT_SECRET")
	adminUsername := os.Getenv(keycloakIntegrationAdminUsernameEnv)
	adminPassword := os.Getenv(keycloakIntegrationAdminPasswordEnv)
	if clientSecret == "" || adminUsername == "" || adminPassword == "" {
		t.Fatal("Keycloak integration credentials are not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := NewOIDCClient(ctx, OIDCClientConfig{
		IssuerURL:    keycloakIntegrationIssuer,
		ClientID:     keycloakIntegrationClientID,
		ClientSecret: clientSecret,
		RedirectURI:  keycloakIntegrationRedirect,
	})
	if err != nil {
		t.Fatalf("create real Keycloak OIDC client: %v", err)
	}
	allowlist, err := NewRedirectAllowlist([]string{keycloakIntegrationPostLoginRedirect})
	if err != nil {
		t.Fatalf("create post-login redirect allowlist: %v", err)
	}
	attempts := newKeycloakOIDCTestAttemptStore()
	flow := NewOIDCFlow(attempts, client, allowlist)

	usernameToken, _, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("generate ephemeral Keycloak username: %v", err)
	}
	userPassword, _, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("generate ephemeral Keycloak password: %v", err)
	}
	username := "machina-ci-" + strings.ToLower(usernameToken[:16])
	email := username + "@example.test"

	adminToken, err := keycloakAdminAccessToken(ctx, adminUsername, adminPassword)
	if err != nil {
		t.Fatalf("obtain ephemeral Keycloak admin access: %v", err)
	}
	if err := createEphemeralKeycloakUser(ctx, adminToken, username, userPassword, email); err != nil {
		t.Fatalf("create runtime-only Keycloak user: %v", err)
	}

	login := func() VerifiedOIDCIdentity {
		t.Helper()

		authorizationURL, err := flow.Begin(ctx, keycloakIntegrationPostLoginRedirect)
		if err != nil {
			t.Fatalf("begin OIDC authorization flow: %v", err)
		}
		callback, err := completeKeycloakBrowserLogin(ctx, authorizationURL, username, userPassword)
		if err != nil {
			t.Fatalf("complete browser login against Keycloak: %v", err)
		}
		result, err := flow.Complete(ctx, callback.state, callback.code)
		if err != nil {
			t.Fatalf("exchange and verify real Keycloak callback: %v", err)
		}
		if result.RedirectURI != keycloakIntegrationPostLoginRedirect {
			t.Fatalf("post-login redirect = %q, want %q", result.RedirectURI, keycloakIntegrationPostLoginRedirect)
		}
		if result.Identity.Subject == "" || result.Identity.Nonce == "" {
			t.Fatalf("verified OIDC identity is incomplete: subject=%t nonce=%t", result.Identity.Subject != "", result.Identity.Nonce != "")
		}
		if result.Identity.Email != email || result.Identity.Name == "" {
			t.Fatalf("verified OIDC claims do not identify the runtime user: email_match=%t name_present=%t", result.Identity.Email == email, result.Identity.Name != "")
		}
		if _, err := attempts.Consume(ctx, callback.state); !errors.Is(err, ErrOIDCAuthorizationAttemptUnavailable) {
			t.Fatalf("authorization state was not single-consume: %v", err)
		}
		return result.Identity
	}

	first := login()
	second := login()
	if first.Subject != second.Subject {
		t.Fatalf("same Keycloak user changed sub across logins")
	}
	if first.Nonce == second.Nonce {
		t.Fatal("independent logins reused the OIDC nonce")
	}
}

func keycloakAdminAccessToken(ctx context.Context, username, password string) (string, error) {
	form := url.Values{
		"client_id":  {"admin-cli"},
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://127.0.0.1:18080/realms/master/protocol/openid-connect/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("build admin token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request admin token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("admin token endpoint returned %s", resp.Status)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode admin token response: %w", err)
	}
	if payload.AccessToken == "" {
		return "", errors.New("admin token response omitted access_token")
	}
	return payload.AccessToken, nil
}

func createEphemeralKeycloakUser(ctx context.Context, adminToken, username, password, email string) error {
	payload := struct {
		Username      string `json:"username"`
		Enabled       bool   `json:"enabled"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"emailVerified"`
		FirstName     string `json:"firstName"`
		LastName      string `json:"lastName"`
		Credentials   []struct {
			Type      string `json:"type"`
			Value     string `json:"value"`
			Temporary bool   `json:"temporary"`
		} `json:"credentials"`
	}{
		Username:      username,
		Enabled:       true,
		Email:         email,
		EmailVerified: true,
		FirstName:     "Machina",
		LastName:      "CI User",
		Credentials: []struct {
			Type      string `json:"type"`
			Value     string `json:"value"`
			Temporary bool   `json:"temporary"`
		}{
			{Type: "password", Value: password, Temporary: false},
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode Keycloak user representation: %w", err)
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://127.0.0.1:18080/admin/realms/machina-preview/users",
		bytes.NewReader(encoded),
	)
	if err != nil {
		return fmt.Errorf("build Keycloak user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("create Keycloak user: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("Keycloak Admin REST user creation returned %s", resp.Status)
	}
	return nil
}

func completeKeycloakBrowserLogin(ctx context.Context, authorizationURL, username, password string) (keycloakCallback, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return keycloakCallback{}, fmt.Errorf("create browser cookie jar: %w", err)
	}
	browser := &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
	}
	browser.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if isKeycloakIntegrationCallback(req.URL) {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return errors.New("too many Keycloak browser redirects")
		}
		return nil
	}

	loginReq, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizationURL, nil)
	if err != nil {
		return keycloakCallback{}, fmt.Errorf("build authorization request: %w", err)
	}
	loginPage, err := browser.Do(loginReq)
	if err != nil {
		return keycloakCallback{}, fmt.Errorf("open Keycloak authorization endpoint: %w", err)
	}
	defer loginPage.Body.Close()
	if loginPage.StatusCode != http.StatusOK {
		return keycloakCallback{}, fmt.Errorf("Keycloak authorization endpoint returned %s", loginPage.Status)
	}

	loginAction, err := keycloakLoginAction(loginPage.Body, loginPage.Request.URL)
	if err != nil {
		return keycloakCallback{}, err
	}
	form := url.Values{
		"username": {username},
		"password": {password},
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, loginAction, strings.NewReader(form.Encode()))
	if err != nil {
		return keycloakCallback{}, fmt.Errorf("build Keycloak login request: %w", err)
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.Header.Set("Origin", "http://127.0.0.1:18080")
	postReq.Header.Set("Referer", loginPage.Request.URL.String())

	callbackResponse, err := browser.Do(postReq)
	if err != nil {
		return keycloakCallback{}, fmt.Errorf("submit Keycloak login form: %w", err)
	}
	defer callbackResponse.Body.Close()
	_, _ = io.Copy(io.Discard, callbackResponse.Body)

	location := callbackResponse.Header.Get("Location")
	if location == "" {
		return keycloakCallback{}, fmt.Errorf("Keycloak login did not redirect to callback: %s", callbackResponse.Status)
	}
	callbackURL, err := callbackResponse.Location()
	if err != nil {
		return keycloakCallback{}, fmt.Errorf("parse Keycloak callback redirect: %w", err)
	}
	if !isKeycloakIntegrationCallback(callbackURL) {
		return keycloakCallback{}, fmt.Errorf("Keycloak login stopped at unexpected redirect host/path")
	}
	query := callbackURL.Query()
	if providerError := query.Get("error"); providerError != "" {
		return keycloakCallback{}, fmt.Errorf("Keycloak authorization returned provider error %q", providerError)
	}
	code := query.Get("code")
	state := query.Get("state")
	if code == "" || state == "" {
		return keycloakCallback{}, errors.New("Keycloak callback omitted authorization code or state")
	}
	return keycloakCallback{code: code, state: state}, nil
}

func keycloakLoginAction(body io.Reader, baseURL *url.URL) (string, error) {
	document, err := html.Parse(body)
	if err != nil {
		return "", fmt.Errorf("parse Keycloak login page: %w", err)
	}

	var action string
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if action != "" {
			return
		}
		if node.Type == html.ElementNode && node.Data == "form" {
			var id string
			var candidate string
			for _, attribute := range node.Attr {
				switch attribute.Key {
				case "id":
					id = attribute.Val
				case "action":
					candidate = attribute.Val
				}
			}
			if id == "kc-form-login" && candidate != "" {
				action = candidate
				return
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(document)
	if action == "" {
		return "", errors.New("Keycloak login form action was not found")
	}
	resolved, err := baseURL.Parse(action)
	if err != nil {
		return "", fmt.Errorf("resolve Keycloak login action: %w", err)
	}
	return resolved.String(), nil
}

func isKeycloakIntegrationCallback(candidate *url.URL) bool {
	return candidate != nil && candidate.Scheme == "http" && candidate.Host == "127.0.0.1:18081" && candidate.Path == "/auth/callback"
}
