package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidOIDCClientConfig        = errors.New("invalid OIDC client configuration")
	ErrMissingOIDCAuthorizationInput = errors.New("missing OIDC authorization input")
	ErrOIDCClientNotConfigured       = errors.New("OIDC client is not configured")
)

type OIDCClientConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

type OIDCClient struct {
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

func NewOIDCClient(ctx context.Context, cfg OIDCClientConfig) (*OIDCClient, error) {
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURI == "" {
		return nil, ErrInvalidOIDCClientConfig
	}
	if _, err := parseSafeRedirectURL(cfg.RedirectURI); err != nil {
		return nil, fmt.Errorf("%w: redirect URI: %v", ErrInvalidOIDCClientConfig, err)
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider: %w", err)
	}

	scopes := append([]string(nil), cfg.Scopes...)
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}
	} else if !containsString(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  cfg.RedirectURI,
		Scopes:       scopes,
	}
	return &OIDCClient{
		oauth2Config: oauth2Config,
		verifier:     provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

func (c *OIDCClient) AuthorizationURL(state, nonce, pkceChallenge string) (string, error) {
	if state == "" || nonce == "" || pkceChallenge == "" {
		return "", ErrMissingOIDCAuthorizationInput
	}
	if c == nil || c.oauth2Config == nil {
		return "", ErrOIDCClientNotConfigured
	}

	return c.oauth2Config.AuthCodeURL(
		state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
