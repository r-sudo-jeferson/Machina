package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	ErrOIDCSecretCollision      = errors.New("OIDC secret collision")
	ErrInvalidRedirectAllowlist = errors.New("invalid redirect allowlist")
	ErrRedirectNotAllowed       = errors.New("redirect URL is not allowlisted")
)

type OIDCSecrets struct {
	State         string
	Nonce         string
	PKCEVerifier  string
	PKCEChallenge string
}

type RedirectAllowlist struct {
	allowed map[string]struct{}
}

func NewOIDCSecrets() (OIDCSecrets, error) {
	state, _, err := NewOpaqueToken()
	if err != nil {
		return OIDCSecrets{}, err
	}
	nonce, _, err := NewOpaqueToken()
	if err != nil {
		return OIDCSecrets{}, err
	}
	verifier, _, err := NewOpaqueToken()
	if err != nil {
		return OIDCSecrets{}, err
	}
	if state == nonce || state == verifier || nonce == verifier {
		return OIDCSecrets{}, ErrOIDCSecretCollision
	}

	digest := sha256.Sum256([]byte(verifier))
	return OIDCSecrets{
		State:         state,
		Nonce:         nonce,
		PKCEVerifier:  verifier,
		PKCEChallenge: base64.RawURLEncoding.EncodeToString(digest[:]),
	}, nil
}

func NewRedirectAllowlist(values []string) (*RedirectAllowlist, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("%w: no redirect URLs configured", ErrInvalidRedirectAllowlist)
	}

	allowed := make(map[string]struct{}, len(values))
	for _, rawURL := range values {
		parsed, err := parseSafeRedirectURL(rawURL)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidRedirectAllowlist, rawURL, err)
		}
		allowed[parsed.String()] = struct{}{}
	}
	return &RedirectAllowlist{allowed: allowed}, nil
}

func (p *RedirectAllowlist) Validate(rawURL string) error {
	if p == nil || len(p.allowed) == 0 {
		return ErrRedirectNotAllowed
	}

	parsed, err := parseSafeRedirectURL(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRedirectNotAllowed, err)
	}
	if _, ok := p.allowed[parsed.String()]; !ok {
		return ErrRedirectNotAllowed
	}
	return nil
}

func parseSafeRedirectURL(rawURL string) (*url.URL, error) {
	if strings.TrimSpace(rawURL) == "" || rawURL != strings.TrimSpace(rawURL) {
		return nil, errors.New("redirect URL must be non-empty and contain no surrounding whitespace")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse redirect URL: %w", err)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return nil, errors.New("redirect URL must be absolute")
	}
	if parsed.User != nil {
		return nil, errors.New("redirect URL must not contain userinfo")
	}
	if parsed.Fragment != "" {
		return nil, errors.New("redirect URL must not contain a fragment")
	}
	if strings.Contains(parsed.Hostname(), "*") {
		return nil, errors.New("redirect URL must not contain wildcards")
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return parsed, nil
	case "http":
		if isLoopbackHost(parsed.Hostname()) {
			return parsed, nil
		}
		return nil, errors.New("plain HTTP redirect is allowed only for loopback hosts")
	default:
		return nil, errors.New("redirect URL scheme is not allowed")
	}
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
