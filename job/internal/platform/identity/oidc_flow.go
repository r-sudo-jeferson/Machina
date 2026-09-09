package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

const oidcAuthorizationAttemptLifetime = 5 * time.Minute

var (
	ErrOIDCFlowNotConfigured    = errors.New("OIDC flow is not configured")
	ErrMissingOIDCCallbackInput = errors.New("missing OIDC callback input")
	ErrOIDCNonceMismatch        = errors.New("OIDC nonce mismatch")
	ErrInvalidOIDCAttempt       = errors.New("invalid OIDC authorization attempt")
)

type oidcFlowAttemptStore interface {
	Create(context.Context, string, string, string, string, time.Time) error
	Consume(context.Context, string) (sqlcgen.ConsumeOIDCAuthorizationAttemptRow, error)
}

type oidcFlowClient interface {
	AuthorizationURL(string, string, string) (string, error)
	ExchangeAndVerify(context.Context, string, string) (VerifiedOIDCIdentity, error)
}

type OIDCFlow struct {
	attempts   oidcFlowAttemptStore
	client     oidcFlowClient
	redirects  *RedirectAllowlist
	now        func() time.Time
	newSecrets func() (OIDCSecrets, error)
}

type OIDCFlowResult struct {
	Identity    VerifiedOIDCIdentity
	RedirectURI string
}

func NewOIDCFlow(attempts oidcFlowAttemptStore, client oidcFlowClient, redirects *RedirectAllowlist) *OIDCFlow {
	return &OIDCFlow{
		attempts:   attempts,
		client:     client,
		redirects:  redirects,
		now:        time.Now,
		newSecrets: NewOIDCSecrets,
	}
}

func (f *OIDCFlow) Begin(ctx context.Context, postLoginRedirect string) (string, error) {
	if !f.configured() {
		return "", ErrOIDCFlowNotConfigured
	}
	if err := f.redirects.Validate(postLoginRedirect); err != nil {
		return "", err
	}

	secrets, err := f.newSecrets()
	if err != nil {
		return "", fmt.Errorf("generate OIDC authorization secrets: %w", err)
	}
	authorizationURL, err := f.client.AuthorizationURL(secrets.State, secrets.Nonce, secrets.PKCEChallenge)
	if err != nil {
		return "", fmt.Errorf("build OIDC authorization URL: %w", err)
	}

	expiresAt := f.now().UTC().Add(oidcAuthorizationAttemptLifetime)
	if err := f.attempts.Create(
		ctx,
		secrets.State,
		secrets.Nonce,
		secrets.PKCEVerifier,
		postLoginRedirect,
		expiresAt,
	); err != nil {
		return "", fmt.Errorf("persist OIDC authorization attempt: %w", err)
	}
	return authorizationURL, nil
}

func (f *OIDCFlow) Complete(ctx context.Context, state, code string) (OIDCFlowResult, error) {
	if !f.configured() {
		return OIDCFlowResult{}, ErrOIDCFlowNotConfigured
	}
	if state == "" || code == "" {
		return OIDCFlowResult{}, ErrMissingOIDCCallbackInput
	}

	attempt, err := f.attempts.Consume(ctx, state)
	if err != nil {
		return OIDCFlowResult{}, fmt.Errorf("consume OIDC authorization attempt: %w", err)
	}
	if err := f.redirects.Validate(attempt.RedirectUri); err != nil {
		return OIDCFlowResult{}, err
	}
	if len(attempt.NonceHash) != sha256.Size || attempt.PkceVerifier == "" {
		return OIDCFlowResult{}, ErrInvalidOIDCAttempt
	}

	verified, err := f.client.ExchangeAndVerify(ctx, code, attempt.PkceVerifier)
	if err != nil {
		return OIDCFlowResult{}, fmt.Errorf("exchange and verify OIDC callback: %w", err)
	}
	verifiedNonceHash := HashToken(verified.Nonce)
	if subtle.ConstantTimeCompare(verifiedNonceHash[:], attempt.NonceHash) != 1 {
		return OIDCFlowResult{}, ErrOIDCNonceMismatch
	}

	return OIDCFlowResult{
		Identity:    verified,
		RedirectURI: attempt.RedirectUri,
	}, nil
}

func (f *OIDCFlow) configured() bool {
	return f != nil && f.attempts != nil && f.client != nil && f.redirects != nil && f.now != nil && f.newSecrets != nil
}
