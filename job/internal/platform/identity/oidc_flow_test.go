package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingOIDCFlowAttemptStore struct {
	createState    string
	createNonce    string
	createVerifier string
	createRedirect string
	createExpiry   time.Time
	createCalls    int
	createErr      error
	consumeState   string
	consumeCalls   int
	consumeRow     sqlcgen.ConsumeOIDCAuthorizationAttemptRow
	consumeErr     error
}

func (s *recordingOIDCFlowAttemptStore) Create(_ context.Context, state, nonce, verifier, redirectURI string, expiresAt time.Time) error {
	s.createCalls++
	s.createState = state
	s.createNonce = nonce
	s.createVerifier = verifier
	s.createRedirect = redirectURI
	s.createExpiry = expiresAt
	return s.createErr
}

func (s *recordingOIDCFlowAttemptStore) Consume(_ context.Context, state string) (sqlcgen.ConsumeOIDCAuthorizationAttemptRow, error) {
	s.consumeCalls++
	s.consumeState = state
	return s.consumeRow, s.consumeErr
}

type recordingOIDCFlowClient struct {
	authorizationState     string
	authorizationNonce     string
	authorizationChallenge string
	authorizationCalls     int
	authorizationURL       string
	authorizationErr       error
	exchangeCode           string
	exchangeVerifier       string
	exchangeCalls          int
	exchangeIdentity       VerifiedOIDCIdentity
	exchangeErr            error
}

func (c *recordingOIDCFlowClient) AuthorizationURL(state, nonce, challenge string) (string, error) {
	c.authorizationCalls++
	c.authorizationState = state
	c.authorizationNonce = nonce
	c.authorizationChallenge = challenge
	return c.authorizationURL, c.authorizationErr
}

func (c *recordingOIDCFlowClient) ExchangeAndVerify(_ context.Context, code, verifier string) (VerifiedOIDCIdentity, error) {
	c.exchangeCalls++
	c.exchangeCode = code
	c.exchangeVerifier = verifier
	return c.exchangeIdentity, c.exchangeErr
}

func TestOIDCFlowBeginPersistsSecretsAndReturnsAuthorizationURL(t *testing.T) {
	t.Parallel()

	allowlist, err := NewRedirectAllowlist([]string{"https://app.example.test/home"})
	if err != nil {
		t.Fatalf("NewRedirectAllowlist() error = %v", err)
	}
	attempts := &recordingOIDCFlowAttemptStore{}
	client := &recordingOIDCFlowClient{authorizationURL: "https://idp.example.test/authorize?opaque=1"}
	flow := NewOIDCFlow(attempts, client, allowlist)
	flow.now = func() time.Time { return time.Date(2026, 9, 8, 4, 15, 0, 0, time.UTC) }
	flow.newSecrets = func() (OIDCSecrets, error) {
		return OIDCSecrets{
			State:         "browser-state",
			Nonce:         "id-token-nonce",
			PKCEVerifier:  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234",
			PKCEChallenge: "pkce-challenge",
		}, nil
	}

	authorizationURL, err := flow.Begin(context.Background(), "https://app.example.test/home")
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	if authorizationURL != client.authorizationURL {
		t.Fatalf("Begin() URL = %q, want %q", authorizationURL, client.authorizationURL)
	}
	if client.authorizationCalls != 1 || client.authorizationState != "browser-state" || client.authorizationNonce != "id-token-nonce" || client.authorizationChallenge != "pkce-challenge" {
		t.Fatalf("authorization inputs = %#v", client)
	}
	if attempts.createCalls != 1 || attempts.createState != "browser-state" || attempts.createNonce != "id-token-nonce" {
		t.Fatalf("persisted OIDC attempt = %#v", attempts)
	}
	if attempts.createVerifier != "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234" || attempts.createRedirect != "https://app.example.test/home" {
		t.Fatalf("persisted server-side attempt material = %#v", attempts)
	}
	wantExpiry := flow.now().Add(5 * time.Minute)
	if !attempts.createExpiry.Equal(wantExpiry) {
		t.Fatalf("attempt expiry = %v, want %v", attempts.createExpiry, wantExpiry)
	}
}

func TestOIDCFlowBeginRejectsUnallowlistedRedirectBeforeSideEffects(t *testing.T) {
	t.Parallel()

	allowlist, err := NewRedirectAllowlist([]string{"https://app.example.test/home"})
	if err != nil {
		t.Fatalf("NewRedirectAllowlist() error = %v", err)
	}
	attempts := &recordingOIDCFlowAttemptStore{}
	client := &recordingOIDCFlowClient{}
	flow := NewOIDCFlow(attempts, client, allowlist)

	if _, err := flow.Begin(context.Background(), "https://evil.example.test/home"); !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("Begin() error = %v, want ErrRedirectNotAllowed", err)
	}
	if attempts.createCalls != 0 || client.authorizationCalls != 0 {
		t.Fatal("unallowlisted redirect caused OIDC side effects")
	}
}

func TestOIDCFlowCompleteConsumesStateVerifiesNonceAndReturnsStoredRedirect(t *testing.T) {
	t.Parallel()

	allowlist, err := NewRedirectAllowlist([]string{"https://app.example.test/home"})
	if err != nil {
		t.Fatalf("NewRedirectAllowlist() error = %v", err)
	}
	nonceHash := HashToken("verified-nonce")
	attempts := &recordingOIDCFlowAttemptStore{consumeRow: sqlcgen.ConsumeOIDCAuthorizationAttemptRow{
		NonceHash:    nonceHash[:],
		PkceVerifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234",
		RedirectUri:  "https://app.example.test/home",
	}}
	client := &recordingOIDCFlowClient{exchangeIdentity: VerifiedOIDCIdentity{
		Subject: "subject-123",
		Nonce:   "verified-nonce",
		Name:    "Machina User",
		Email:   "user@example.test",
	}}
	flow := NewOIDCFlow(attempts, client, allowlist)

	result, err := flow.Complete(context.Background(), "browser-state", "authorization-code")
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if attempts.consumeCalls != 1 || attempts.consumeState != "browser-state" {
		t.Fatalf("state consumption = %#v", attempts)
	}
	if client.exchangeCalls != 1 || client.exchangeCode != "authorization-code" || client.exchangeVerifier != attempts.consumeRow.PkceVerifier {
		t.Fatalf("token exchange = %#v", client)
	}
	if result.Identity.Subject != "subject-123" || result.RedirectURI != "https://app.example.test/home" {
		t.Fatalf("Complete() = %#v", result)
	}
}

func TestOIDCFlowCompleteFailsClosedOnNonceMismatch(t *testing.T) {
	t.Parallel()

	allowlist, err := NewRedirectAllowlist([]string{"https://app.example.test/home"})
	if err != nil {
		t.Fatalf("NewRedirectAllowlist() error = %v", err)
	}
	storedNonceHash := HashToken("expected-nonce")
	attempts := &recordingOIDCFlowAttemptStore{consumeRow: sqlcgen.ConsumeOIDCAuthorizationAttemptRow{
		NonceHash:    storedNonceHash[:],
		PkceVerifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234",
		RedirectUri:  "https://app.example.test/home",
	}}
	client := &recordingOIDCFlowClient{exchangeIdentity: VerifiedOIDCIdentity{Subject: "subject-123", Nonce: "attacker-nonce"}}
	flow := NewOIDCFlow(attempts, client, allowlist)

	if _, err := flow.Complete(context.Background(), "browser-state", "authorization-code"); !errors.Is(err, ErrOIDCNonceMismatch) {
		t.Fatalf("Complete() error = %v, want ErrOIDCNonceMismatch", err)
	}
}

func TestOIDCFlowCompleteRevalidatesStoredRedirectAndStopsBeforeExchange(t *testing.T) {
	t.Parallel()

	allowlist, err := NewRedirectAllowlist([]string{"https://app.example.test/home"})
	if err != nil {
		t.Fatalf("NewRedirectAllowlist() error = %v", err)
	}
	nonceHash := HashToken("verified-nonce")
	attempts := &recordingOIDCFlowAttemptStore{consumeRow: sqlcgen.ConsumeOIDCAuthorizationAttemptRow{
		NonceHash:    nonceHash[:],
		PkceVerifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234",
		RedirectUri:  "https://evil.example.test/home",
	}}
	client := &recordingOIDCFlowClient{}
	flow := NewOIDCFlow(attempts, client, allowlist)

	if _, err := flow.Complete(context.Background(), "browser-state", "authorization-code"); !errors.Is(err, ErrRedirectNotAllowed) {
		t.Fatalf("Complete() error = %v, want ErrRedirectNotAllowed", err)
	}
	if client.exchangeCalls != 0 {
		t.Fatal("invalid stored redirect reached the OIDC token endpoint")
	}
}

func TestOIDCFlowCompleteDoesNotExchangeWhenStateIsUnavailable(t *testing.T) {
	t.Parallel()

	allowlist, err := NewRedirectAllowlist([]string{"https://app.example.test/home"})
	if err != nil {
		t.Fatalf("NewRedirectAllowlist() error = %v", err)
	}
	attempts := &recordingOIDCFlowAttemptStore{consumeErr: ErrOIDCAuthorizationAttemptUnavailable}
	client := &recordingOIDCFlowClient{}
	flow := NewOIDCFlow(attempts, client, allowlist)

	if _, err := flow.Complete(context.Background(), "replayed-state", "authorization-code"); !errors.Is(err, ErrOIDCAuthorizationAttemptUnavailable) {
		t.Fatalf("Complete() error = %v, want unavailable state", err)
	}
	if client.exchangeCalls != 0 {
		t.Fatal("unavailable/replayed state reached the OIDC token endpoint")
	}
}
