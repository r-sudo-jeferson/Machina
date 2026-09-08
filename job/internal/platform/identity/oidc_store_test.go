package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingOIDCAuthorizationAttemptQueries struct {
	createParams sqlcgen.CreateOIDCAuthorizationAttemptParams
	createCalls  int
	createErr    error
	consumeHash  []byte
	consumeCalls int
	consumeRow   sqlcgen.ConsumeOIDCAuthorizationAttemptRow
	consumeErr   error
}

func (q *recordingOIDCAuthorizationAttemptQueries) CreateOIDCAuthorizationAttempt(_ context.Context, arg sqlcgen.CreateOIDCAuthorizationAttemptParams) error {
	q.createCalls++
	q.createParams = arg
	return q.createErr
}

func (q *recordingOIDCAuthorizationAttemptQueries) ConsumeOIDCAuthorizationAttempt(_ context.Context, stateHash []byte) (sqlcgen.ConsumeOIDCAuthorizationAttemptRow, error) {
	q.consumeCalls++
	q.consumeHash = append([]byte(nil), stateHash...)
	return q.consumeRow, q.consumeErr
}

func TestOIDCAuthorizationAttemptStoreCreateHashesBrowserSecrets(t *testing.T) {
	t.Parallel()

	queries := &recordingOIDCAuthorizationAttemptQueries{}
	store := NewOIDCAuthorizationAttemptStore(queries)
	expiresAt := time.Date(2026, 9, 8, 4, 5, 0, 0, time.UTC)

	err := store.Create(
		context.Background(),
		"presented-state",
		"presented-nonce",
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234",
		"https://app.example.test/auth/callback",
		expiresAt,
	)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if queries.createCalls != 1 {
		t.Fatalf("CreateOIDCAuthorizationAttempt() calls = %d, want 1", queries.createCalls)
	}

	wantStateHash := HashToken("presented-state")
	wantNonceHash := HashToken("presented-nonce")
	if string(queries.createParams.StateHash) != string(wantStateHash[:]) {
		t.Fatal("Create() did not replace presented state with its SHA-256 hash")
	}
	if string(queries.createParams.NonceHash) != string(wantNonceHash[:]) {
		t.Fatal("Create() did not replace presented nonce with its SHA-256 hash")
	}
	if queries.createParams.PkceVerifier != "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234" {
		t.Fatal("Create() changed the server-side PKCE verifier")
	}
	if queries.createParams.RedirectUri != "https://app.example.test/auth/callback" {
		t.Fatal("Create() changed the validated redirect URI")
	}
	if !queries.createParams.ExpiresAt.Valid || !queries.createParams.ExpiresAt.Time.Equal(expiresAt) {
		t.Fatalf("Create() expiry = %#v, want %v", queries.createParams.ExpiresAt, expiresAt)
	}
}

func TestOIDCAuthorizationAttemptStoreConsumeHashesPresentedState(t *testing.T) {
	t.Parallel()

	want := sqlcgen.ConsumeOIDCAuthorizationAttemptRow{
		NonceHash:    []byte("01234567890123456789012345678901"),
		PkceVerifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234",
		RedirectUri:  "https://app.example.test/auth/callback",
	}
	queries := &recordingOIDCAuthorizationAttemptQueries{consumeRow: want}
	store := NewOIDCAuthorizationAttemptStore(queries)

	got, err := store.Consume(context.Background(), "presented-state")
	if err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Consume() = %#v, want %#v", got, want)
	}
	wantStateHash := HashToken("presented-state")
	if string(queries.consumeHash) != string(wantStateHash[:]) {
		t.Fatal("Consume() sent a value other than the state hash to the database boundary")
	}
}

func TestOIDCAuthorizationAttemptStoreFailsClosedOnMissingBrowserSecrets(t *testing.T) {
	t.Parallel()

	expiresAt := time.Now().Add(5 * time.Minute)
	cases := []struct {
		name        string
		state       string
		nonce       string
		verifier    string
		redirectURI string
	}{
		{name: "state", state: "", nonce: "nonce", verifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234", redirectURI: "https://app.example.test/auth/callback"},
		{name: "nonce", state: "state", nonce: "", verifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234", redirectURI: "https://app.example.test/auth/callback"},
		{name: "verifier", state: "state", nonce: "nonce", verifier: "", redirectURI: "https://app.example.test/auth/callback"},
		{name: "redirect", state: "state", nonce: "nonce", verifier: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL01234", redirectURI: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			queries := &recordingOIDCAuthorizationAttemptQueries{}
			store := NewOIDCAuthorizationAttemptStore(queries)
			if err := store.Create(context.Background(), tc.state, tc.nonce, tc.verifier, tc.redirectURI, expiresAt); err == nil {
				t.Fatalf("Create() accepted missing %s", tc.name)
			}
			if queries.createCalls != 0 {
				t.Fatalf("missing %s reached the database boundary", tc.name)
			}
		})
	}

	queries := &recordingOIDCAuthorizationAttemptQueries{}
	store := NewOIDCAuthorizationAttemptStore(queries)
	if _, err := store.Consume(context.Background(), ""); err == nil {
		t.Fatal("Consume() accepted missing state")
	}
	if queries.consumeCalls != 0 {
		t.Fatal("missing OIDC state reached the database boundary")
	}
}

func TestOIDCAuthorizationAttemptStoreHidesReplayAndExpiryAsUnavailable(t *testing.T) {
	t.Parallel()

	queries := &recordingOIDCAuthorizationAttemptQueries{consumeErr: pgx.ErrNoRows}
	store := NewOIDCAuthorizationAttemptStore(queries)

	_, err := store.Consume(context.Background(), "already-consumed-or-expired")
	if !errors.Is(err, ErrOIDCAuthorizationAttemptUnavailable) {
		t.Fatalf("Consume() error = %v, want ErrOIDCAuthorizationAttemptUnavailable", err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("Consume() leaked database no-row semantics across the identity boundary")
	}
}
