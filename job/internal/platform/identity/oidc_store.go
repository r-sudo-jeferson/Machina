package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var (
	ErrMissingOIDCAuthorizationAttemptInput = errors.New("missing OIDC authorization attempt input")
	ErrOIDCAuthorizationAttemptUnavailable  = errors.New("OIDC authorization attempt unavailable")
)

type oidcAuthorizationAttemptQueries interface {
	CreateOIDCAuthorizationAttempt(context.Context, sqlcgen.CreateOIDCAuthorizationAttemptParams) error
	ConsumeOIDCAuthorizationAttempt(context.Context, []byte) (sqlcgen.ConsumeOIDCAuthorizationAttemptRow, error)
}

type OIDCAuthorizationAttemptStore struct {
	queries oidcAuthorizationAttemptQueries
}

func NewOIDCAuthorizationAttemptStore(queries oidcAuthorizationAttemptQueries) *OIDCAuthorizationAttemptStore {
	return &OIDCAuthorizationAttemptStore{queries: queries}
}

func (s *OIDCAuthorizationAttemptStore) Create(
	ctx context.Context,
	state string,
	nonce string,
	pkceVerifier string,
	redirectURI string,
	expiresAt time.Time,
) error {
	if state == "" || nonce == "" || pkceVerifier == "" || redirectURI == "" {
		return ErrMissingOIDCAuthorizationAttemptInput
	}

	stateHash := HashToken(state)
	nonceHash := HashToken(nonce)
	return s.queries.CreateOIDCAuthorizationAttempt(ctx, sqlcgen.CreateOIDCAuthorizationAttemptParams{
		StateHash:    stateHash[:],
		NonceHash:    nonceHash[:],
		PkceVerifier: pkceVerifier,
		RedirectUri:  redirectURI,
		ExpiresAt: pgtype.Timestamptz{
			Time:  expiresAt.UTC(),
			Valid: true,
		},
	})
}

func (s *OIDCAuthorizationAttemptStore) Consume(ctx context.Context, state string) (sqlcgen.ConsumeOIDCAuthorizationAttemptRow, error) {
	if state == "" {
		return sqlcgen.ConsumeOIDCAuthorizationAttemptRow{}, ErrMissingOIDCAuthorizationAttemptInput
	}

	stateHash := HashToken(state)
	attempt, err := s.queries.ConsumeOIDCAuthorizationAttempt(ctx, stateHash[:])
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlcgen.ConsumeOIDCAuthorizationAttemptRow{}, ErrOIDCAuthorizationAttemptUnavailable
		}
		return sqlcgen.ConsumeOIDCAuthorizationAttemptRow{}, fmt.Errorf("consume OIDC authorization attempt: %w", err)
	}
	return attempt, nil
}
