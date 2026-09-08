package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var ErrInvalidVerifiedOIDCIdentity = errors.New("invalid verified OIDC identity")

type subjectQueries interface {
	UpsertSubject(context.Context, sqlcgen.UpsertSubjectParams) (pgtype.UUID, error)
}

type SubjectStore struct {
	queries subjectQueries
}

func NewSubjectStore(queries subjectQueries) *SubjectStore {
	return &SubjectStore{queries: queries}
}

func (s *SubjectStore) UpsertVerifiedIdentity(
	ctx context.Context,
	candidateID pgtype.UUID,
	identity VerifiedOIDCIdentity,
) (pgtype.UUID, error) {
	if s == nil || s.queries == nil || !candidateID.Valid {
		return pgtype.UUID{}, ErrInvalidVerifiedOIDCIdentity
	}
	if strings.TrimSpace(identity.Subject) == "" {
		return pgtype.UUID{}, ErrInvalidVerifiedOIDCIdentity
	}

	displayName := strings.TrimSpace(identity.Name)
	if displayName == "" {
		displayName = identity.Subject
	}
	if utf8.RuneCountInString(displayName) < 1 || utf8.RuneCountInString(displayName) > 160 {
		return pgtype.UUID{}, ErrInvalidVerifiedOIDCIdentity
	}

	subjectID, err := s.queries.UpsertSubject(ctx, sqlcgen.UpsertSubjectParams{
		SubjectID:       candidateID,
		ExternalSubject: identity.Subject,
		DisplayName:     displayName,
	})
	if err != nil {
		return pgtype.UUID{}, fmt.Errorf("upsert verified OIDC subject: %w", err)
	}
	if !subjectID.Valid {
		return pgtype.UUID{}, ErrInvalidVerifiedOIDCIdentity
	}
	return subjectID, nil
}
