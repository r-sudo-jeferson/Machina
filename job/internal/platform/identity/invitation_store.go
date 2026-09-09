package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var (
	ErrMissingInvitationToken   = errors.New("missing invitation token")
	ErrInvalidInvitationSubject = errors.New("invalid invitation subject")
)

type invitationQueries interface {
	AcceptInvitation(context.Context, sqlcgen.AcceptInvitationParams) (sqlcgen.AcceptInvitationRow, error)
}

type InvitationStore struct {
	queries invitationQueries
}

func NewInvitationStore(queries invitationQueries) *InvitationStore {
	return &InvitationStore{queries: queries}
}

func (s *InvitationStore) Accept(
	ctx context.Context,
	presentedToken string,
	subjectID pgtype.UUID,
) (sqlcgen.AcceptInvitationRow, error) {
	if s == nil || s.queries == nil || !subjectID.Valid {
		return sqlcgen.AcceptInvitationRow{}, ErrInvalidInvitationSubject
	}
	if presentedToken == "" {
		return sqlcgen.AcceptInvitationRow{}, ErrMissingInvitationToken
	}

	tokenHash := HashToken(presentedToken)
	row, err := s.queries.AcceptInvitation(ctx, sqlcgen.AcceptInvitationParams{
		TokenHash: tokenHash[:],
		SubjectID: subjectID,
	})
	if err != nil {
		return sqlcgen.AcceptInvitationRow{}, fmt.Errorf("accept invitation: %w", err)
	}
	return row, nil
}
