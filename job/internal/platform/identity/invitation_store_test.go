package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingInvitationQueries struct {
	acceptParams sqlcgen.AcceptInvitationParams
	acceptCalls  int
	acceptRow    sqlcgen.AcceptInvitationRow
	acceptErr    error
}

func (q *recordingInvitationQueries) AcceptInvitation(_ context.Context, arg sqlcgen.AcceptInvitationParams) (sqlcgen.AcceptInvitationRow, error) {
	q.acceptCalls++
	q.acceptParams = sqlcgen.AcceptInvitationParams{
		TokenHash: append([]byte(nil), arg.TokenHash...),
		SubjectID: arg.SubjectID,
	}
	return q.acceptRow, q.acceptErr
}

func TestInvitationStoreAcceptHashesPresentedTokenAndPassesSubject(t *testing.T) {
	t.Parallel()

	subjectID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	want := sqlcgen.AcceptInvitationRow{
		TenantID:    pgtype.UUID{Bytes: [16]byte{2}, Valid: true},
		SubjectID:   subjectID,
		StarterRole: "operator",
		Status:      "active",
	}
	queries := &recordingInvitationQueries{acceptRow: want}
	store := NewInvitationStore(queries)

	got, err := store.Accept(context.Background(), "presented-invitation-token", subjectID)
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if got != want {
		t.Fatalf("Accept() = %#v, want %#v", got, want)
	}
	if queries.acceptCalls != 1 {
		t.Fatalf("AcceptInvitation() calls = %d, want 1", queries.acceptCalls)
	}
	wantHash := HashToken("presented-invitation-token")
	if string(queries.acceptParams.TokenHash) != string(wantHash[:]) {
		t.Fatal("Accept() sent a value other than the invitation-token hash to the database boundary")
	}
	if queries.acceptParams.SubjectID != subjectID {
		t.Fatalf("Accept() subject = %#v, want %#v", queries.acceptParams.SubjectID, subjectID)
	}
}

func TestInvitationStoreAcceptRejectsInvalidInputBeforeDatabase(t *testing.T) {
	t.Parallel()

	validSubject := pgtype.UUID{Bytes: [16]byte{3}, Valid: true}
	tests := []struct {
		name      string
		token     string
		subjectID pgtype.UUID
	}{
		{name: "missing token", token: "", subjectID: validSubject},
		{name: "missing subject", token: "presented-invitation-token", subjectID: pgtype.UUID{}},
	}

	for _, tt := range tests {
		t := tt
		testName := tt.name
		t.Run(testName, func(t *testing.T) {
			t.Parallel()
			queries := &recordingInvitationQueries{}
			store := NewInvitationStore(queries)
			if _, err := store.Accept(context.Background(), tt.token, tt.subjectID); err == nil {
				t.Fatal("Accept() accepted invalid invitation input")
			}
			if queries.acceptCalls != 0 {
				t.Fatalf("invalid invitation input reached database boundary: calls = %d", queries.acceptCalls)
			}
		})
	}
}

func TestInvitationStoreAcceptPreservesDatabaseError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("invitation unavailable")
	queries := &recordingInvitationQueries{acceptErr: wantErr}
	store := NewInvitationStore(queries)
	subjectID := pgtype.UUID{Bytes: [16]byte{4}, Valid: true}

	if _, err := store.Accept(context.Background(), "presented-invitation-token", subjectID); !errors.Is(err, wantErr) {
		t.Fatalf("Accept() error = %v, want errors.Is(_, %v)", err, wantErr)
	}
	if queries.acceptCalls != 1 {
		t.Fatalf("AcceptInvitation() calls = %d, want 1", queries.acceptCalls)
	}
}
