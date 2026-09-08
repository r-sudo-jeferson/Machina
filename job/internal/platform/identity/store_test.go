package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingSessionQueries struct {
	createParams sqlcgen.CreateSessionParams
	createCalls  int
	lookupHash   []byte
	lookupCalls  int
	lookupRow    sqlcgen.GetActiveSessionRow
	lookupErr    error
	revokeHash   []byte
	revokeCalls  int
	rotateParams sqlcgen.RotateSessionParams
	rotateCalls  int
	rotateRow    sqlcgen.RotateSessionRow
	rotateErr    error
	switchParams sqlcgen.SwitchSessionContextParams
	switchCalls  int
	switchRow    sqlcgen.SwitchSessionContextRow
	switchErr    error
	upsertParams sqlcgen.UpsertSubjectParams
	upsertCalls  int
}

func (q *recordingSessionQueries) CreateSession(_ context.Context, arg sqlcgen.CreateSessionParams) (pgtype.UUID, error) {
	q.createCalls++
	q.createParams = arg
	return arg.SessionID, nil
}

func (q *recordingSessionQueries) GetActiveSession(_ context.Context, sessionTokenHash []byte) (sqlcgen.GetActiveSessionRow, error) {
	q.lookupCalls++
	q.lookupHash = append([]byte(nil), sessionTokenHash...)
	return q.lookupRow, q.lookupErr
}

func (q *recordingSessionQueries) RevokeSession(_ context.Context, sessionTokenHash []byte) error {
	q.revokeCalls++
	q.revokeHash = append([]byte(nil), sessionTokenHash...)
	return nil
}

func (q *recordingSessionQueries) RotateSession(_ context.Context, arg sqlcgen.RotateSessionParams) (sqlcgen.RotateSessionRow, error) {
	q.rotateCalls++
	q.rotateParams = sqlcgen.RotateSessionParams{
		SessionTokenHash:    append([]byte(nil), arg.SessionTokenHash...),
		NewSessionTokenHash: append([]byte(nil), arg.NewSessionTokenHash...),
		NewCsrfTokenHash:    append([]byte(nil), arg.NewCsrfTokenHash...),
	}
	return q.rotateRow, q.rotateErr
}

func (q *recordingSessionQueries) SwitchSessionContext(_ context.Context, arg sqlcgen.SwitchSessionContextParams) (sqlcgen.SwitchSessionContextRow, error) {
	q.switchCalls++
	q.switchParams = sqlcgen.SwitchSessionContextParams{
		CurrentSessionTokenHash:     append([]byte(nil), arg.CurrentSessionTokenHash...),
		ReplacementSessionTokenHash: append([]byte(nil), arg.ReplacementSessionTokenHash...),
		ReplacementCsrfTokenHash:    append([]byte(nil), arg.ReplacementCsrfTokenHash...),
		TargetTenantID:              arg.TargetTenantID,
		TargetWorkspaceID:           arg.TargetWorkspaceID,
	}
	return q.switchRow, q.switchErr
}

func (q *recordingSessionQueries) UpsertSubject(_ context.Context, arg sqlcgen.UpsertSubjectParams) (pgtype.UUID, error) {
	q.upsertCalls++
	q.upsertParams = arg
	return arg.SubjectID, nil
}

func TestSessionStoreCreatePersistsOnlyTokenHashes(t *testing.T) {
	t.Parallel()

	queries := &recordingSessionQueries{}
	store := NewSessionStore(queries)
	sessionID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	subjectID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	expiresAt := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)

	if err := store.Create(context.Background(), sessionID, subjectID, "presented-session-token", "presented-csrf-token", expiresAt); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if queries.createCalls != 1 {
		t.Fatalf("CreateSession() calls = %d, want 1", queries.createCalls)
	}
	wantSessionHash := HashToken("presented-session-token")
	wantCSRFHash := HashToken("presented-csrf-token")
	if string(queries.createParams.SessionTokenHash) != string(wantSessionHash[:]) {
		t.Fatal("Create() did not replace presented session token with its SHA-256 hash")
	}
	if string(queries.createParams.CsrfTokenHash) != string(wantCSRFHash[:]) {
		t.Fatal("Create() did not replace presented CSRF token with its SHA-256 hash")
	}
	if queries.createParams.SessionID != sessionID || queries.createParams.SubjectID != subjectID {
		t.Fatal("Create() changed session or subject identity")
	}
	if !queries.createParams.ExpiresAt.Valid || !queries.createParams.ExpiresAt.Time.Equal(expiresAt) {
		t.Fatalf("Create() expiry = %#v, want %v", queries.createParams.ExpiresAt, expiresAt)
	}
}

func TestSessionStoreLookupHashesPresentedSessionToken(t *testing.T) {
	t.Parallel()

	want := sqlcgen.GetActiveSessionRow{ID: pgtype.UUID{Bytes: [16]byte{3}, Valid: true}}
	queries := &recordingSessionQueries{lookupRow: want}
	store := NewSessionStore(queries)

	got, err := store.Lookup(context.Background(), "presented-session-token")
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Lookup() = %#v, want %#v", got, want)
	}
	wantHash := HashToken("presented-session-token")
	if string(queries.lookupHash) != string(wantHash[:]) {
		t.Fatal("Lookup() sent a value other than the session-token hash to the database boundary")
	}
}

func TestSessionStoreRevokeHashesPresentedSessionToken(t *testing.T) {
	t.Parallel()

	queries := &recordingSessionQueries{}
	store := NewSessionStore(queries)
	if err := store.Revoke(context.Background(), "presented-session-token"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	wantHash := HashToken("presented-session-token")
	if string(queries.revokeHash) != string(wantHash[:]) {
		t.Fatal("Revoke() sent a value other than the session-token hash to the database boundary")
	}
}

func TestSessionStoreRotateHashesPresentedAndReplacementSecrets(t *testing.T) {
	t.Parallel()

	want := sqlcgen.RotateSessionRow{
		ID:        pgtype.UUID{Bytes: [16]byte{4}, Valid: true},
		SubjectID: pgtype.UUID{Bytes: [16]byte{5}, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 1, 0, 0, 0, time.UTC), Valid: true},
		RotatedAt: pgtype.Timestamptz{Time: time.Date(2026, 9, 8, 4, 0, 0, 0, time.UTC), Valid: true},
	}
	queries := &recordingSessionQueries{rotateRow: want}
	store := NewSessionStore(queries)

	got, err := store.Rotate(context.Background(), "presented-old-session", "presented-new-session", "presented-new-csrf")
	if err != nil {
		t.Fatalf("Rotate() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Rotate() = %#v, want %#v", got, want)
	}
	if queries.rotateCalls != 1 {
		t.Fatalf("RotateSession() calls = %d, want 1", queries.rotateCalls)
	}

	wantOldHash := HashToken("presented-old-session")
	wantNewHash := HashToken("presented-new-session")
	wantCSRFHash := HashToken("presented-new-csrf")
	if string(queries.rotateParams.SessionTokenHash) != string(wantOldHash[:]) {
		t.Fatal("Rotate() did not hash the presented old session token")
	}
	if string(queries.rotateParams.NewSessionTokenHash) != string(wantNewHash[:]) {
		t.Fatal("Rotate() did not hash the replacement session token")
	}
	if string(queries.rotateParams.NewCsrfTokenHash) != string(wantCSRFHash[:]) {
		t.Fatal("Rotate() did not hash the replacement CSRF token")
	}
}

func TestSessionStoreRotateRejectsMissingReusedOrCollidingSecretsBeforeDatabase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		old     string
		new     string
		newCSRF string
	}{
		{name: "missing old session", old: "", new: "new-session", newCSRF: "new-csrf"},
		{name: "missing new session", old: "old-session", new: "", newCSRF: "new-csrf"},
		{name: "missing new csrf", old: "old-session", new: "new-session", newCSRF: ""},
		{name: "reused session", old: "same-session", new: "same-session", newCSRF: "new-csrf"},
		{name: "session csrf collision", old: "old-session", new: "same-secret", newCSRF: "same-secret"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			queries := &recordingSessionQueries{}
			store := NewSessionStore(queries)
			if _, err := store.Rotate(context.Background(), tt.old, tt.new, tt.newCSRF); err == nil {
				t.Fatal("Rotate() accepted invalid replacement material")
			}
			if queries.rotateCalls != 0 {
				t.Fatal("invalid rotation material reached the database boundary")
			}
		})
	}
}

func TestSessionStoreRotatePreservesDatabaseError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("rotation unavailable")
	queries := &recordingSessionQueries{rotateErr: wantErr}
	store := NewSessionStore(queries)
	if _, err := store.Rotate(context.Background(), "old-session", "new-session", "new-csrf"); !errors.Is(err, wantErr) {
		t.Fatalf("Rotate() error = %v, want errors.Is(_, %v)", err, wantErr)
	}
}

func TestSessionStoreSwitchContextHashesSecretsAndPassesOnlyRequestedTarget(t *testing.T) {
	t.Parallel()

	tenantID := pgtype.UUID{Bytes: [16]byte{6}, Valid: true}
	workspaceID := pgtype.UUID{Bytes: [16]byte{7}, Valid: true}
	want := sqlcgen.SwitchSessionContextRow{
		SessionID:         pgtype.UUID{Bytes: [16]byte{8}, Valid: true},
		ActiveTenantID:    tenantID,
		ActiveWorkspaceID: workspaceID,
		ExpiresAt:         pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 2, 0, 0, 0, time.UTC), Valid: true},
	}
	queries := &recordingSessionQueries{switchRow: want}
	store := NewSessionStore(queries)

	got, err := store.SwitchContext(
		context.Background(),
		"presented-old-session",
		"presented-new-session",
		"presented-new-csrf",
		tenantID,
		workspaceID,
	)
	if err != nil {
		t.Fatalf("SwitchContext() error = %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SwitchContext() = %#v, want %#v", got, want)
	}
	if queries.switchCalls != 1 {
		t.Fatalf("SwitchSessionContext() calls = %d, want 1", queries.switchCalls)
	}

	wantOldHash := HashToken("presented-old-session")
	wantNewHash := HashToken("presented-new-session")
	wantCSRFHash := HashToken("presented-new-csrf")
	if string(queries.switchParams.CurrentSessionTokenHash) != string(wantOldHash[:]) {
		t.Fatal("SwitchContext() did not hash the presented old session token")
	}
	if string(queries.switchParams.ReplacementSessionTokenHash) != string(wantNewHash[:]) {
		t.Fatal("SwitchContext() did not hash the replacement session token")
	}
	if string(queries.switchParams.ReplacementCsrfTokenHash) != string(wantCSRFHash[:]) {
		t.Fatal("SwitchContext() did not hash the replacement CSRF token")
	}
	if queries.switchParams.TargetTenantID != tenantID || queries.switchParams.TargetWorkspaceID != workspaceID {
		t.Fatal("SwitchContext() changed the requested target before the server-side validation boundary")
	}
}

func TestSessionStoreSwitchContextRejectsInvalidInputBeforeDatabase(t *testing.T) {
	t.Parallel()

	validTenant := pgtype.UUID{Bytes: [16]byte{9}, Valid: true}
	validWorkspace := pgtype.UUID{Bytes: [16]byte{10}, Valid: true}
	tests := []struct {
		name      string
		old       string
		new       string
		newCSRF   string
		tenant    pgtype.UUID
		workspace pgtype.UUID
	}{
		{name: "missing old session", old: "", new: "new-session", newCSRF: "new-csrf", tenant: validTenant, workspace: validWorkspace},
		{name: "missing new session", old: "old-session", new: "", newCSRF: "new-csrf", tenant: validTenant, workspace: validWorkspace},
		{name: "missing new csrf", old: "old-session", new: "new-session", newCSRF: "", tenant: validTenant, workspace: validWorkspace},
		{name: "reused session", old: "same-session", new: "same-session", newCSRF: "new-csrf", tenant: validTenant, workspace: validWorkspace},
		{name: "session csrf collision", old: "old-session", new: "same-secret", newCSRF: "same-secret", tenant: validTenant, workspace: validWorkspace},
		{name: "invalid tenant", old: "old-session", new: "new-session", newCSRF: "new-csrf", workspace: validWorkspace},
		{name: "invalid workspace", old: "old-session", new: "new-session", newCSRF: "new-csrf", tenant: validTenant},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			queries := &recordingSessionQueries{}
			store := NewSessionStore(queries)
			if _, err := store.SwitchContext(context.Background(), tt.old, tt.new, tt.newCSRF, tt.tenant, tt.workspace); err == nil {
				t.Fatal("SwitchContext() accepted invalid input")
			}
			if queries.switchCalls != 0 {
				t.Fatal("invalid context switch input reached the database boundary")
			}
		})
	}
}

func TestSessionStoreSwitchContextPreservesDatabaseError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("context switch unavailable")
	queries := &recordingSessionQueries{switchErr: wantErr}
	store := NewSessionStore(queries)
	if _, err := store.SwitchContext(
		context.Background(),
		"old-session",
		"new-session",
		"new-csrf",
		pgtype.UUID{Bytes: [16]byte{11}, Valid: true},
		pgtype.UUID{Bytes: [16]byte{12}, Valid: true},
	); !errors.Is(err, wantErr) {
		t.Fatalf("SwitchContext() error = %v, want errors.Is(_, %v)", err, wantErr)
	}
}

func TestSessionStoreFailsClosedOnMissingPresentedToken(t *testing.T) {
	t.Parallel()

	queries := &recordingSessionQueries{lookupErr: errors.New("must not be called")}
	store := NewSessionStore(queries)

	if _, err := store.Lookup(context.Background(), ""); err == nil {
		t.Fatal("Lookup() accepted empty presented session token")
	}
	if err := store.Revoke(context.Background(), ""); err == nil {
		t.Fatal("Revoke() accepted empty presented session token")
	}
	if queries.lookupCalls != 0 || queries.revokeCalls != 0 {
		t.Fatal("missing session token reached the database boundary")
	}
}
