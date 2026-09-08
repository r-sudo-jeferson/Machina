package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingSessionContextSwitcher struct {
	presentedSessionToken   string
	replacementSessionToken string
	replacementCSRFToken    string
	targetTenantID          pgtype.UUID
	targetWorkspaceID       pgtype.UUID
	calls                   int
	row                     sqlcgen.SwitchSessionContextRow
	err                     error
}

func (s *recordingSessionContextSwitcher) SwitchContext(
	_ context.Context,
	presentedSessionToken string,
	replacementSessionToken string,
	replacementCSRFToken string,
	targetTenantID pgtype.UUID,
	targetWorkspaceID pgtype.UUID,
) (sqlcgen.SwitchSessionContextRow, error) {
	s.calls++
	s.presentedSessionToken = presentedSessionToken
	s.replacementSessionToken = replacementSessionToken
	s.replacementCSRFToken = replacementCSRFToken
	s.targetTenantID = targetTenantID
	s.targetWorkspaceID = targetWorkspaceID
	return s.row, s.err
}

func TestSessionContextSwitchServicePublishesOnlyValidatedServerContext(t *testing.T) {
	t.Parallel()

	tenantID := pgtype.UUID{Bytes: [16]byte{1}, Valid: true}
	workspaceID := pgtype.UUID{Bytes: [16]byte{2}, Valid: true}
	expiresAt := time.Date(2026, 9, 9, 5, 0, 0, 0, time.UTC)
	store := &recordingSessionContextSwitcher{row: sqlcgen.SwitchSessionContextRow{
		SessionID:         pgtype.UUID{Bytes: [16]byte{3}, Valid: true},
		ActiveTenantID:    tenantID,
		ActiveWorkspaceID: workspaceID,
		ExpiresAt:         pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}}
	service, err := NewSessionContextSwitchService(store)
	if err != nil {
		t.Fatalf("NewSessionContextSwitchService() error = %v", err)
	}
	tokens := []string{"replacement-session", "replacement-csrf"}
	service.newToken = func() (string, error) {
		token := tokens[0]
		tokens = tokens[1:]
		return token, nil
	}

	got, err := service.Switch(context.Background(), "presented-session", tenantID, workspaceID)
	if err != nil {
		t.Fatalf("Switch() error = %v", err)
	}
	if store.calls != 1 {
		t.Fatalf("SwitchContext() calls = %d, want 1", store.calls)
	}
	if store.presentedSessionToken != "presented-session" || store.replacementSessionToken != "replacement-session" || store.replacementCSRFToken != "replacement-csrf" {
		t.Fatalf("switch material = %#v", store)
	}
	if store.targetTenantID != tenantID || store.targetWorkspaceID != workspaceID {
		t.Fatal("requested target changed before the server validation boundary")
	}
	if got.ActiveTenantID != tenantID || got.ActiveWorkspaceID != workspaceID || got.SessionToken != "replacement-session" || got.CSRFToken != "replacement-csrf" || !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("switched browser session = %#v", got)
	}
	if got.SessionCookie().Value != got.SessionToken || !got.SessionCookie().Expires.Equal(expiresAt) {
		t.Fatal("switched session cookie does not carry replacement token with authoritative expiry")
	}
	if got.CSRFCookie().Value != got.CSRFToken || !got.CSRFCookie().Expires.Equal(expiresAt) {
		t.Fatal("switched CSRF cookie does not carry replacement token with authoritative expiry")
	}
}

func TestSessionContextSwitchServiceRejectsGeneratedSecretReuseBeforeDatabase(t *testing.T) {
	t.Parallel()

	tenantID := pgtype.UUID{Bytes: [16]byte{4}, Valid: true}
	workspaceID := pgtype.UUID{Bytes: [16]byte{5}, Valid: true}
	for _, tc := range []struct {
		name   string
		tokens []string
	}{
		{name: "replacement session reuses presented session", tokens: []string{"presented-session", "replacement-csrf"}},
		{name: "replacement tokens collide", tokens: []string{"same-secret", "same-secret"}},
		{name: "replacement csrf reuses presented session", tokens: []string{"replacement-session", "presented-session"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingSessionContextSwitcher{}
			service, err := NewSessionContextSwitchService(store)
			if err != nil {
				t.Fatalf("NewSessionContextSwitchService() error = %v", err)
			}
			tokens := append([]string(nil), tc.tokens...)
			service.newToken = func() (string, error) {
				token := tokens[0]
				tokens = tokens[1:]
				return token, nil
			}
			if _, err := service.Switch(context.Background(), "presented-session", tenantID, workspaceID); err == nil {
				t.Fatal("Switch() accepted reused or colliding generated secret")
			}
			if store.calls != 0 {
				t.Fatal("invalid generated switch material reached database boundary")
			}
		})
	}
}

func TestSessionContextSwitchServiceFailsClosedOnInvalidServerResult(t *testing.T) {
	t.Parallel()

	tenantID := pgtype.UUID{Bytes: [16]byte{6}, Valid: true}
	workspaceID := pgtype.UUID{Bytes: [16]byte{7}, Valid: true}
	otherTenantID := pgtype.UUID{Bytes: [16]byte{8}, Valid: true}
	validExpiry := pgtype.Timestamptz{Time: time.Date(2026, 9, 9, 6, 0, 0, 0, time.UTC), Valid: true}

	for _, tc := range []struct {
		name string
		row  sqlcgen.SwitchSessionContextRow
	}{
		{name: "missing session identity", row: sqlcgen.SwitchSessionContextRow{ActiveTenantID: tenantID, ActiveWorkspaceID: workspaceID, ExpiresAt: validExpiry}},
		{name: "tenant mismatch", row: sqlcgen.SwitchSessionContextRow{SessionID: pgtype.UUID{Bytes: [16]byte{9}, Valid: true}, ActiveTenantID: otherTenantID, ActiveWorkspaceID: workspaceID, ExpiresAt: validExpiry}},
		{name: "workspace missing", row: sqlcgen.SwitchSessionContextRow{SessionID: pgtype.UUID{Bytes: [16]byte{10}, Valid: true}, ActiveTenantID: tenantID, ExpiresAt: validExpiry}},
		{name: "expiry missing", row: sqlcgen.SwitchSessionContextRow{SessionID: pgtype.UUID{Bytes: [16]byte{11}, Valid: true}, ActiveTenantID: tenantID, ActiveWorkspaceID: workspaceID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingSessionContextSwitcher{row: tc.row}
			service, err := NewSessionContextSwitchService(store)
			if err != nil {
				t.Fatalf("NewSessionContextSwitchService() error = %v", err)
			}
			tokens := []string{"replacement-session", "replacement-csrf"}
			service.newToken = func() (string, error) {
				token := tokens[0]
				tokens = tokens[1:]
				return token, nil
			}
			if _, err := service.Switch(context.Background(), "presented-session", tenantID, workspaceID); !errors.Is(err, ErrInvalidSessionContextSwitchResult) {
				t.Fatalf("Switch() error = %v, want ErrInvalidSessionContextSwitchResult", err)
			}
		})
	}
}

func TestSessionContextSwitchServicePreservesGenerationAndStoreFailures(t *testing.T) {
	t.Parallel()

	tenantID := pgtype.UUID{Bytes: [16]byte{12}, Valid: true}
	workspaceID := pgtype.UUID{Bytes: [16]byte{13}, Valid: true}
	generationErr := errors.New("entropy unavailable")
	store := &recordingSessionContextSwitcher{}
	service, err := NewSessionContextSwitchService(store)
	if err != nil {
		t.Fatalf("NewSessionContextSwitchService() error = %v", err)
	}
	service.newToken = func() (string, error) { return "", generationErr }
	if _, err := service.Switch(context.Background(), "presented-session", tenantID, workspaceID); !errors.Is(err, generationErr) {
		t.Fatalf("Switch() generation error = %v, want errors.Is(_, %v)", err, generationErr)
	}
	if store.calls != 0 {
		t.Fatal("token generation failure reached database boundary")
	}

	storeErr := errors.New("context switch unavailable")
	store = &recordingSessionContextSwitcher{err: storeErr}
	service, err = NewSessionContextSwitchService(store)
	if err != nil {
		t.Fatalf("NewSessionContextSwitchService() error = %v", err)
	}
	tokens := []string{"replacement-session", "replacement-csrf"}
	service.newToken = func() (string, error) {
		token := tokens[0]
		tokens = tokens[1:]
		return token, nil
	}
	if _, err := service.Switch(context.Background(), "presented-session", tenantID, workspaceID); !errors.Is(err, storeErr) {
		t.Fatalf("Switch() store error = %v, want errors.Is(_, %v)", err, storeErr)
	}
}

func TestSessionContextSwitchServiceRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := NewSessionContextSwitchService(nil); err == nil {
		t.Fatal("NewSessionContextSwitchService() accepted nil session store")
	}
}
