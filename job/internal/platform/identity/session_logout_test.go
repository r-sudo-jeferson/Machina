package identity

import (
	"context"
	"errors"
	"testing"
)

type recordingSessionRevoker struct {
	presentedSessionToken string
	calls                 int
	err                   error
}

func (s *recordingSessionRevoker) Revoke(_ context.Context, presentedSessionToken string) error {
	s.calls++
	s.presentedSessionToken = presentedSessionToken
	return s.err
}

func TestSessionLogoutServiceRevokesPresentedServerSideSession(t *testing.T) {
	t.Parallel()

	store := &recordingSessionRevoker{}
	service, err := NewSessionLogoutService(store)
	if err != nil {
		t.Fatalf("NewSessionLogoutService() error = %v", err)
	}
	if err := service.Logout(context.Background(), "presented-session"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if store.calls != 1 || store.presentedSessionToken != "presented-session" {
		t.Fatalf("server-side revoke = %#v", store)
	}
}

func TestSessionLogoutServiceRejectsMissingSessionBeforeStore(t *testing.T) {
	t.Parallel()

	store := &recordingSessionRevoker{}
	service, err := NewSessionLogoutService(store)
	if err != nil {
		t.Fatalf("NewSessionLogoutService() error = %v", err)
	}
	if err := service.Logout(context.Background(), ""); !errors.Is(err, ErrMissingSessionToken) {
		t.Fatalf("Logout() error = %v, want ErrMissingSessionToken", err)
	}
	if store.calls != 0 {
		t.Fatal("missing session token reached the revoke boundary")
	}
}

func TestSessionLogoutServicePreservesRevokeFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("revoke unavailable")
	store := &recordingSessionRevoker{err: wantErr}
	service, err := NewSessionLogoutService(store)
	if err != nil {
		t.Fatalf("NewSessionLogoutService() error = %v", err)
	}
	if err := service.Logout(context.Background(), "presented-session"); !errors.Is(err, wantErr) {
		t.Fatalf("Logout() error = %v, want errors.Is(_, %v)", err, wantErr)
	}
}

func TestSessionLogoutServiceRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := NewSessionLogoutService(nil); err == nil {
		t.Fatal("NewSessionLogoutService() accepted nil session store")
	}
}
