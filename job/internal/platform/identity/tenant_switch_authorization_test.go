package identity

import (
	"context"
	"errors"
	"reflect"
	"testing"

	platformauthz "github.com/r-sudo-jeferson/Machina/job/internal/platform/authz"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type recordingTenantSwitchAuthorizer struct {
	decision platformauthz.Decision
	err      error
	calls    int
	request  platformauthz.Request
	observe  func() [4]int
	atCall   [4]int
}

func (a *recordingTenantSwitchAuthorizer) Authorize(_ context.Context, request platformauthz.Request) (platformauthz.Decision, error) {
	a.calls++
	a.request = request
	if a.observe != nil {
		a.atCall = a.observe()
	}
	return a.decision, a.err
}

func allowTenantSwitchAuthorizer() *recordingTenantSwitchAuthorizer {
	request := validTenantSwitchRequest()
	return &recordingTenantSwitchAuthorizer{decision: platformauthz.Decision{
		DecisionID:         uuidText(request.CorrelationID),
		Allowed:            true,
		PolicyVersion:      1,
		PolicySnapshotHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}
}

func newAuthorizedRecordingTenantSwitchCoordinator(unit *recordingTenantSwitchUnit, authorizer tenantSwitchAuthorizer) *TenantSwitchCoordinator {
	coordinator, err := newTenantSwitchCoordinator(func(ctx context.Context, fn func(context.Context, tenantSwitchUnit) error) error {
		return fn(ctx, unit)
	}, authorizer)
	if err != nil {
		panic(err)
	}
	return coordinator
}

func TestTenantSwitchCoordinatorRequiresAuthorizer(t *testing.T) {
	t.Parallel()

	_, err := newTenantSwitchCoordinator(func(ctx context.Context, fn func(context.Context, tenantSwitchUnit) error) error {
		return fn(ctx, claimedTenantSwitchUnit())
	}, nil)
	if !errors.Is(err, ErrInvalidTenantSwitchCoordinatorConfig) {
		t.Fatalf("newTenantSwitchCoordinator() error = %v, want ErrInvalidTenantSwitchCoordinatorConfig", err)
	}
}

func TestTenantSwitchCoordinatorAuthorizesBeforeMutationWithServerDerivedContext(t *testing.T) {
	t.Parallel()

	unit := claimedTenantSwitchUnit()
	authorizer := allowTenantSwitchAuthorizer()
	authorizer.observe = func() [4]int {
		return [4]int{unit.claimCalls, unit.switchCalls, unit.auditCalls, unit.outboxCalls}
	}
	coordinator := newAuthorizedRecordingTenantSwitchCoordinator(unit, authorizer)

	if _, err := coordinator.Switch(context.Background(), validTenantSwitchRequest()); err != nil {
		t.Fatalf("Switch() error = %v", err)
	}
	if authorizer.calls != 1 {
		t.Fatalf("Authorize() calls = %d, want 1", authorizer.calls)
	}
	if authorizer.atCall != [4]int{} {
		t.Fatalf("mutation happened before authorization: claim/switch/audit/outbox = %v", authorizer.atCall)
	}
	want := platformauthz.Request{
		SubjectID:             uuidText(tenantSwitchUUID(2)),
		TenantID:              uuidText(tenantSwitchUUID(2)),
		WorkspaceID:           uuidText(tenantSwitchUUID(4)),
		Action:                "tenant.switch",
		ResourceType:          "Tenant",
		ResourceID:            uuidText(tenantSwitchUUID(2)),
		RequiredPolicyVersion: 1,
		CorrelationID:         uuidText(validTenantSwitchRequest().CorrelationID),
		Context: map[string]string{
			"starter_role":      "owner",
			"membership_status": "active",
		},
	}
	if !reflect.DeepEqual(authorizer.request, want) {
		t.Fatalf("Authorize() request = %#v, want %#v", authorizer.request, want)
	}
}

func TestTenantSwitchCoordinatorDenyAndErrorsFailClosedBeforeMutation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		authorizer *recordingTenantSwitchAuthorizer
		want       error
	}{
		{
			name: "explicit deny",
			authorizer: &recordingTenantSwitchAuthorizer{decision: platformauthz.Decision{
				DecisionID:    uuidText(validTenantSwitchRequest().CorrelationID),
				Allowed:       false,
				PolicyVersion: 1,
				ReasonCodes:   []string{"explicit_forbid"},
			}},
			want: ErrTenantSwitchForbidden,
		},
		{
			name:       "transport error",
			authorizer: &recordingTenantSwitchAuthorizer{err: errors.New("authz unavailable")},
			want:       ErrTenantSwitchAuthorizationUnavailable,
		},
		{
			name:       "deadline",
			authorizer: &recordingTenantSwitchAuthorizer{err: context.DeadlineExceeded},
			want:       ErrTenantSwitchAuthorizationUnavailable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unit := claimedTenantSwitchUnit()
			coordinator := newAuthorizedRecordingTenantSwitchCoordinator(unit, tc.authorizer)
			got, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
			if !errors.Is(err, tc.want) {
				t.Fatalf("Switch() error = %v, want errors.Is(_, %v)", err, tc.want)
			}
			if !reflect.DeepEqual(got, TenantSwitchResult{}) {
				t.Fatalf("failed authorization returned result = %#v", got)
			}
			if tc.authorizer.calls != 1 {
				t.Fatalf("Authorize() calls = %d, want 1", tc.authorizer.calls)
			}
			if unit.claimCalls != 0 || unit.switchCalls != 0 || unit.completeCalls != 0 || unit.finishCalls != 0 || unit.outboxCalls != 0 {
				t.Fatalf("authorization failure reached mutation: claim=%d switch=%d complete=%d finish=%d outbox=%d", unit.claimCalls, unit.switchCalls, unit.completeCalls, unit.finishCalls, unit.outboxCalls)
			}
		})
	}
}

func TestTenantSwitchCoordinatorReplayRequiresCurrentAuthorization(t *testing.T) {
	t.Parallel()

	unit := claimedTenantSwitchUnit()
	unit.bindRow.MappingState = "replay"
	unit.bindRow.Generation++
	unit.claimRow = sqlcgen.ClaimIdempotencyKeyRow{
		ClaimState:     "replay",
		ResponseStatus: 200,
		ResponseBody:   tenantSwitchCoordinatorResponseBody(),
		CorrelationID:  validTenantSwitchRequest().CorrelationID,
	}
	authorizer := &recordingTenantSwitchAuthorizer{decision: platformauthz.Decision{
		DecisionID:    uuidText(validTenantSwitchRequest().CorrelationID),
		Allowed:       false,
		PolicyVersion: 1,
		ReasonCodes:   []string{"default_deny"},
	}}
	coordinator := newAuthorizedRecordingTenantSwitchCoordinator(unit, authorizer)

	got, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
	if !errors.Is(err, ErrTenantSwitchForbidden) {
		t.Fatalf("Switch() error = %v, want ErrTenantSwitchForbidden", err)
	}
	if !reflect.DeepEqual(got, TenantSwitchResult{}) {
		t.Fatalf("denied replay returned result = %#v", got)
	}
	if authorizer.calls != 1 {
		t.Fatalf("Authorize() calls = %d, want 1", authorizer.calls)
	}
	if unit.claimCalls != 0 || unit.switchCalls != 0 || unit.completeCalls != 0 || unit.finishCalls != 0 || unit.etagCalls != 0 {
		t.Fatalf("denied replay crossed receipt/mutation boundary: claim=%d switch=%d complete=%d finish=%d etag=%d", unit.claimCalls, unit.switchCalls, unit.completeCalls, unit.finishCalls, unit.etagCalls)
	}
}
