package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	platformauthz "github.com/r-sudo-jeferson/Machina/job/internal/platform/authz"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

type sequencedPolicyTenantSwitchUnit struct {
	*recordingTenantSwitchUnit
	policyRows  []sqlcgen.GetActivePolicySnapshotRow
	policyCalls int
}

func (u *sequencedPolicyTenantSwitchUnit) GetActivePolicySnapshot(_ context.Context, _ pgtype.UUID) (sqlcgen.GetActivePolicySnapshotRow, error) {
	u.policyCalls++
	if len(u.policyRows) == 0 {
		return sqlcgen.GetActivePolicySnapshotRow{}, errors.New("no policy snapshot configured")
	}
	index := u.policyCalls - 1
	if index >= len(u.policyRows) {
		index = len(u.policyRows) - 1
	}
	return u.policyRows[index], nil
}

func newSequencedPolicyTenantSwitchCoordinator(unit tenantSwitchUnit, authorizer tenantSwitchAuthorizer) *TenantSwitchCoordinator {
	coordinator, err := newTenantSwitchCoordinator(func(ctx context.Context, fn func(context.Context, tenantSwitchUnit) error) error {
		return fn(ctx, unit)
	}, authorizer)
	if err != nil {
		panic(err)
	}
	return coordinator
}

func TestTenantSwitchCoordinatorPinsAuthorizedPolicySnapshotIntoSuccess(t *testing.T) {
	t.Parallel()

	base := claimedTenantSwitchUnit()
	unit := &sequencedPolicyTenantSwitchUnit{
		recordingTenantSwitchUnit: base,
		policyRows: []sqlcgen.GetActivePolicySnapshotRow{
			{Version: 1, SnapshotHash: strings.Repeat("a", 64)},
			{Version: 2, SnapshotHash: strings.Repeat("b", 64)},
		},
	}
	authorizer := allowTenantSwitchAuthorizer()
	coordinator := newSequencedPolicyTenantSwitchCoordinator(unit, authorizer)

	result, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
	if err != nil {
		t.Fatalf("Switch() error = %v", err)
	}
	if unit.policyCalls != 1 {
		t.Fatalf("active policy reads = %d, want exactly 1 authorized snapshot read", unit.policyCalls)
	}
	response, _, err := unmarshalTenantSwitchResponse(result.ResponseBody)
	if err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Active.PolicyVersion != 1 || base.auditParams.PolicyVersion != 1 {
		t.Fatalf("authorized policy was not pinned: response=%d audit=%d", response.Active.PolicyVersion, base.auditParams.PolicyVersion)
	}
	if authorizer.calls != 1 || authorizer.request.RequiredPolicyVersion != 1 {
		t.Fatalf("authorization request = calls:%d version:%d", authorizer.calls, authorizer.request.RequiredPolicyVersion)
	}
}

func TestTenantSwitchCoordinatorRejectsAuthorizationSnapshotHashMismatch(t *testing.T) {
	t.Parallel()

	unit := claimedTenantSwitchUnit()
	authorizer := allowTenantSwitchAuthorizer()
	authorizer.decision.PolicySnapshotHash = strings.Repeat("b", 64)
	coordinator := newAuthorizedRecordingTenantSwitchCoordinator(unit, authorizer)

	result, err := coordinator.Switch(context.Background(), validTenantSwitchRequest())
	if !errors.Is(err, ErrTenantSwitchAuthorizationUnavailable) {
		t.Fatalf("Switch() error = %v, want ErrTenantSwitchAuthorizationUnavailable", err)
	}
	if result != (TenantSwitchResult{}) {
		t.Fatalf("snapshot mismatch returned result = %#v", result)
	}
	if unit.claimCalls != 0 || unit.switchCalls != 0 || unit.auditCalls != 0 || unit.outboxCalls != 0 {
		t.Fatalf("snapshot mismatch crossed mutation boundary: claim=%d switch=%d audit=%d outbox=%d", unit.claimCalls, unit.switchCalls, unit.auditCalls, unit.outboxCalls)
	}
}
