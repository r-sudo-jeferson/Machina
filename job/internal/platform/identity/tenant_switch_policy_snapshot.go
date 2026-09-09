package identity

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

// pinnedTenantSwitchPolicyUnit guarantees that one tenant-switch transaction
// observes exactly one active policy snapshot. The first policy lookup is the
// snapshot sent to Cedar; later projection reads receive the same immutable
// row instead of observing a newer READ COMMITTED statement snapshot.
type pinnedTenantSwitchPolicyUnit struct {
	tenantSwitchUnit
	loaded   bool
	tenantID pgtype.UUID
	row      sqlcgen.GetActivePolicySnapshotRow
	err      error
}

func pinTenantSwitchPolicySnapshot(unit tenantSwitchUnit) tenantSwitchUnit {
	if isNilTenantSwitchUnit(unit) {
		return unit
	}
	return &pinnedTenantSwitchPolicyUnit{tenantSwitchUnit: unit}
}

func (u *pinnedTenantSwitchPolicyUnit) GetActivePolicySnapshot(ctx context.Context, tenantID pgtype.UUID) (sqlcgen.GetActivePolicySnapshotRow, error) {
	if u == nil || isNilTenantSwitchUnit(u.tenantSwitchUnit) {
		return sqlcgen.GetActivePolicySnapshotRow{}, ErrInvalidTenantSwitchCoordinatorConfig
	}
	if u.loaded {
		if u.tenantID != tenantID {
			return sqlcgen.GetActivePolicySnapshotRow{}, ErrInvalidTenantSwitchOutcome
		}
		return u.row, u.err
	}

	u.loaded = true
	u.tenantID = tenantID
	u.row, u.err = u.tenantSwitchUnit.GetActivePolicySnapshot(ctx, tenantID)
	return u.row, u.err
}
