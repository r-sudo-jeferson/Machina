package identity

import (
	"context"
	"fmt"
	"reflect"

	platformauthz "github.com/r-sudo-jeferson/Machina/job/internal/platform/authz"
	"github.com/r-sudo-jeferson/Machina/job/internal/platform/db/sqlcgen"
)

var (
	ErrTenantSwitchForbidden                = fmt.Errorf("tenant switch forbidden")
	ErrTenantSwitchAuthorizationUnavailable = fmt.Errorf("tenant switch authorization unavailable")
)

type tenantSwitchAuthorizer interface {
	Authorize(context.Context, platformauthz.Request) (platformauthz.Decision, error)
}

func (c *TenantSwitchCoordinator) authorizeTenantSwitch(
	ctx context.Context,
	unit tenantSwitchUnit,
	request TenantSwitchRequest,
	presentedSessionHash []byte,
	bind sqlcgen.BindTenantSwitchIdempotencyRow,
) error {
	if c == nil || isNilTenantSwitchAuthorizer(c.authorizer) || ctx == nil || isNilTenantSwitchUnit(unit) {
		return ErrInvalidTenantSwitchCoordinatorConfig
	}

	identity, err := unit.GetSessionIdentity(ctx, presentedSessionHash)
	if err != nil {
		return fmt.Errorf("%w: resolve authenticated subject: %w", ErrTenantSwitchAuthorizationUnavailable, err)
	}
	if !identity.ID.Valid {
		return ErrTenantSwitchAuthorizationUnavailable
	}

	tenants, err := unit.ListSessionTenants(ctx, presentedSessionHash)
	if err != nil {
		return fmt.Errorf("%w: resolve active membership: %w", ErrTenantSwitchAuthorizationUnavailable, err)
	}
	var starterRole string
	targetMemberships := 0
	for _, tenant := range tenants {
		if tenant.TenantID != bind.ActiveTenantID {
			continue
		}
		targetMemberships++
		if tenant.Status != "active" || tenant.StarterRole == "" {
			return ErrTenantSwitchAuthorizationUnavailable
		}
		starterRole = tenant.StarterRole
	}
	if targetMemberships != 1 {
		return ErrTenantSwitchAuthorizationUnavailable
	}

	policy, err := unit.GetActivePolicySnapshot(ctx, bind.ActiveTenantID)
	if err != nil {
		return fmt.Errorf("%w: resolve active policy: %w", ErrTenantSwitchAuthorizationUnavailable, err)
	}
	if policy.Version <= 0 || !validTenantSwitchRequestHash(policy.SnapshotHash) {
		return ErrTenantSwitchAuthorizationUnavailable
	}

	correlationID := uuidText(request.CorrelationID)
	targetTenantID := uuidText(bind.ActiveTenantID)
	decision, err := c.authorizer.Authorize(ctx, platformauthz.Request{
		SubjectID:             uuidText(identity.ID),
		TenantID:              targetTenantID,
		WorkspaceID:           uuidText(bind.ActiveWorkspaceID),
		Action:                "tenant.switch",
		ResourceType:          "Tenant",
		ResourceID:            targetTenantID,
		RequiredPolicyVersion: uint64(policy.Version),
		CorrelationID:         correlationID,
		Context: map[string]string{
			"starter_role":      starterRole,
			"membership_status": "active",
		},
	})
	if err != nil {
		return fmt.Errorf("%w: cedar decision failed: %w", ErrTenantSwitchAuthorizationUnavailable, err)
	}
	if decision.DecisionID != correlationID || decision.PolicyVersion != uint64(policy.Version) {
		return ErrTenantSwitchAuthorizationUnavailable
	}
	if decision.Allowed {
		if decision.PolicySnapshotHash == "" || len(decision.ReasonCodes) != 0 || decision.DiagnosticRef != "" {
			return ErrTenantSwitchAuthorizationUnavailable
		}
		return nil
	}

	if tenantSwitchDenyIsOperational(decision.ReasonCodes) {
		return ErrTenantSwitchAuthorizationUnavailable
	}
	return ErrTenantSwitchForbidden
}

func tenantSwitchDenyIsOperational(reasonCodes []string) bool {
	if len(reasonCodes) == 0 {
		return true
	}
	for _, reason := range reasonCodes {
		switch reason {
		case "default_deny", "explicit_forbid":
		case "evaluation_error", "policy_unavailable", "stale_policy_version":
			return true
		default:
			return true
		}
	}
	return false
}

func isNilTenantSwitchAuthorizer(authorizer tenantSwitchAuthorizer) bool {
	if authorizer == nil {
		return true
	}
	value := reflect.ValueOf(authorizer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
