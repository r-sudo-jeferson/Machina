use cedar_policy::{Context, EntityUid, Request, RestrictedExpression};
use machina_authz::evaluator::{DecisionReason, Evaluator};
use machina_authz::starter::{STARTER_POLICY_VERSION, snapshot};

fn request_for(action: &str, resource: &str, role: Option<&str>, status: Option<&str>) -> Request {
    let mut context = Vec::new();
    if let Some(role) = role {
        context.push((
            "starter_role".to_owned(),
            RestrictedExpression::new_string(role.to_owned()),
        ));
    }
    if let Some(status) = status {
        context.push((
            "membership_status".to_owned(),
            RestrictedExpression::new_string(status.to_owned()),
        ));
    }

    Request::new(
        "User::\"subject-a\""
            .parse::<EntityUid>()
            .expect("principal"),
        format!("Action::\"{action}\"")
            .parse::<EntityUid>()
            .expect("action"),
        resource.parse::<EntityUid>().expect("resource"),
        Context::from_pairs(context).expect("context"),
        None,
    )
    .expect("unvalidated request")
}

fn context_read_request(role: Option<&str>, status: Option<&str>) -> Request {
    request_for("context.read", "PlatformContext::\"active\"", role, status)
}

fn tenant_switch_request(role: Option<&str>, status: Option<&str>) -> Request {
    request_for(
        "tenant.switch",
        "Tenant::\"20000000-0000-0000-0000-0000000000a1\"",
        role,
        status,
    )
}

#[test]
fn active_owner_can_read_platform_context() {
    let snapshot = snapshot().expect("starter snapshot");
    let decision = Evaluator::new().decide(
        &context_read_request(Some("owner"), Some("active")),
        STARTER_POLICY_VERSION,
        &snapshot,
    );

    assert!(decision.allowed);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn active_member_can_read_platform_context() {
    let snapshot = snapshot().expect("starter snapshot");
    let decision = Evaluator::new().decide(
        &context_read_request(Some("member"), Some("active")),
        STARTER_POLICY_VERSION,
        &snapshot,
    );

    assert!(decision.allowed);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn active_owner_can_switch_tenant() {
    let snapshot = snapshot().expect("starter snapshot");
    let decision = Evaluator::new().decide(
        &tenant_switch_request(Some("owner"), Some("active")),
        STARTER_POLICY_VERSION,
        &snapshot,
    );

    assert!(
        decision.allowed,
        "active owner must be allowed to switch tenant"
    );
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn active_member_can_switch_tenant() {
    let snapshot = snapshot().expect("starter snapshot");
    let decision = Evaluator::new().decide(
        &tenant_switch_request(Some("member"), Some("active")),
        STARTER_POLICY_VERSION,
        &snapshot,
    );

    assert!(
        decision.allowed,
        "active member must be allowed to switch tenant"
    );
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn tenant_switch_inactive_or_unknown_context_denies() {
    let snapshot = snapshot().expect("starter snapshot");
    for (role, status) in [
        (Some("owner"), Some("revoked")),
        (Some("member"), Some("inactive")),
        (Some("admin"), Some("active")),
    ] {
        let decision = Evaluator::new().decide(
            &tenant_switch_request(role, status),
            STARTER_POLICY_VERSION,
            &snapshot,
        );
        assert!(!decision.allowed, "invalid tenant-switch context must deny");
    }
}

#[test]
fn tenant_switch_missing_context_denies_fail_closed() {
    let snapshot = snapshot().expect("starter snapshot");
    let decision = Evaluator::new().decide(
        &tenant_switch_request(None, Some("active")),
        STARTER_POLICY_VERSION,
        &snapshot,
    );

    assert!(!decision.allowed);
}

#[test]
fn tenant_switch_wrong_action_or_resource_denies() {
    let snapshot = snapshot().expect("starter snapshot");
    for request in [
        request_for(
            "context.read",
            "Tenant::\"20000000-0000-0000-0000-0000000000a1\"",
            Some("owner"),
            Some("active"),
        ),
        request_for(
            "tenant.switch",
            "PlatformContext::\"active\"",
            Some("owner"),
            Some("active"),
        ),
    ] {
        let decision = Evaluator::new().decide(&request, STARTER_POLICY_VERSION, &snapshot);
        assert!(!decision.allowed, "wrong action/resource pair must deny");
    }
}

#[test]
fn starter_snapshot_remains_strict_valid_and_warning_free() {
    snapshot().expect("starter schema and policies must parse and strict-validate");
}

#[test]
fn unknown_role_is_denied_by_default() {
    let snapshot = snapshot().expect("starter snapshot");
    let decision = Evaluator::new().decide(
        &context_read_request(Some("admin"), Some("active")),
        STARTER_POLICY_VERSION,
        &snapshot,
    );

    assert!(!decision.allowed);
    assert_eq!(decision.reason_codes, vec![DecisionReason::DefaultDeny]);
}

#[test]
fn revoked_membership_is_denied_by_default() {
    let snapshot = snapshot().expect("starter snapshot");
    let decision = Evaluator::new().decide(
        &context_read_request(Some("owner"), Some("revoked")),
        STARTER_POLICY_VERSION,
        &snapshot,
    );

    assert!(!decision.allowed);
    assert_eq!(decision.reason_codes, vec![DecisionReason::DefaultDeny]);
}

#[test]
fn missing_server_derived_membership_context_denies_as_validation_error() {
    let snapshot = snapshot().expect("starter snapshot");
    let decision = Evaluator::new().decide(
        &context_read_request(None, Some("active")),
        STARTER_POLICY_VERSION,
        &snapshot,
    );

    assert!(!decision.allowed);
    assert_eq!(decision.reason_codes, vec![DecisionReason::EvaluationError]);
    assert_eq!(
        decision.diagnostic_ref.as_deref(),
        Some("cedar-request-validation-error")
    );
}
