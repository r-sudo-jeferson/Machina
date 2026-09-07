use cedar_policy::{Context, EntityUid, Request, RestrictedExpression};
use machina_authz::evaluator::{DecisionReason, Evaluator};
use machina_authz::starter::{STARTER_POLICY_VERSION, snapshot};

fn request(role: Option<&str>, status: Option<&str>) -> Request {
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
        "Action::\"context.read\""
            .parse::<EntityUid>()
            .expect("action"),
        "PlatformContext::\"active\""
            .parse::<EntityUid>()
            .expect("resource"),
        Context::from_pairs(context).expect("context"),
        None,
    )
    .expect("unvalidated request")
}

#[test]
fn active_owner_can_read_platform_context() {
    let snapshot = snapshot().expect("starter snapshot");
    let decision = Evaluator::new().decide(
        &request(Some("owner"), Some("active")),
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
        &request(Some("member"), Some("active")),
        STARTER_POLICY_VERSION,
        &snapshot,
    );

    assert!(decision.allowed);
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn unknown_role_is_denied_by_default() {
    let snapshot = snapshot().expect("starter snapshot");
    let decision = Evaluator::new().decide(
        &request(Some("admin"), Some("active")),
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
        &request(Some("owner"), Some("revoked")),
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
        &request(None, Some("active")),
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
