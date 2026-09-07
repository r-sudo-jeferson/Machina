use cedar_policy::{Context, Entities, EntityUid, PolicySet, Request, Schema};
use machina_authz::evaluator::{DecisionReason, Evaluator};
use machina_authz::policy_store::PolicySnapshot;

fn request() -> Request {
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
        Context::empty(),
        None,
    )
    .expect("request")
}

fn schema() -> Schema {
    let (schema, warnings) = Schema::from_cedarschema_str(
        r#"
        entity User = { department: String };
        entity PlatformContext = {};
        action "context.read" appliesTo {
            principal: User,
            resource: PlatformContext,
            context: {}
        };
        "#,
    )
    .expect("schema");
    assert_eq!(warnings.count(), 0, "test schema must have no warnings");
    schema
}

fn snapshot(version: u64, policies: PolicySet) -> PolicySnapshot {
    PolicySnapshot::try_new(version, schema(), policies, Entities::empty())
        .expect("test policy snapshot must validate")
}

fn matching_permit_policy() -> PolicySet {
    r#"
        permit(
            principal == User::"subject-a",
            action == Action::"context.read",
            resource == PlatformContext::"active"
        );
    "#
    .parse()
    .expect("policy")
}

fn matching_permit_and_forbid_policy() -> PolicySet {
    r#"
        permit(
            principal == User::"subject-a",
            action == Action::"context.read",
            resource == PlatformContext::"active"
        );
        forbid(
            principal == User::"subject-a",
            action == Action::"context.read",
            resource == PlatformContext::"active"
        );
    "#
    .parse()
    .expect("policies")
}

fn evaluation_error_policy() -> PolicySet {
    r#"
        permit(
            principal,
            action == Action::"context.read",
            resource == PlatformContext::"active"
        ) when {
            principal.department == "finance"
        };
    "#
    .parse()
    .expect("policy")
}

#[test]
fn empty_policy_store_denies_fail_closed() {
    let evaluator = Evaluator::new();
    let snapshot = snapshot(7, PolicySet::new());

    let decision = evaluator.decide(&request(), 7, &snapshot);

    assert!(!decision.allowed);
    assert_eq!(decision.policy_version, 7);
    assert_eq!(decision.reason_codes, vec![DecisionReason::DefaultDeny]);
    assert!(decision.diagnostic_ref.is_none());
}

#[test]
fn stale_policy_version_denies_before_evaluation() {
    let evaluator = Evaluator::new();
    let snapshot = snapshot(7, matching_permit_policy());

    let decision = evaluator.decide(&request(), 8, &snapshot);

    assert!(!decision.allowed);
    assert_eq!(decision.policy_version, 7);
    assert_eq!(
        decision.reason_codes,
        vec![DecisionReason::StalePolicyVersion]
    );
    assert!(decision.diagnostic_ref.is_none());
}

#[test]
fn newer_policy_snapshot_than_required_denies_before_evaluation() {
    let evaluator = Evaluator::new();
    let snapshot = snapshot(8, matching_permit_policy());

    let decision = evaluator.decide(&request(), 7, &snapshot);

    assert!(!decision.allowed);
    assert_eq!(decision.policy_version, 8);
    assert_eq!(
        decision.reason_codes,
        vec![DecisionReason::StalePolicyVersion]
    );
    assert!(decision.diagnostic_ref.is_none());
}

#[test]
fn matching_permit_policy_allows() {
    let evaluator = Evaluator::new();
    let snapshot = snapshot(7, matching_permit_policy());

    let decision = evaluator.decide(&request(), 7, &snapshot);

    assert!(decision.allowed, "matching permit must allow");
    assert_eq!(decision.policy_version, 7);
    assert!(decision.diagnostic_ref.is_none());
}

#[test]
fn matching_forbid_overrides_matching_permit() {
    let evaluator = Evaluator::new();
    let snapshot = snapshot(7, matching_permit_and_forbid_policy());

    let decision = evaluator.decide(&request(), 7, &snapshot);

    assert!(!decision.allowed, "matching forbid must override permit");
    assert_eq!(decision.policy_version, 7);
    assert_eq!(decision.reason_codes, vec![DecisionReason::ExplicitForbid]);
    assert!(decision.diagnostic_ref.is_none());
}

#[test]
fn cedar_evaluation_diagnostics_deny_without_leaking_raw_error() {
    let evaluator = Evaluator::new();
    let snapshot = snapshot(7, evaluation_error_policy());

    let decision = evaluator.decide(&request(), 7, &snapshot);

    assert!(!decision.allowed, "evaluation uncertainty must deny");
    assert_eq!(decision.policy_version, 7);
    assert_eq!(decision.reason_codes, vec![DecisionReason::EvaluationError]);
    assert_eq!(
        decision.diagnostic_ref.as_deref(),
        Some("cedar-evaluation-error")
    );
}
