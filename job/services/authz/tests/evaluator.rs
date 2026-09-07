#[path = "../src/evaluator.rs"]
mod evaluator;

use cedar_policy::{Context, Entities, EntityUid, PolicySet, Request};
use evaluator::{DecisionReason, Evaluator, VersionedPolicySet};

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

#[test]
fn empty_policy_store_denies_fail_closed() {
    let evaluator = Evaluator::new();
    let snapshot = VersionedPolicySet::new(7, PolicySet::new(), Entities::empty());

    let decision = evaluator.decide(&request(), 7, &snapshot);

    assert!(!decision.allowed);
    assert_eq!(decision.policy_version, 7);
    assert_eq!(decision.reason_codes, vec![DecisionReason::DefaultDeny]);
    assert!(decision.diagnostic_ref.is_none());
}

#[test]
fn stale_policy_version_denies_before_evaluation() {
    let evaluator = Evaluator::new();
    let snapshot = VersionedPolicySet::new(7, matching_permit_policy(), Entities::empty());

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
fn matching_permit_policy_allows() {
    let evaluator = Evaluator::new();
    let snapshot = VersionedPolicySet::new(7, matching_permit_policy(), Entities::empty());

    let decision = evaluator.decide(&request(), 7, &snapshot);

    assert!(decision.allowed, "matching permit must allow");
    assert_eq!(decision.policy_version, 7);
    assert!(decision.diagnostic_ref.is_none());
}
