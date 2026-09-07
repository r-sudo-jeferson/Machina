use cedar_policy::{Context, Entities, EntityUid, PolicySet, Request, Schema};
use machina_authz::evaluator::DecisionReason;
use machina_authz::policy_store::{PolicyCache, PolicySnapshot};
use machina_authz::service::{AuthorizationEngine, DecisionInput};

const TEST_SNAPSHOT_HASH: &str =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn cedar_request() -> Request {
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
        entity User = {};
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

fn permit_snapshot(version: u64) -> PolicySnapshot {
    let policies: PolicySet = r#"
        permit(
            principal == User::"subject-a",
            action == Action::"context.read",
            resource == PlatformContext::"active"
        );
    "#
    .parse()
    .expect("policy");

    PolicySnapshot::try_new(
        version,
        TEST_SNAPSHOT_HASH,
        schema(),
        policies,
        Entities::empty(),
    )
    .expect("valid snapshot")
}

#[test]
fn missing_policy_snapshot_denies_fail_closed() {
    let engine = AuthorizationEngine::new();
    let cache = PolicyCache::new();
    let input = DecisionInput::new("tenant-a", 7, cedar_request());

    let decision = engine.decide(&cache, &input);

    assert!(!decision.allowed);
    assert_eq!(decision.policy_version, 0);
    assert!(decision.policy_snapshot_hash.is_none());
    assert_eq!(
        decision.reason_codes,
        vec![DecisionReason::PolicyUnavailable]
    );
    assert!(decision.diagnostic_ref.is_none());
}

#[test]
fn exact_tenant_and_policy_snapshot_delegates_to_cedar() {
    let engine = AuthorizationEngine::new();
    let mut cache = PolicyCache::new();
    cache.insert("tenant-a", permit_snapshot(7));
    let input = DecisionInput::new("tenant-a", 7, cedar_request());

    let decision = engine.decide(&cache, &input);

    assert!(decision.allowed);
    assert_eq!(decision.policy_version, 7);
    assert_eq!(
        decision.policy_snapshot_hash.as_deref(),
        Some(TEST_SNAPSHOT_HASH)
    );
    assert!(decision.reason_codes.is_empty());
}

#[test]
fn another_tenants_snapshot_is_never_used_as_fallback() {
    let engine = AuthorizationEngine::new();
    let mut cache = PolicyCache::new();
    cache.insert("tenant-a", permit_snapshot(7));
    let input = DecisionInput::new("tenant-b", 7, cedar_request());

    let decision = engine.decide(&cache, &input);

    assert!(!decision.allowed);
    assert_eq!(decision.policy_version, 0);
    assert!(decision.policy_snapshot_hash.is_none());
    assert_eq!(
        decision.reason_codes,
        vec![DecisionReason::PolicyUnavailable]
    );
}
