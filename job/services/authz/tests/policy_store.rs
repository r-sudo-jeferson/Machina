use cedar_policy::{Entities, PolicySet, Schema};
use machina_authz::policy_store::{PolicyCache, PolicyLoadError, PolicySnapshot};

const TEST_SNAPSHOT_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const PERSISTED_SCHEMA_JSON: &str = include_str!("fixtures/starter-schema.json");
const PERSISTED_POLICIES: &str = include_str!("fixtures/starter.cedar");

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

fn valid_snapshot(version: u64) -> PolicySnapshot {
    PolicySnapshot::try_new(
        version,
        TEST_SNAPSHOT_HASH,
        schema(),
        PolicySet::new(),
        Entities::empty(),
    )
    .expect("valid snapshot")
}

#[test]
fn persisted_starter_fixture_is_valid_cedar() {
    let schema = Schema::from_json_str(PERSISTED_SCHEMA_JSON).expect("persisted JSON schema");
    let policies = PERSISTED_POLICIES
        .parse::<PolicySet>()
        .expect("persisted policies");

    PolicySnapshot::try_new(1, TEST_SNAPSHOT_HASH, schema, policies, Entities::empty())
        .expect("persisted starter fixture must validate");
}

#[test]
fn malformed_snapshot_hash_is_rejected_before_policy_load() {
    let result = PolicySnapshot::try_new(
        7,
        "not-a-sha256",
        schema(),
        PolicySet::new(),
        Entities::empty(),
    );

    assert!(matches!(result, Err(PolicyLoadError::InvalidSnapshotHash)));
}

#[test]
fn policy_with_unknown_principal_attribute_is_rejected_strictly() {
    let policies: PolicySet = r#"
        permit(
            principal,
            action == Action::"context.read",
            resource == PlatformContext::"active"
        ) when {
            principal.department == "finance"
        };
    "#
    .parse()
    .expect("policy syntax");

    let result =
        PolicySnapshot::try_new(7, TEST_SNAPSHOT_HASH, schema(), policies, Entities::empty());

    assert!(matches!(result, Err(PolicyLoadError::ValidationFailed)));
}

#[test]
fn cache_returns_snapshot_only_for_exact_tenant_and_policy_version() {
    let mut cache = PolicyCache::new();
    cache.insert("tenant-a", valid_snapshot(7));

    assert_eq!(
        cache.get_exact("tenant-a", 7).map(PolicySnapshot::version),
        Some(7)
    );
    assert!(cache.get_exact("tenant-a", 8).is_none());
    assert!(cache.get_exact("tenant-b", 7).is_none());
}

#[test]
fn invalidation_removes_only_the_target_tenant_snapshot() {
    let mut cache = PolicyCache::new();
    cache.insert("tenant-a", valid_snapshot(7));
    cache.insert("tenant-b", valid_snapshot(7));

    assert!(cache.invalidate("tenant-a"));
    assert!(cache.get_exact("tenant-a", 7).is_none());
    assert_eq!(
        cache.get_exact("tenant-b", 7).map(PolicySnapshot::version),
        Some(7)
    );
}

#[test]
fn newer_snapshot_replaces_the_previous_tenant_version() {
    let mut cache = PolicyCache::new();
    cache.insert("tenant-a", valid_snapshot(7));
    cache.insert("tenant-a", valid_snapshot(8));

    assert!(cache.get_exact("tenant-a", 7).is_none());
    assert_eq!(
        cache.get_exact("tenant-a", 8).map(PolicySnapshot::version),
        Some(8)
    );
}

#[test]
fn older_snapshot_cannot_downgrade_cached_tenant_version() {
    let mut cache = PolicyCache::new();
    cache.insert("tenant-a", valid_snapshot(8));
    cache.insert("tenant-a", valid_snapshot(7));

    assert!(cache.get_exact("tenant-a", 7).is_none());
    assert_eq!(
        cache.get_exact("tenant-a", 8).map(PolicySnapshot::version),
        Some(8)
    );
}
