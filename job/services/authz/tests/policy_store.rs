use cedar_policy::{Entities, PolicySet, Schema};
use machina_authz::policy_store::{PolicyCache, PolicyLoadError, PolicySnapshot};

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
    PolicySnapshot::try_new(version, schema(), PolicySet::new(), Entities::empty())
        .expect("valid snapshot")
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

    let result = PolicySnapshot::try_new(7, schema(), policies, Entities::empty());

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
