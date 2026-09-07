#[path = "../src/policy_store.rs"]
mod policy_store;

use cedar_policy::{Entities, PolicySet, Schema};
use policy_store::{PolicyLoadError, PolicySnapshot};

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
