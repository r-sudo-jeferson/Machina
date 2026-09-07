use cedar_policy::{Entities, PolicySet, Schema};

use crate::policy_store::{PolicyLoadError, PolicySnapshot};

pub const STARTER_POLICY_VERSION: u64 = 1;
pub const STARTER_POLICY_HASH: &str =
    "218c923c581ab330dce012de2f0b47e871ecb7574db36151f6b95ded84da8873";

const STARTER_SCHEMA: &str = r#"
entity User = {};
entity PlatformContext = {};
action "context.read" appliesTo {
    principal: User,
    resource: PlatformContext,
    context: {
        starter_role: String,
        membership_status: String
    }
};
"#;

const STARTER_POLICIES: &str = r#"
permit(
    principal,
    action == Action::"context.read",
    resource == PlatformContext::"active"
) when {
    context.membership_status == "active" &&
    context.starter_role == "owner"
};

permit(
    principal,
    action == Action::"context.read",
    resource == PlatformContext::"active"
) when {
    context.membership_status == "active" &&
    context.starter_role == "member"
};
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StarterPolicyError {
    InvalidSnapshotHash,
    SchemaInvalid,
    SchemaWarning,
    PolicyInvalid,
    ValidationFailed,
}

pub fn snapshot() -> Result<PolicySnapshot, StarterPolicyError> {
    let (schema, mut warnings) = Schema::from_cedarschema_str(STARTER_SCHEMA)
        .map_err(|_| StarterPolicyError::SchemaInvalid)?;
    if warnings.next().is_some() {
        return Err(StarterPolicyError::SchemaWarning);
    }

    let policies = STARTER_POLICIES
        .parse::<PolicySet>()
        .map_err(|_| StarterPolicyError::PolicyInvalid)?;

    PolicySnapshot::try_new(
        STARTER_POLICY_VERSION,
        STARTER_POLICY_HASH,
        schema,
        policies,
        Entities::empty(),
    )
    .map_err(|error| match error {
        PolicyLoadError::InvalidSnapshotHash => StarterPolicyError::InvalidSnapshotHash,
        PolicyLoadError::ValidationFailed => StarterPolicyError::ValidationFailed,
    })
}
