use cedar_policy::{Entities, PolicySet, Schema, ValidationMode, Validator};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyLoadError {
    ValidationFailed,
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub version: u64,
    pub schema: Schema,
    pub policies: PolicySet,
    pub entities: Entities,
}

impl PolicySnapshot {
    pub fn try_new(
        version: u64,
        schema: Schema,
        policies: PolicySet,
        entities: Entities,
    ) -> Result<Self, PolicyLoadError> {
        let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed() {
            return Err(PolicyLoadError::ValidationFailed);
        }

        Ok(Self {
            version,
            schema,
            policies,
            entities,
        })
    }
}
