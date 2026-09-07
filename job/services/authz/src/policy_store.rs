use cedar_policy::{Entities, PolicySet, Schema, ValidationMode, Validator};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyLoadError {
    ValidationFailed,
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    version: u64,
    policies: PolicySet,
    entities: Entities,
}

impl PolicySnapshot {
    pub fn try_new(
        version: u64,
        schema: Schema,
        policies: PolicySet,
        entities: Entities,
    ) -> Result<Self, PolicyLoadError> {
        let validation = Validator::new(schema).validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed() {
            return Err(PolicyLoadError::ValidationFailed);
        }

        Ok(Self {
            version,
            policies,
            entities,
        })
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub(crate) fn evaluation_parts(&self) -> (&PolicySet, &Entities) {
        (&self.policies, &self.entities)
    }
}
