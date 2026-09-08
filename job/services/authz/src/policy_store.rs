use std::collections::HashMap;

use cedar_policy::{Entities, PolicySet, Schema, ValidationMode, Validator};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyLoadError {
    InvalidSnapshotHash,
    ValidationFailed,
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    version: u64,
    snapshot_hash: String,
    schema: Schema,
    policies: PolicySet,
    entities: Entities,
}

impl PolicySnapshot {
    pub fn try_new(
        version: u64,
        snapshot_hash: impl Into<String>,
        schema: Schema,
        policies: PolicySet,
        entities: Entities,
    ) -> Result<Self, PolicyLoadError> {
        let snapshot_hash = snapshot_hash.into();
        if snapshot_hash.len() != 64
            || !snapshot_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(PolicyLoadError::InvalidSnapshotHash);
        }

        let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed() {
            return Err(PolicyLoadError::ValidationFailed);
        }

        Ok(Self {
            version,
            snapshot_hash,
            schema,
            policies,
            entities,
        })
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn snapshot_hash(&self) -> &str {
        &self.snapshot_hash
    }

    pub(crate) fn schema(&self) -> &Schema {
        &self.schema
    }

    pub(crate) fn evaluation_parts(&self) -> (&PolicySet, &Entities) {
        (&self.policies, &self.entities)
    }
}

#[derive(Debug, Default)]
pub struct PolicyCache {
    snapshots: HashMap<String, PolicySnapshot>,
}

impl PolicyCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, tenant_id: &str, snapshot: PolicySnapshot) {
        if self
            .snapshots
            .get(tenant_id)
            .is_some_and(|current| current.version() >= snapshot.version())
        {
            return;
        }
        self.snapshots.insert(tenant_id.to_owned(), snapshot);
    }

    pub fn get(&self, tenant_id: &str) -> Option<&PolicySnapshot> {
        self.snapshots.get(tenant_id)
    }

    pub fn get_exact(
        &self,
        tenant_id: &str,
        required_policy_version: u64,
    ) -> Option<&PolicySnapshot> {
        self.get(tenant_id)
            .filter(|snapshot| snapshot.version() == required_policy_version)
    }

    pub fn invalidate(&mut self, tenant_id: &str) -> bool {
        self.snapshots.remove(tenant_id).is_some()
    }
}
