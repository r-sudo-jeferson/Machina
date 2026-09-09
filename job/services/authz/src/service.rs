use cedar_policy::Request;

use crate::evaluator::{Decision, DecisionReason, Evaluator};
use crate::policy_store::PolicyCache;

#[derive(Debug)]
pub struct DecisionInput {
    tenant_id: String,
    required_policy_version: u64,
    request: Request,
}

impl DecisionInput {
    pub fn new(
        tenant_id: impl Into<String>,
        required_policy_version: u64,
        request: Request,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            required_policy_version,
            request,
        }
    }
}

#[derive(Debug, Default)]
pub struct AuthorizationEngine {
    evaluator: Evaluator,
}

impl AuthorizationEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn decide(&self, cache: &PolicyCache, input: &DecisionInput) -> Decision {
        let Some(snapshot) = cache.get(&input.tenant_id) else {
            return Decision {
                allowed: false,
                policy_version: 0,
                policy_snapshot_hash: None,
                reason_codes: vec![DecisionReason::PolicyUnavailable],
                diagnostic_ref: None,
            };
        };

        self.evaluator
            .decide(&input.request, input.required_policy_version, snapshot)
    }
}
