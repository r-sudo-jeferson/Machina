use crate::policy_store::PolicySnapshot;
use cedar_policy::{Authorizer, Decision as CedarDecision, Request};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionReason {
    DefaultDeny,
    EvaluationError,
    ExplicitForbid,
    PolicyUnavailable,
    StalePolicyVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub policy_version: u64,
    pub policy_snapshot_hash: Option<String>,
    pub reason_codes: Vec<DecisionReason>,
    pub diagnostic_ref: Option<String>,
}

#[derive(Debug, Default)]
pub struct Evaluator;

impl Evaluator {
    pub fn new() -> Self {
        Self
    }

    pub fn decide(
        &self,
        request: &Request,
        required_policy_version: u64,
        snapshot: &PolicySnapshot,
    ) -> Decision {
        let policy_version = snapshot.version();
        let policy_snapshot_hash = Some(snapshot.snapshot_hash().to_owned());
        if policy_version != required_policy_version {
            return Decision {
                allowed: false,
                policy_version,
                policy_snapshot_hash,
                reason_codes: vec![DecisionReason::StalePolicyVersion],
                diagnostic_ref: None,
            };
        }

        let Some(principal) = request.principal() else {
            return request_validation_error(policy_version, snapshot.snapshot_hash());
        };
        let Some(action) = request.action() else {
            return request_validation_error(policy_version, snapshot.snapshot_hash());
        };
        let Some(resource) = request.resource() else {
            return request_validation_error(policy_version, snapshot.snapshot_hash());
        };
        let Some(context) = request.context() else {
            return request_validation_error(policy_version, snapshot.snapshot_hash());
        };

        let validated_request = match Request::new(
            principal.clone(),
            action.clone(),
            resource.clone(),
            context.clone(),
            Some(snapshot.schema()),
        ) {
            Ok(request) => request,
            Err(_) => {
                return request_validation_error(policy_version, snapshot.snapshot_hash());
            }
        };

        let (policies, entities) = snapshot.evaluation_parts();
        let response = Authorizer::new().is_authorized(&validated_request, policies, entities);

        // Cedar can continue evaluating other policies after an evaluation
        // error. Machina treats any such uncertainty as a hard deny and only
        // exposes a stable safe reference, never the raw Cedar diagnostic.
        if response.diagnostics().errors().next().is_some() {
            return Decision {
                allowed: false,
                policy_version,
                policy_snapshot_hash,
                reason_codes: vec![DecisionReason::EvaluationError],
                diagnostic_ref: Some("cedar-evaluation-error".to_owned()),
            };
        }

        if response.decision() == CedarDecision::Allow {
            return Decision {
                allowed: true,
                policy_version,
                policy_snapshot_hash,
                reason_codes: Vec::new(),
                diagnostic_ref: None,
            };
        }

        let reason = if response.diagnostics().reason().next().is_some() {
            DecisionReason::ExplicitForbid
        } else {
            DecisionReason::DefaultDeny
        };

        Decision {
            allowed: false,
            policy_version,
            policy_snapshot_hash,
            reason_codes: vec![reason],
            diagnostic_ref: None,
        }
    }
}

fn request_validation_error(policy_version: u64, policy_snapshot_hash: &str) -> Decision {
    Decision {
        allowed: false,
        policy_version,
        policy_snapshot_hash: Some(policy_snapshot_hash.to_owned()),
        reason_codes: vec![DecisionReason::EvaluationError],
        diagnostic_ref: Some("cedar-request-validation-error".to_owned()),
    }
}
