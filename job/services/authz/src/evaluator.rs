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
        if policy_version != required_policy_version {
            return Decision {
                allowed: false,
                policy_version,
                reason_codes: vec![DecisionReason::StalePolicyVersion],
                diagnostic_ref: None,
            };
        }

        let (policies, entities) = snapshot.evaluation_parts();
        let response = Authorizer::new().is_authorized(request, policies, entities);

        // Cedar can continue evaluating other policies after an evaluation
        // error. Machina treats any such uncertainty as a hard deny and only
        // exposes a stable safe reference, never the raw Cedar diagnostic.
        if response.diagnostics().errors().next().is_some() {
            return Decision {
                allowed: false,
                policy_version,
                reason_codes: vec![DecisionReason::EvaluationError],
                diagnostic_ref: Some("cedar-evaluation-error".to_owned()),
            };
        }

        if response.decision() == CedarDecision::Allow {
            return Decision {
                allowed: true,
                policy_version,
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
            reason_codes: vec![reason],
            diagnostic_ref: None,
        }
    }
}
