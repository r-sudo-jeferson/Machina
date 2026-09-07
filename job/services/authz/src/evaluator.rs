use cedar_policy::{Authorizer, Decision as CedarDecision, Entities, PolicySet, Request};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionReason {
    DefaultDeny,
    ExplicitForbid,
    StalePolicyVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub policy_version: u64,
    pub reason_codes: Vec<DecisionReason>,
    pub diagnostic_ref: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VersionedPolicySet {
    pub version: u64,
    pub policies: PolicySet,
    pub entities: Entities,
}

impl VersionedPolicySet {
    pub fn new(version: u64, policies: PolicySet, entities: Entities) -> Self {
        Self {
            version,
            policies,
            entities,
        }
    }
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
        snapshot: &VersionedPolicySet,
    ) -> Decision {
        if snapshot.version < required_policy_version {
            return Decision {
                allowed: false,
                policy_version: snapshot.version,
                reason_codes: vec![DecisionReason::StalePolicyVersion],
                diagnostic_ref: None,
            };
        }

        let response =
            Authorizer::new().is_authorized(request, &snapshot.policies, &snapshot.entities);

        // Cedar may continue evaluating other policies after an evaluation
        // error. Machina therefore never turns a response containing an error
        // diagnostic into an allow.
        if response.diagnostics().errors().next().is_some() {
            return Decision {
                allowed: false,
                policy_version: snapshot.version,
                reason_codes: vec![DecisionReason::DefaultDeny],
                diagnostic_ref: None,
            };
        }

        if response.decision() == CedarDecision::Allow {
            return Decision {
                allowed: true,
                policy_version: snapshot.version,
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
            policy_version: snapshot.version,
            reason_codes: vec![reason],
            diagnostic_ref: None,
        }
    }
}
