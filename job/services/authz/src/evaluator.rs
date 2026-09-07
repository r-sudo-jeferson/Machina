use cedar_policy::{Entities, PolicySet, Request};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionReason {
    DefaultDeny,
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
        _request: &Request,
        _required_policy_version: u64,
        snapshot: &VersionedPolicySet,
    ) -> Decision {
        // A missing policy is never an implicit permit. This is the first and
        // strongest service-boundary invariant; later policy evaluation may
        // only turn this into an allow after all validation/version/error
        // gates have succeeded.
        let _ = (&snapshot.policies, &snapshot.entities);
        Decision {
            allowed: false,
            policy_version: snapshot.version,
            reason_codes: vec![DecisionReason::DefaultDeny],
            diagnostic_ref: None,
        }
    }
}
