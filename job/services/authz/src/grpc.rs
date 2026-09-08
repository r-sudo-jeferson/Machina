use std::str::FromStr;
use std::sync::RwLock;

use cedar_policy::{Context, EntityId, EntityTypeName, EntityUid, Request, RestrictedExpression};
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};

use crate::evaluator::DecisionReason;
use crate::policy_source::PostgresPolicySource;
use crate::policy_store::PolicyCache;
use crate::proto::authorization_service_server::AuthorizationService;
use crate::proto::{DecisionRequest, DecisionResponse};
use crate::service::{AuthorizationEngine, DecisionInput};

const PRINCIPAL_TYPE: &str = "User";
const ACTION_TYPE: &str = "Action";
const INVALID_REQUEST_MESSAGE: &str = "invalid authorization request";
const AUTHZ_STATE_UNAVAILABLE_MESSAGE: &str = "authorization state unavailable";

pub struct AuthorizationServiceHandler {
    engine: AuthorizationEngine,
    cache: RwLock<PolicyCache>,
    policy_source: Option<PostgresPolicySource>,
}

impl Default for AuthorizationServiceHandler {
    fn default() -> Self {
        Self::new(PolicyCache::new())
    }
}

impl AuthorizationServiceHandler {
    pub fn new(cache: PolicyCache) -> Self {
        Self {
            engine: AuthorizationEngine::new(),
            cache: RwLock::new(cache),
            policy_source: None,
        }
    }

    pub fn with_policy_source(cache: PolicyCache, policy_source: PostgresPolicySource) -> Self {
        Self {
            engine: AuthorizationEngine::new(),
            cache: RwLock::new(cache),
            policy_source: Some(policy_source),
        }
    }

    async fn refresh_policy_if_needed(
        &self,
        tenant_id: &str,
        required_policy_version: u64,
    ) -> Result<(), Status> {
        let Some(source) = &self.policy_source else {
            return Ok(());
        };

        if !source.is_healthy() {
            self.cache
                .write()
                .map_err(|_| Status::unavailable(AUTHZ_STATE_UNAVAILABLE_MESSAGE))?
                .invalidate(tenant_id);
            return Ok(());
        }

        let exact_snapshot_is_cached = self
            .cache
            .read()
            .map_err(|_| Status::unavailable(AUTHZ_STATE_UNAVAILABLE_MESSAGE))?
            .get_exact(tenant_id, required_policy_version)
            .is_some();
        if exact_snapshot_is_cached {
            return Ok(());
        }

        let loaded = source.load_active(tenant_id).await;
        let mut cache = self
            .cache
            .write()
            .map_err(|_| Status::unavailable(AUTHZ_STATE_UNAVAILABLE_MESSAGE))?;
        match loaded {
            Ok(Some(snapshot)) => cache.insert(tenant_id, snapshot),
            Ok(None) | Err(_) => {
                cache.invalidate(tenant_id);
            }
        }

        Ok(())
    }

    async fn decide_message(&self, message: DecisionRequest) -> Result<DecisionResponse, Status> {
        validate_message(&message)?;
        let request = cedar_request(&message)?;
        self.refresh_policy_if_needed(&message.tenant_id, message.required_policy_version)
            .await?;
        let input = DecisionInput::new(
            message.tenant_id.clone(),
            message.required_policy_version,
            request,
        );

        let decision = {
            let cache = self
                .cache
                .read()
                .map_err(|_| Status::unavailable(AUTHZ_STATE_UNAVAILABLE_MESSAGE))?;
            self.engine.decide(&cache, &input)
        };

        Ok(DecisionResponse {
            decision_id: message.correlation_id,
            allowed: decision.allowed,
            policy_version: decision.policy_version,
            reason_codes: decision
                .reason_codes
                .into_iter()
                .map(reason_code)
                .map(str::to_owned)
                .collect(),
            diagnostic_ref: decision.diagnostic_ref.unwrap_or_default(),
            policy_snapshot_hash: decision.policy_snapshot_hash.unwrap_or_default(),
        })
    }
}

#[tonic::async_trait]
impl AuthorizationService for AuthorizationServiceHandler {
    async fn decide(
        &self,
        request: TonicRequest<DecisionRequest>,
    ) -> Result<TonicResponse<DecisionResponse>, Status> {
        self.decide_message(request.into_inner())
            .await
            .map(TonicResponse::new)
    }
}

fn validate_message(message: &DecisionRequest) -> Result<(), Status> {
    if message.subject_id.is_empty()
        || !is_canonical_uuid(&message.tenant_id)
        || message.action.is_empty()
        || message.resource_type.is_empty()
        || message.resource_id.is_empty()
        || message.required_policy_version == 0
        || message.correlation_id.is_empty()
    {
        return Err(Status::invalid_argument(INVALID_REQUEST_MESSAGE));
    }

    Ok(())
}

fn is_canonical_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }

    bytes.iter().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => *byte == b'-',
        _ => byte.is_ascii_hexdigit(),
    })
}

fn cedar_request(message: &DecisionRequest) -> Result<Request, Status> {
    let principal = entity_uid(PRINCIPAL_TYPE, &message.subject_id)?;
    let action = entity_uid(ACTION_TYPE, &message.action)?;
    let resource = entity_uid(&message.resource_type, &message.resource_id)?;
    let context = Context::from_pairs(
        message
            .context
            .iter()
            .map(|(key, value)| (key.clone(), RestrictedExpression::new_string(value.clone()))),
    )
    .map_err(|_| Status::invalid_argument(INVALID_REQUEST_MESSAGE))?;

    Request::new(principal, action, resource, context, None)
        .map_err(|_| Status::invalid_argument(INVALID_REQUEST_MESSAGE))
}

fn entity_uid(entity_type: &str, entity_id: &str) -> Result<EntityUid, Status> {
    let entity_type = EntityTypeName::from_str(entity_type)
        .map_err(|_| Status::invalid_argument(INVALID_REQUEST_MESSAGE))?;
    let entity_id = EntityId::from_str(entity_id)
        .map_err(|_| Status::invalid_argument(INVALID_REQUEST_MESSAGE))?;
    Ok(EntityUid::from_type_name_and_id(entity_type, entity_id))
}

fn reason_code(reason: DecisionReason) -> &'static str {
    match reason {
        DecisionReason::DefaultDeny => "default_deny",
        DecisionReason::EvaluationError => "evaluation_error",
        DecisionReason::ExplicitForbid => "explicit_forbid",
        DecisionReason::PolicyUnavailable => "policy_unavailable",
        DecisionReason::StalePolicyVersion => "stale_policy_version",
    }
}
