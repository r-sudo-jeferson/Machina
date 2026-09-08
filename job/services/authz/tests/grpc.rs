use std::collections::HashMap;
use std::future::Future;
use std::task::{Context as TaskContext, Poll, Waker};

use cedar_policy::{Entities, PolicySet, Schema};
use machina_authz::grpc::AuthorizationServiceHandler;
use machina_authz::policy_store::{PolicyCache, PolicySnapshot};
use machina_authz::proto::DecisionRequest;
use machina_authz::proto::authorization_service_server::AuthorizationService;
use tonic::{Code, Request as TonicRequest};

const SNAPSHOT_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TENANT_ID: &str = "00000000-0000-0000-0000-0000000000a1";

fn ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = TaskContext::from_waker(waker);
    let mut future = Box::pin(future);

    match future.as_mut().poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("authorization handler must not suspend on external work"),
    }
}

fn schema() -> Schema {
    let (schema, warnings) = Schema::from_cedarschema_str(
        r#"
        entity User = {};
        entity PlatformContext = {};
        action "context.read" appliesTo {
            principal: User,
            resource: PlatformContext,
            context: {
                locale: String
            }
        };
        "#,
    )
    .expect("schema");
    assert_eq!(warnings.count(), 0, "test schema must have no warnings");
    schema
}

fn permit_snapshot(version: u64) -> PolicySnapshot {
    let policies: PolicySet = r#"
        permit(
            principal == User::"subject-a",
            action == Action::"context.read",
            resource == PlatformContext::"active"
        ) when {
            context.locale == "pt-BR"
        };
    "#
    .parse()
    .expect("policy");

    PolicySnapshot::try_new(
        version,
        SNAPSHOT_HASH,
        schema(),
        policies,
        Entities::empty(),
    )
    .expect("valid snapshot")
}

fn request(tenant_id: &str, required_policy_version: u64) -> DecisionRequest {
    DecisionRequest {
        subject_id: "subject-a".to_owned(),
        tenant_id: tenant_id.to_owned(),
        workspace_id: "workspace-a".to_owned(),
        action: "context.read".to_owned(),
        resource_type: "PlatformContext".to_owned(),
        resource_id: "active".to_owned(),
        required_policy_version,
        correlation_id: "corr-a".to_owned(),
        context: HashMap::from([("locale".to_owned(), "pt-BR".to_owned())]),
    }
}

fn assert_tonic_service<T: AuthorizationService>() {}

#[test]
fn handler_implements_canonical_tonic_service_contract() {
    assert_tonic_service::<AuthorizationServiceHandler>();
}

#[test]
fn decide_denies_fail_closed_when_exact_policy_snapshot_is_missing() {
    let handler = AuthorizationServiceHandler::new(PolicyCache::new());

    let response = ready(AuthorizationService::decide(
        &handler,
        TonicRequest::new(request(TENANT_ID, 7)),
    ))
    .expect("transport response")
    .into_inner();

    assert!(!response.allowed);
    assert_eq!(response.policy_version, 0);
    assert_eq!(response.reason_codes, vec!["policy_unavailable"]);
    assert!(response.policy_snapshot_hash.is_empty());
}

#[test]
fn decide_translates_typed_request_context_and_preserves_cedar_allow() {
    let mut cache = PolicyCache::new();
    cache.insert(TENANT_ID, permit_snapshot(7));
    let handler = AuthorizationServiceHandler::new(cache);

    let response = ready(AuthorizationService::decide(
        &handler,
        TonicRequest::new(request(TENANT_ID, 7)),
    ))
    .expect("transport response")
    .into_inner();

    assert!(response.allowed);
    assert_eq!(response.policy_version, 7);
    assert!(response.reason_codes.is_empty());
    assert_eq!(response.policy_snapshot_hash, SNAPSHOT_HASH);
}

#[test]
fn structurally_invalid_cedar_identity_is_rejected_before_evaluation() {
    let mut cache = PolicyCache::new();
    cache.insert(TENANT_ID, permit_snapshot(7));
    let handler = AuthorizationServiceHandler::new(cache);
    let mut malformed = request(TENANT_ID, 7);
    malformed.resource_type = "Platform Context".to_owned();

    let status = ready(AuthorizationService::decide(
        &handler,
        TonicRequest::new(malformed),
    ))
    .expect_err("invalid resource type must not reach Cedar");

    assert_eq!(status.code(), Code::InvalidArgument);
}

#[test]
fn malformed_tenant_identity_is_rejected_before_policy_lookup() {
    let handler = AuthorizationServiceHandler::new(PolicyCache::new());

    let status = ready(AuthorizationService::decide(
        &handler,
        TonicRequest::new(request("not-a-uuid", 7)),
    ))
    .expect_err("malformed tenant identity must not reach policy lookup");

    assert_eq!(status.code(), Code::InvalidArgument);
}
