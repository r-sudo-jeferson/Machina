use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream};
use std::time::Duration;

use machina_authz::grpc::AuthorizationServiceHandler;
use machina_authz::policy_store::PolicyCache;
use machina_authz::proto::DecisionRequest;
use machina_authz::proto::authorization_service_client::AuthorizationServiceClient;
use machina_authz::runtime::{ProbeState, RuntimeConfig, serve};
use machina_authz::starter::{STARTER_POLICY_HASH, STARTER_POLICY_VERSION, snapshot};
use tokio::sync::watch;
use tonic::transport::Channel;

const TENANT_ID: &str = "00000000-0000-0000-0000-0000000000a1";

fn reserve_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("reserve local port");
    let addr = listener.local_addr().expect("reserved local address");
    drop(listener);
    addr
}

fn runtime_config() -> RuntimeConfig {
    let grpc_addr = reserve_addr();
    let mut probe_addr = reserve_addr();
    while probe_addr == grpc_addr {
        probe_addr = reserve_addr();
    }

    RuntimeConfig::parse(&grpc_addr.to_string(), &probe_addr.to_string()).expect("runtime config")
}

fn try_http_status(addr: SocketAddr, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(100)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(200)))
        .ok()?;

    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    stream.flush().ok()?;

    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse::<u16>()
        .ok()
}

async fn await_http_status(addr: SocketAddr, path: &str, expected: u16) {
    let path = path.to_owned();
    for _ in 0..100 {
        let attempt_path = path.clone();
        let status = tokio::task::spawn_blocking(move || try_http_status(addr, &attempt_path))
            .await
            .expect("probe client task");
        if status == Some(expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("{path} did not report HTTP {expected}");
}

async fn connect_client(addr: SocketAddr) -> AuthorizationServiceClient<Channel> {
    let endpoint = format!("http://{addr}");
    for _ in 0..100 {
        if let Ok(client) = AuthorizationServiceClient::connect(endpoint.clone()).await {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("authorization gRPC listener did not become reachable");
}

async fn shutdown_runtime(
    shutdown_tx: watch::Sender<bool>,
    server: tokio::task::JoinHandle<Result<(), machina_authz::runtime::RuntimeServeError>>,
) {
    shutdown_tx.send(true).expect("shutdown receiver alive");
    let result = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("runtime shutdown deadline")
        .expect("runtime task join");
    result.expect("clean runtime shutdown");
}

#[tokio::test]
async fn probe_listener_reports_liveness_and_reversible_readiness_until_shutdown() {
    let config = runtime_config();
    let probe_addr = config.probe_addr();
    let probes = ProbeState::new();
    let server_probes = probes.clone();
    let handler = AuthorizationServiceHandler::new(PolicyCache::new());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let server =
        tokio::spawn(async move { serve(config, handler, server_probes, shutdown_rx).await });

    await_http_status(probe_addr, "/healthz", 200).await;
    await_http_status(probe_addr, "/readyz", 503).await;

    probes.mark_ready();
    await_http_status(probe_addr, "/readyz", 200).await;

    probes.mark_not_ready();
    await_http_status(probe_addr, "/readyz", 503).await;

    probes.mark_ready();
    shutdown_runtime(shutdown_tx, server).await;
    assert!(!probes.is_ready(), "shutdown must withdraw readiness");
}

#[tokio::test]
async fn grpc_listener_serves_starter_authorization_over_real_network() {
    let config = runtime_config();
    let grpc_addr = config.grpc_addr();
    let probes = ProbeState::new();
    let mut cache = PolicyCache::new();
    cache.insert(TENANT_ID, snapshot().expect("starter policy snapshot"));
    let handler = AuthorizationServiceHandler::new(cache);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let server = tokio::spawn(async move { serve(config, handler, probes, shutdown_rx).await });
    let mut client = connect_client(grpc_addr).await;

    let response = client
        .decide(DecisionRequest {
            subject_id: "subject-a".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            workspace_id: "workspace-a".to_owned(),
            action: "context.read".to_owned(),
            resource_type: "PlatformContext".to_owned(),
            resource_id: "active".to_owned(),
            required_policy_version: STARTER_POLICY_VERSION,
            correlation_id: "corr-network-a".to_owned(),
            context: HashMap::from([
                ("starter_role".to_owned(), "owner".to_owned()),
                ("membership_status".to_owned(), "active".to_owned()),
            ]),
        })
        .await
        .expect("network authorization response")
        .into_inner();

    assert!(response.allowed);
    assert_eq!(response.policy_version, STARTER_POLICY_VERSION);
    assert_eq!(response.policy_snapshot_hash, STARTER_POLICY_HASH);
    assert!(response.reason_codes.is_empty());

    shutdown_runtime(shutdown_tx, server).await;
}
