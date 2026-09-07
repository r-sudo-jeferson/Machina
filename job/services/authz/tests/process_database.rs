use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use machina_authz::proto::DecisionRequest;
use machina_authz::proto::authorization_service_client::AuthorizationServiceClient;
use tonic::transport::Channel;

const GRPC_ENV: &str = "MACHINA_AUTHZ_GRPC_ADDR";
const PROBE_ENV: &str = "MACHINA_AUTHZ_PROBE_ADDR";
const DATABASE_ENV: &str = "MACHINA_AUTHZ_DATABASE_URL";
const TEST_DATABASE_ENV: &str = "MACHINA_AUTHZ_TEST_DATABASE_URL";
const TENANT_ID: &str = "00000000-0000-0000-0000-0000000000a1";
const SNAPSHOT_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn binary_path() -> &'static str {
    env!("CARGO_BIN_EXE_machina-authz")
}

fn reserve_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve local port");
    let addr = listener.local_addr().expect("reserved local address");
    drop(listener);
    addr
}

fn distinct_addrs() -> (SocketAddr, SocketAddr) {
    let grpc = reserve_addr();
    let mut probe = reserve_addr();
    while probe == grpc {
        probe = reserve_addr();
    }
    (grpc, probe)
}

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn spawn(grpc_addr: SocketAddr, probe_addr: SocketAddr, database_url: &str) -> Self {
        let child = Command::new(binary_path())
            .env(GRPC_ENV, grpc_addr.to_string())
            .env(PROBE_ENV, probe_addr.to_string())
            .env(DATABASE_ENV, database_url)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start authz executable");
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
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

#[tokio::test]
#[ignore = "requires the pinned PostgreSQL policy-source harness"]
async fn executable_loads_active_tenant_policy_from_postgres_before_becoming_ready() {
    let database_url = env::var(TEST_DATABASE_ENV).expect("policy-source harness database URL");
    let (grpc_addr, probe_addr) = distinct_addrs();
    let _child = ChildGuard::spawn(grpc_addr, probe_addr, &database_url);

    await_http_status(probe_addr, "/healthz", 200).await;
    await_http_status(probe_addr, "/readyz", 200).await;

    let mut client = connect_client(grpc_addr).await;
    let response = client
        .decide(DecisionRequest {
            subject_id: "subject-a".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            workspace_id: "workspace-a".to_owned(),
            action: "context.read".to_owned(),
            resource_type: "PlatformContext".to_owned(),
            resource_id: "active".to_owned(),
            required_policy_version: 1,
            correlation_id: "corr-postgres-a".to_owned(),
            context: HashMap::from([
                ("starter_role".to_owned(), "owner".to_owned()),
                ("membership_status".to_owned(), "active".to_owned()),
            ]),
        })
        .await
        .expect("PostgreSQL-backed authorization response")
        .into_inner();

    assert!(
        response.allowed,
        "authorization denied: version={} hash={} reasons={:?} diagnostic_ref={}",
        response.policy_version,
        response.policy_snapshot_hash,
        response.reason_codes,
        response.diagnostic_ref
    );
    assert_eq!(response.policy_version, 1);
    assert_eq!(response.policy_snapshot_hash, SNAPSHOT_HASH);
    assert!(response.reason_codes.is_empty());
}
