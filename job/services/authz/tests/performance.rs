use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::time::{Duration, Instant};

use cedar_policy::{Context, EntityUid, Request, RestrictedExpression};
use machina_authz::evaluator::Evaluator;
use machina_authz::grpc::AuthorizationServiceHandler;
use machina_authz::policy_store::PolicyCache;
use machina_authz::proto::DecisionRequest;
use machina_authz::proto::authorization_service_client::AuthorizationServiceClient;
use machina_authz::runtime::{ProbeState, RuntimeConfig, serve};
use machina_authz::starter::{STARTER_POLICY_VERSION, snapshot};
use tokio::sync::watch;
use tonic::transport::Channel;

const TENANT_ID: &str = "00000000-0000-0000-0000-0000000000a1";
const P95_TARGET: Duration = Duration::from_millis(10);
const DIRECT_WARMUP: usize = 1_000;
const DIRECT_SAMPLES: usize = 20_000;
const GRPC_WARMUP: usize = 256;
const GRPC_CONCURRENCY: usize = 16;
const GRPC_REQUESTS_PER_WORKER: usize = 1_000;

#[derive(Debug, Clone, Copy)]
struct LatencySummary {
    p50: Duration,
    p95: Duration,
    p99: Duration,
}

fn summarize(samples: &mut [Duration]) -> LatencySummary {
    assert!(
        !samples.is_empty(),
        "performance sample set must not be empty"
    );
    samples.sort_unstable();
    LatencySummary {
        p50: percentile(samples, 50),
        p95: percentile(samples, 95),
        p99: percentile(samples, 99),
    }
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    let rank = ((samples.len() - 1) * percentile).div_ceil(100);
    samples[rank]
}

fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

fn print_summary(name: &str, summary: LatencySummary, samples: usize, wall: Duration) {
    let throughput = samples as f64 / wall.as_secs_f64();
    eprintln!(
        "authz_perf name={name} samples={samples} p50_us={:.3} p95_us={:.3} p99_us={:.3} throughput_rps={throughput:.1} errors=0",
        micros(summary.p50),
        micros(summary.p95),
        micros(summary.p99),
    );
}

fn cedar_request() -> Request {
    let context = Context::from_pairs([
        (
            "starter_role".to_owned(),
            RestrictedExpression::new_string("owner".to_owned()),
        ),
        (
            "membership_status".to_owned(),
            RestrictedExpression::new_string("active".to_owned()),
        ),
    ])
    .expect("starter performance context");

    Request::new(
        "User::\"subject-a\""
            .parse::<EntityUid>()
            .expect("performance principal"),
        "Action::\"context.read\""
            .parse::<EntityUid>()
            .expect("performance action"),
        "PlatformContext::\"active\""
            .parse::<EntityUid>()
            .expect("performance resource"),
        context,
        None,
    )
    .expect("performance request")
}

fn decision_request() -> DecisionRequest {
    DecisionRequest {
        subject_id: "subject-a".to_owned(),
        tenant_id: TENANT_ID.to_owned(),
        workspace_id: "workspace-a".to_owned(),
        action: "context.read".to_owned(),
        resource_type: "PlatformContext".to_owned(),
        resource_id: "active".to_owned(),
        required_policy_version: STARTER_POLICY_VERSION,
        correlation_id: "perf-authz".to_owned(),
        context: HashMap::from([
            ("starter_role".to_owned(), "owner".to_owned()),
            ("membership_status".to_owned(), "active".to_owned()),
        ]),
    }
}

fn reserve_addr() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    let addr = listener.local_addr().expect("reserved loopback address");
    drop(listener);
    addr
}

fn runtime_config() -> RuntimeConfig {
    let grpc_addr = reserve_addr();
    let mut probe_addr = reserve_addr();
    while probe_addr == grpc_addr {
        probe_addr = reserve_addr();
    }
    RuntimeConfig::parse(&grpc_addr.to_string(), &probe_addr.to_string())
        .expect("performance runtime config")
}

async fn connect_client(addr: SocketAddr) -> AuthorizationServiceClient<Channel> {
    let endpoint = format!("http://{addr}");
    for _ in 0..100 {
        if let Ok(client) = AuthorizationServiceClient::connect(endpoint.clone()).await {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("authorization performance listener did not become reachable");
}

#[test]
#[ignore = "Task 4 performance evidence; run via job/scripts/authzperf/run.sh"]
fn evaluator_hot_cache_p95_is_below_contract_target() {
    let evaluator = Evaluator::new();
    let snapshot = snapshot().expect("starter policy snapshot");
    let request = cedar_request();

    for _ in 0..DIRECT_WARMUP {
        let decision = evaluator.decide(&request, STARTER_POLICY_VERSION, &snapshot);
        assert!(decision.allowed, "warmup authorization must allow");
    }

    let wall_started = Instant::now();
    let mut samples = Vec::with_capacity(DIRECT_SAMPLES);
    for _ in 0..DIRECT_SAMPLES {
        let started = Instant::now();
        let decision = evaluator.decide(&request, STARTER_POLICY_VERSION, &snapshot);
        samples.push(started.elapsed());
        assert!(decision.allowed, "measured authorization must allow");
    }
    let wall = wall_started.elapsed();
    let summary = summarize(&mut samples);
    print_summary("evaluator_hot_cache", summary, DIRECT_SAMPLES, wall);

    assert!(
        summary.p95 < P95_TARGET,
        "evaluator p95 {:.3}us exceeded contract target {:.3}us",
        micros(summary.p95),
        micros(P95_TARGET)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Task 4 performance evidence; run via job/scripts/authzperf/run.sh"]
async fn grpc_hot_cache_p95_is_below_contract_target() {
    let config = runtime_config();
    let grpc_addr = config.grpc_addr();
    let mut cache = PolicyCache::new();
    cache.insert(TENANT_ID, snapshot().expect("starter policy snapshot"));
    let handler = AuthorizationServiceHandler::new(cache);
    let probes = ProbeState::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(async move { serve(config, handler, probes, shutdown_rx).await });
    let mut client = connect_client(grpc_addr).await;

    for _ in 0..GRPC_WARMUP {
        let response = client
            .decide(decision_request())
            .await
            .expect("gRPC warmup response")
            .into_inner();
        assert!(response.allowed, "gRPC warmup authorization must allow");
    }

    let wall_started = Instant::now();
    let mut workers = Vec::with_capacity(GRPC_CONCURRENCY);
    for _ in 0..GRPC_CONCURRENCY {
        let mut worker_client = client.clone();
        workers.push(tokio::spawn(async move {
            let mut samples = Vec::with_capacity(GRPC_REQUESTS_PER_WORKER);
            for _ in 0..GRPC_REQUESTS_PER_WORKER {
                let started = Instant::now();
                let response = worker_client
                    .decide(decision_request())
                    .await
                    .expect("measured gRPC authorization response")
                    .into_inner();
                samples.push(started.elapsed());
                assert!(response.allowed, "measured gRPC authorization must allow");
            }
            samples
        }));
    }

    let mut samples = Vec::with_capacity(GRPC_CONCURRENCY * GRPC_REQUESTS_PER_WORKER);
    for worker in workers {
        samples.extend(worker.await.expect("performance worker join"));
    }
    let wall = wall_started.elapsed();
    let summary = summarize(&mut samples);
    print_summary("grpc_hot_cache", summary, samples.len(), wall);

    shutdown_tx.send(true).expect("performance server alive");
    let server_result = tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("performance server shutdown deadline")
        .expect("performance server join");
    server_result.expect("clean performance server shutdown");

    assert!(
        summary.p95 < P95_TARGET,
        "gRPC p95 {:.3}us exceeded contract target {:.3}us",
        micros(summary.p95),
        micros(P95_TARGET)
    );
}
