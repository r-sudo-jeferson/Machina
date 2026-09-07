use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const GRPC_ENV: &str = "MACHINA_AUTHZ_GRPC_ADDR";
const PROBE_ENV: &str = "MACHINA_AUTHZ_PROBE_ADDR";

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

fn await_http_status(addr: SocketAddr, path: &str, expected: u16) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if try_http_status(addr, path) == Some(expected) {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("{path} did not report HTTP {expected}");
}

fn terminate(mut child: Child) {
    child.kill().expect("terminate authz process");
    let status = child.wait().expect("reap authz process");
    assert!(!status.success(), "forced termination must not report success");
}

#[test]
fn executable_fails_fast_when_required_listener_configuration_is_missing() {
    let output = Command::new(binary_path())
        .env_remove(GRPC_ENV)
        .env_remove(PROBE_ENV)
        .output()
        .expect("run authz executable");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(GRPC_ENV));
}

#[test]
fn executable_rejects_colliding_listener_addresses() {
    let addr = reserve_addr().to_string();
    let output = Command::new(binary_path())
        .env(GRPC_ENV, &addr)
        .env(PROBE_ENV, &addr)
        .output()
        .expect("run authz executable");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("distinct"));
}

#[test]
fn executable_serves_health_but_stays_not_ready_without_loaded_policy_source() {
    let (grpc_addr, probe_addr) = distinct_addrs();
    let child = Command::new(binary_path())
        .env(GRPC_ENV, grpc_addr.to_string())
        .env(PROBE_ENV, probe_addr.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start authz executable");

    await_http_status(probe_addr, "/healthz", 200);
    await_http_status(probe_addr, "/readyz", 503);
    terminate(child);
}
