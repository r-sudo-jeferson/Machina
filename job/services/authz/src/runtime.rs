use std::error::Error;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::time::{Duration, timeout};
use tonic::transport::Server;

use crate::grpc::AuthorizationServiceHandler;
use crate::proto::authorization_service_server::AuthorizationServiceServer;

const MAX_PROBE_REQUEST_BYTES: usize = 2 * 1024;
const MAX_PROBE_CONNECTIONS: usize = 32;
const PROBE_IO_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeConfigError {
    InvalidAddress,
    ListenerCollision,
    ZeroPort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeConfig {
    grpc_addr: SocketAddr,
    probe_addr: SocketAddr,
}

impl RuntimeConfig {
    pub fn parse(grpc_addr: &str, probe_addr: &str) -> Result<Self, RuntimeConfigError> {
        let grpc_addr = grpc_addr
            .parse::<SocketAddr>()
            .map_err(|_| RuntimeConfigError::InvalidAddress)?;
        let probe_addr = probe_addr
            .parse::<SocketAddr>()
            .map_err(|_| RuntimeConfigError::InvalidAddress)?;

        if grpc_addr.port() == 0 || probe_addr.port() == 0 {
            return Err(RuntimeConfigError::ZeroPort);
        }
        if grpc_addr == probe_addr {
            return Err(RuntimeConfigError::ListenerCollision);
        }

        Ok(Self {
            grpc_addr,
            probe_addr,
        })
    }

    pub fn grpc_addr(&self) -> SocketAddr {
        self.grpc_addr
    }

    pub fn probe_addr(&self) -> SocketAddr {
        self.probe_addr
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProbeState {
    ready: Arc<AtomicBool>,
}

impl ProbeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    pub fn mark_not_ready(&self) {
        self.ready.store(false, Ordering::Release);
    }
}

#[derive(Debug)]
pub enum RuntimeServeError {
    Grpc(tonic::transport::Error),
    ProbeAccept(io::Error),
    ProbeBind(io::Error),
}

impl fmt::Display for RuntimeServeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grpc(_) => formatter.write_str("authorization gRPC server failed"),
            Self::ProbeAccept(_) => formatter.write_str("authorization probe listener failed"),
            Self::ProbeBind(_) => {
                formatter.write_str("authorization probe listener could not bind")
            }
        }
    }
}

impl Error for RuntimeServeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Grpc(error) => Some(error),
            Self::ProbeAccept(error) | Self::ProbeBind(error) => Some(error),
        }
    }
}

pub async fn serve(
    config: RuntimeConfig,
    handler: AuthorizationServiceHandler,
    probes: ProbeState,
    shutdown: watch::Receiver<bool>,
) -> Result<(), RuntimeServeError> {
    let probe_listener = TcpListener::bind(config.probe_addr())
        .await
        .map_err(RuntimeServeError::ProbeBind)?;
    let grpc_shutdown = shutdown.clone();
    let probe_shutdown = shutdown;

    let grpc_server = async move {
        Server::builder()
            .add_service(AuthorizationServiceServer::new(handler))
            .serve_with_shutdown(config.grpc_addr(), wait_for_shutdown(grpc_shutdown))
            .await
            .map_err(RuntimeServeError::Grpc)
    };
    let probe_server = serve_probes(probe_listener, probes.clone(), probe_shutdown);

    let result = tokio::try_join!(grpc_server, probe_server);
    probes.mark_not_ready();
    result.map(|_| ())
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }

    loop {
        if shutdown.changed().await.is_err() || *shutdown.borrow() {
            return;
        }
    }
}

async fn serve_probes(
    listener: TcpListener,
    probes: ProbeState,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), RuntimeServeError> {
    let connections = Arc::new(Semaphore::new(MAX_PROBE_CONNECTIONS));

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(RuntimeServeError::ProbeAccept)?;
                let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                    continue;
                };
                let connection_probes = probes.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = handle_probe_connection(stream, connection_probes).await;
                });
            }
        }
    }
}

async fn handle_probe_connection(mut stream: TcpStream, probes: ProbeState) -> io::Result<()> {
    let request = match timeout(PROBE_IO_TIMEOUT, read_probe_request(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(_)) | Err(_) => {
            write_probe_response(&mut stream, 400, "Bad Request", "bad request\n").await?;
            return Ok(());
        }
    };

    let (status, reason, body) = classify_probe_request(&request, &probes);
    write_probe_response(&mut stream, status, reason, body).await
}

async fn read_probe_request(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(512);
    let mut chunk = [0_u8; 512];

    loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "probe request ended before headers",
            ));
        }
        if request.len() + count > MAX_PROBE_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "probe request exceeds maximum size",
            ));
        }

        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
    }
}

fn classify_probe_request(
    request: &[u8],
    probes: &ProbeState,
) -> (u16, &'static str, &'static str) {
    let request_line = request
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .map(str::trim_end)
        .unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next();
    let path = parts.next();
    let version = parts.next();

    if method.is_none()
        || path.is_none()
        || !matches!(version, Some("HTTP/1.0") | Some("HTTP/1.1"))
        || parts.next().is_some()
    {
        return (400, "Bad Request", "bad request\n");
    }
    if method != Some("GET") {
        return (405, "Method Not Allowed", "method not allowed\n");
    }

    match path {
        Some("/healthz") => (200, "OK", "ok\n"),
        Some("/readyz") if probes.is_ready() => (200, "OK", "ready\n"),
        Some("/readyz") => (503, "Service Unavailable", "not ready\n"),
        _ => (404, "Not Found", "not found\n"),
    }
}

async fn write_probe_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}
