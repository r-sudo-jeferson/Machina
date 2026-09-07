use std::env;
use std::error::Error;
use std::fmt;
use std::io;
use std::process::ExitCode;

use machina_authz::grpc::AuthorizationServiceHandler;
use machina_authz::policy_store::PolicyCache;
use machina_authz::runtime::{
    ProbeState, RuntimeConfig, RuntimeConfigError, RuntimeServeError, serve,
};
use tokio::sync::watch;

const GRPC_ENV: &str = "MACHINA_AUTHZ_GRPC_ADDR";
const PROBE_ENV: &str = "MACHINA_AUTHZ_PROBE_ADDR";
const CONFIG_ERROR_EXIT_CODE: u8 = 78;
const RUNTIME_ERROR_EXIT_CODE: u8 = 70;

#[derive(Debug)]
enum StartupError {
    MissingEnvironment(&'static str),
    InvalidRuntimeConfig(RuntimeConfigError),
    Signal(io::Error),
    Runtime(RuntimeServeError),
}

impl StartupError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::MissingEnvironment(_) | Self::InvalidRuntimeConfig(_) => CONFIG_ERROR_EXIT_CODE,
            Self::Signal(_) | Self::Runtime(_) => RUNTIME_ERROR_EXIT_CODE,
        }
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvironment(name) => {
                write!(formatter, "missing required environment variable {name}")
            }
            Self::InvalidRuntimeConfig(RuntimeConfigError::InvalidAddress) => {
                formatter.write_str("listener addresses must be valid socket addresses")
            }
            Self::InvalidRuntimeConfig(RuntimeConfigError::ListenerCollision) => {
                formatter.write_str("gRPC and probe listener addresses must be distinct")
            }
            Self::InvalidRuntimeConfig(RuntimeConfigError::ZeroPort) => {
                formatter.write_str("listener ports must be non-zero")
            }
            Self::Signal(_) => {
                formatter.write_str("failed to register process termination signal handler")
            }
            Self::Runtime(error) => write!(formatter, "authorization runtime failed: {error}"),
        }
    }
}

impl Error for StartupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Signal(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::MissingEnvironment(_) | Self::InvalidRuntimeConfig(_) => None,
        }
    }
}

fn required_environment(name: &'static str) -> Result<String, StartupError> {
    env::var(name).map_err(|_| StartupError::MissingEnvironment(name))
}

#[cfg(unix)]
async fn wait_for_termination_signal() -> Result<(), StartupError> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate()).map_err(StartupError::Signal)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(StartupError::Signal)?;

    tokio::select! {
        _ = terminate.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn wait_for_termination_signal() -> Result<(), StartupError> {
    tokio::signal::ctrl_c().await.map_err(StartupError::Signal)
}

async fn run() -> Result<(), StartupError> {
    let grpc_addr = required_environment(GRPC_ENV)?;
    let probe_addr = required_environment(PROBE_ENV)?;
    let config = RuntimeConfig::parse(&grpc_addr, &probe_addr)
        .map_err(StartupError::InvalidRuntimeConfig)?;

    let handler = AuthorizationServiceHandler::new(PolicyCache::new());
    let probes = ProbeState::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let runtime = serve(config, handler, probes, shutdown_rx);
    tokio::pin!(runtime);

    tokio::select! {
        result = runtime.as_mut() => result.map_err(StartupError::Runtime),
        signal = wait_for_termination_signal() => {
            signal?;
            let _ = shutdown_tx.send(true);
            runtime.as_mut().await.map_err(StartupError::Runtime)
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(error.exit_code())
        }
    }
}
