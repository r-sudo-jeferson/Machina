use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
