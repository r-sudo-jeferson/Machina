use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use cedar_policy::{Entities, PolicySet, Schema};
use rustls::{ClientConfig, RootCertStore};
use tokio::sync::Mutex;
use tokio_postgres::config::SslMode;
use tokio_postgres::{Client, Config, NoTls};
use tokio_postgres_rustls::MakeRustlsConnect;

use crate::policy_store::{PolicyLoadError, PolicySnapshot};
use crate::runtime::ProbeState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySourceError {
    InvalidConfiguration,
    OpportunisticTlsRejected,
    ConnectionUnavailable,
    QueryFailed,
    InvalidVersion,
    InvalidSchema,
    InvalidPolicies,
    InvalidSnapshot,
}

impl PolicySourceError {
    fn invalidates_source_health(self) -> bool {
        matches!(Self::from(self), Self::ConnectionUnavailable | Self::QueryFailed)
    }
}

impl From<PolicySourceError> for PolicySourceError {
    fn from(error: PolicySourceError) -> Self {
        error
    }
}

impl fmt::Display for PolicySourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration => {
                formatter.write_str("invalid authorization database configuration")
            }
            Self::OpportunisticTlsRejected => {
                formatter.write_str("authorization database must use explicit TLS policy")
            }
            Self::ConnectionUnavailable => {
                formatter.write_str("authorization database connection unavailable")
            }
            Self::QueryFailed => formatter.write_str("authorization policy query failed"),
            Self::InvalidVersion => formatter.write_str("authorization policy version is invalid"),
            Self::InvalidSchema => formatter.write_str("authorization policy schema is invalid"),
            Self::InvalidPolicies => formatter.write_str("authorization policy set is invalid"),
            Self::InvalidSnapshot => {
                formatter.write_str("authorization policy snapshot is invalid")
            }
        }
    }
}

impl Error for PolicySourceError {}

struct PolicySourceInner {
    client: Mutex<Client>,
    healthy: Arc<AtomicBool>,
    probes: ProbeState,
}

#[derive(Clone)]
pub struct PostgresPolicySource {
    inner: Arc<PolicySourceInner>,
}

impl PostgresPolicySource {
    pub async fn connect(
        database_url: &str,
        probes: ProbeState,
    ) -> Result<Self, PolicySourceError> {
        let config =
            Config::from_str(database_url).map_err(|_| PolicySourceError::InvalidConfiguration)?;
        let healthy = Arc::new(AtomicBool::new(false));

        let client = match config.get_ssl_mode() {
            SslMode::Disable => {
                let (client, connection) = config
                    .connect(NoTls)
                    .await
                    .map_err(|_| PolicySourceError::ConnectionUnavailable)?;
                let monitor_health = Arc::clone(&healthy);
                let monitor_probes = probes.clone();
                tokio::spawn(async move {
                    let _ = connection.await;
                    monitor_health.store(false, Ordering::Release);
                    monitor_probes.mark_not_ready();
                });
                client
            }
            SslMode::Require => {
                let roots =
                    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let tls_config = ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let tls = MakeRustlsConnect::new(tls_config);
                let (client, connection) = config
                    .connect(tls)
                    .await
                    .map_err(|_| PolicySourceError::ConnectionUnavailable)?;
                let monitor_health = Arc::clone(&healthy);
                let monitor_probes = probes.clone();
                tokio::spawn(async move {
                    let _ = connection.await;
                    monitor_health.store(false, Ordering::Release);
                    monitor_probes.mark_not_ready();
                });
                client
            }
            SslMode::Prefer => return Err(PolicySourceError::OpportunisticTlsRejected),
            _ => return Err(PolicySourceError::InvalidConfiguration),
        };

        healthy.store(true, Ordering::Release);
        Ok(Self {
            inner: Arc::new(PolicySourceInner {
                client: Mutex::new(client),
                healthy,
                probes,
            }),
        })
    }

    pub fn is_healthy(&self) -> bool {
        self.inner.healthy.load(Ordering::Acquire)
    }

    pub async fn load_active(
        &self,
        tenant_id: &str,
    ) -> Result<Option<PolicySnapshot>, PolicySourceError> {
        if !self.is_healthy() {
            return Err(PolicySourceError::ConnectionUnavailable);
        }

        let result = self.load_active_inner(tenant_id).await;
        match result {
            Ok(snapshot) => {
                self.inner.healthy.store(true, Ordering::Release);
                self.inner.probes.mark_ready();
                Ok(snapshot)
            }
            Err(error) => {
                if error.invalidates_source_health() {
                    self.inner.healthy.store(false, Ordering::Release);
                    self.inner.probes.mark_not_ready();
                }
                Err(error)
            }
        }
    }

    async fn load_active_inner(
        &self,
        tenant_id: &str,
    ) -> Result<Option<PolicySnapshot>, PolicySourceError> {
        let mut client = self.inner.client.lock().await;
        if client.is_closed() {
            return Err(PolicySourceError::ConnectionUnavailable);
        }

        let transaction = client
            .transaction()
            .await
            .map_err(|_| PolicySourceError::QueryFailed)?;
        transaction
            .query_one(
                "SELECT set_config('app.tenant_id', $1, true)",
                &[&tenant_id],
            )
            .await
            .map_err(|_| PolicySourceError::QueryFailed)?;

        let row = transaction
            .query_opt(
                "SELECT version, snapshot_hash, cedar_schema::text, cedar_policies \
                 FROM authz.policy_snapshots \
                 WHERE tenant_id = ops.current_tenant_id() AND status = 'active'",
                &[],
            )
            .await
            .map_err(|_| PolicySourceError::QueryFailed)?;
        transaction
            .commit()
            .await
            .map_err(|_| PolicySourceError::QueryFailed)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let version: i64 = row.try_get(0).map_err(|_| PolicySourceError::QueryFailed)?;
        let version = u64::try_from(version)
            .ok()
            .filter(|version| *version > 0)
            .ok_or(PolicySourceError::InvalidVersion)?;
        let snapshot_hash: String = row.try_get(1).map_err(|_| PolicySourceError::QueryFailed)?;
        let schema_json: String = row.try_get(2).map_err(|_| PolicySourceError::QueryFailed)?;
        let cedar_policies: String = row.try_get(3).map_err(|_| PolicySourceError::QueryFailed)?;

        let schema =
            Schema::from_json_str(&schema_json).map_err(|_| PolicySourceError::InvalidSchema)?;
        let policies = cedar_policies
            .parse::<PolicySet>()
            .map_err(|_| PolicySourceError::InvalidPolicies)?;
        let snapshot =
            PolicySnapshot::try_new(version, snapshot_hash, schema, policies, Entities::empty())
                .map_err(|error| match error {
                    PolicyLoadError::InvalidSnapshotHash | PolicyLoadError::ValidationFailed => {
                        PolicySourceError::InvalidSnapshot
                    }
                })?;

        Ok(Some(snapshot))
    }
}
