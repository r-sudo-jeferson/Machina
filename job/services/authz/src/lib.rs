pub mod evaluator;
pub mod grpc;
pub mod policy_store;
pub mod runtime;
pub mod service;
pub mod starter;

pub mod proto {
    tonic::include_proto!("machina.authz.v1");
}
