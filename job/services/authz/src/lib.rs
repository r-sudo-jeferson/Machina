pub mod evaluator;
pub mod grpc;
pub mod policy_store;
pub mod service;

pub mod proto {
    tonic::include_proto!("machina.authz.v1");
}
