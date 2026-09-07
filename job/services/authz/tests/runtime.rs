use machina_authz::runtime::{ProbeState, RuntimeConfig, RuntimeConfigError};

#[test]
fn runtime_config_requires_distinct_nonzero_grpc_and_probe_listeners() {
    let config = RuntimeConfig::parse("127.0.0.1:50051", "127.0.0.1:8081").expect("valid config");
    assert_eq!(config.grpc_addr().port(), 50051);
    assert_eq!(config.probe_addr().port(), 8081);

    assert!(matches!(
        RuntimeConfig::parse("127.0.0.1:0", "127.0.0.1:8081"),
        Err(RuntimeConfigError::ZeroPort)
    ));
    assert!(matches!(
        RuntimeConfig::parse("127.0.0.1:50051", "127.0.0.1:50051"),
        Err(RuntimeConfigError::ListenerCollision)
    ));
    assert!(matches!(
        RuntimeConfig::parse("not-an-address", "127.0.0.1:8081"),
        Err(RuntimeConfigError::InvalidAddress)
    ));
}

#[test]
fn readiness_starts_fail_closed_and_is_explicitly_reversible() {
    let state = ProbeState::new();

    assert!(!state.is_ready(), "startup must not claim readiness early");
    state.mark_ready();
    assert!(state.is_ready());
    state.mark_not_ready();
    assert!(!state.is_ready(), "dependency/runtime failure must withdraw readiness");
}
