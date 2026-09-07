use std::collections::HashMap;

use machina_authz::proto::{DecisionRequest, DecisionResponse};

#[test]
fn canonical_decision_messages_preserve_required_authz_fields() {
    let request = DecisionRequest {
        subject_id: "subject-a".to_owned(),
        tenant_id: "tenant-a".to_owned(),
        workspace_id: "workspace-a".to_owned(),
        action: "context.read".to_owned(),
        resource_type: "PlatformContext".to_owned(),
        resource_id: "active".to_owned(),
        required_policy_version: 7,
        correlation_id: "corr-a".to_owned(),
        context: HashMap::from([("locale".to_owned(), "pt-BR".to_owned())]),
    };

    assert_eq!(request.tenant_id, "tenant-a");
    assert_eq!(request.required_policy_version, 7);
    assert_eq!(request.context.get("locale").map(String::as_str), Some("pt-BR"));

    let response = DecisionResponse {
        decision_id: "decision-a".to_owned(),
        allowed: false,
        policy_version: 7,
        reason_codes: vec!["explicit_forbid".to_owned()],
        diagnostic_ref: String::new(),
        policy_snapshot_hash: "sha256:abc".to_owned(),
    };

    assert!(!response.allowed);
    assert_eq!(response.reason_codes, vec!["explicit_forbid"]);
    assert_eq!(response.policy_snapshot_hash, "sha256:abc");
}
