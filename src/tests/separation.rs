use super::support::boundary;
use crate::{RescueError, SeparationConfig};

#[test]
fn normal_rescue_and_recovery_boundaries_must_be_distinct() {
    let normal = boundary(2001, "normal", "normal-key", "normal-exe");
    let mut rescue = boundary(3001, "rescue", "rescue-key", "rescue-exe");
    let recovery = boundary(4001, "recovery", "recovery-key", "recovery-exe");
    rescue.socket_path = normal.socket_path.clone();
    assert_eq!(
        SeparationConfig::new(&normal, rescue, recovery).expect_err("overlap"),
        RescueError::BoundaryOverlap
    );
}

#[test]
fn rescue_cannot_share_group_or_executable_with_normal_control() {
    let normal = boundary(2001, "normal", "normal-key", "normal-exe");
    let mut shared_group = boundary(3001, "rescue", "rescue-key", "rescue-exe");
    let recovery = boundary(4001, "recovery", "recovery-key", "recovery-exe");
    shared_group.gid = normal.gid;
    assert_eq!(
        SeparationConfig::new(&normal, shared_group, recovery.clone()).expect_err("shared group"),
        RescueError::BoundaryOverlap
    );

    let mut shared_binary = boundary(3001, "rescue", "rescue-key", "rescue-exe");
    shared_binary.executable_sha256 = normal.executable_sha256.clone();
    assert_eq!(
        SeparationConfig::new(&normal, shared_binary, recovery).expect_err("shared executable"),
        RescueError::BoundaryOverlap
    );
}

#[test]
fn rescue_action_schema_has_no_restore_variant() {
    let encoded = r#""restore""#;
    assert!(serde_json::from_str::<crate::EmergencyAction>(encoded).is_err());
}

#[test]
fn rescue_authority_cannot_be_a_recovery_authority() {
    use crate::{RecoveryProofTrust, RescueTrust};
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    let shared = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
    let lifeline = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes();
    let receipt = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
    let readback = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    assert_eq!(
        RescueTrust::new(
            "shared",
            shared,
            "lifeline",
            lifeline,
            RecoveryProofTrust {
                receipt_key_id: "receipt".into(),
                receipt_public_key: receipt,
                readback_key_id: "readback".into(),
                readback_public_key: readback,
            },
            BTreeMap::from([
                ("recovery-a".into(), shared),
                ("recovery-b".into(), [4; 32])
            ]),
        )
        .expect_err("shared trust root"),
        RescueError::BoundaryOverlap
    );
}

#[test]
fn rescue_json_contracts_reject_unknown_fields() {
    let value = serde_json::json!({
        "schema": "crowsi://rescue/emergency-request/v1",
        "request_id": "emergency:001",
        "incident_id": "incident:001",
        "action": "contain-asset",
        "resource": "crowsi://assets/server-01",
        "body_sha256": format!("sha256:{}", "a".repeat(64)),
        "implicit_trust": true
    });
    assert!(serde_json::from_value::<crate::EmergencyRequestV1>(value).is_err());
}
