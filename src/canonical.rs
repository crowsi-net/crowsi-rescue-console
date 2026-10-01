use sha2::{Digest, Sha256};

use crate::{
    EmergencyAction, EmergencyAuthorizationV1, LifelineEvidence, RecoveryApproval,
    RecoveryRequestV1,
};

#[must_use]
pub fn canonical_emergency_authorization(value: &EmergencyAuthorizationV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    fields(
        &mut bytes,
        [
            "crowsi.rescue.emergency-authorization.v1",
            value.schema.as_str(),
            value.issuer_key_id.as_str(),
            value.audience.as_str(),
            value.subject_id.as_str(),
            value.assurance.as_str(),
            if value.user_verification {
                "true"
            } else {
                "false"
            },
            value.request_id.as_str(),
            value.incident_id.as_str(),
            action(value.action),
            value.resource.as_str(),
            value.body_sha256.as_str(),
            value.nonce.as_str(),
            &value.issued_at_epoch_s.to_string(),
            &value.expires_at_epoch_s.to_string(),
        ],
    );
    bytes
}

#[must_use]
pub fn canonical_lifeline_evidence(value: &LifelineEvidence) -> Vec<u8> {
    let mut bytes = Vec::new();
    fields(
        &mut bytes,
        [
            "crowsi.rescue.lifeline-evidence.v1",
            value.schema.as_str(),
            value.issuer_key_id.as_str(),
            value.interface_id.as_str(),
            value.route_table_id.as_str(),
            value.health_check_id.as_str(),
            &value.tested_at_epoch_s.to_string(),
            &value.expires_at_epoch_s.to_string(),
        ],
    );
    bytes
}

#[must_use]
pub fn recovery_request_digest(value: &RecoveryRequestV1) -> String {
    let mut bytes = Vec::new();
    fields(
        &mut bytes,
        [
            "crowsi.rescue.recovery-request.v1",
            value.schema.as_str(),
            value.request_id.as_str(),
            value.security_domain.as_str(),
            value.deployment_id.as_str(),
            value.incident_id.as_str(),
            value.resource.as_str(),
            &value.fence_epoch.to_string(),
            value.quarantine_receipt_digest.as_str(),
            value.independent_verification_digest.as_str(),
            value.nonce.as_str(),
            &value.issued_at_epoch_s.to_string(),
            &value.expires_at_epoch_s.to_string(),
        ],
    );
    sha256_digest(&bytes)
}

#[must_use]
pub fn canonical_recovery_approval(value: &RecoveryApproval) -> Vec<u8> {
    let mut bytes = Vec::new();
    fields(
        &mut bytes,
        [
            "crowsi.rescue.recovery-approval.v1",
            value.schema.as_str(),
            value.key_id.as_str(),
            value.subject_id.as_str(),
            value.assurance.as_str(),
            if value.user_verification {
                "true"
            } else {
                "false"
            },
            value.recovery_request_digest.as_str(),
            &value.issued_at_epoch_s.to_string(),
            &value.expires_at_epoch_s.to_string(),
        ],
    );
    bytes
}

#[must_use]
pub fn sha256_digest(value: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(value)))
}

fn fields<'a>(bytes: &mut Vec<u8>, values: impl IntoIterator<Item = &'a str>) {
    for value in values {
        bytes.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
}

fn action(value: EmergencyAction) -> &'static str {
    match value {
        EmergencyAction::ContainAsset => "contain-asset",
        EmergencyAction::RevokeCredential => "revoke-credential",
    }
}
