use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryIdentity {
    pub uid: u32,
    pub gid: u32,
    pub socket_path: String,
    pub signing_key_id: String,
    pub executable_sha256: String,
    pub network_namespace_id: String,
    pub ipc_namespace_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeerIdentity {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) executable_sha256: String,
    pub(crate) network_namespace_id: String,
    pub(crate) ipc_namespace_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EmergencyAction {
    ContainAsset,
    RevokeCredential,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencyRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub incident_id: String,
    pub action: EmergencyAction,
    pub resource: String,
    pub body_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencyAuthorizationV1 {
    pub schema: String,
    pub issuer_key_id: String,
    pub audience: String,
    pub subject_id: String,
    pub assurance: String,
    pub user_verification: bool,
    pub request_id: String,
    pub incident_id: String,
    pub action: EmergencyAction,
    pub resource: String,
    pub body_sha256: String,
    pub nonce: String,
    pub issued_at_epoch_s: i64,
    pub expires_at_epoch_s: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEmergencyAuthorization {
    pub document: EmergencyAuthorizationV1,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub security_domain: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub resource: String,
    pub fence_epoch: u64,
    pub quarantine_receipt_digest: String,
    pub independent_verification_digest: String,
    pub nonce: String,
    pub issued_at_epoch_s: i64,
    pub expires_at_epoch_s: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApproval {
    pub schema: String,
    pub key_id: String,
    pub subject_id: String,
    pub assurance: String,
    pub user_verification: bool,
    pub recovery_request_digest: String,
    pub issued_at_epoch_s: i64,
    pub expires_at_epoch_s: i64,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LifelineEvidence {
    pub schema: String,
    pub issuer_key_id: String,
    pub interface_id: String,
    pub route_table_id: String,
    pub health_check_id: String,
    pub tested_at_epoch_s: i64,
    pub expires_at_epoch_s: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLifelineEvidence {
    pub document: LifelineEvidence,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RescueTicket {
    pub schema: &'static str,
    pub request_id: String,
    pub action: EmergencyAction,
    pub resource: String,
    pub command_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveryTicket {
    pub schema: &'static str,
    pub request_id: String,
    pub resource: String,
    pub approver_count: u8,
    pub command_digest: String,
}
