use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    BoundaryIdentity, EmergencyAuthorizationV1, EmergencyRequestV1, LifelineEvidence,
    RecoveryApproval, RecoveryRequestV1, RescueError,
    boundary::{valid_digest, valid_id},
    model::PeerIdentity,
};

pub(crate) fn peer(expected: &BoundaryIdentity, actual: &PeerIdentity) -> Result<(), RescueError> {
    if actual.uid != expected.uid
        || actual.gid != expected.gid
        || actual.executable_sha256 != expected.executable_sha256
        || actual.network_namespace_id != expected.network_namespace_id
        || actual.ipc_namespace_id != expected.ipc_namespace_id
    {
        return Err(RescueError::PeerAttestation);
    }
    Ok(())
}

pub(crate) fn lifeline(value: &LifelineEvidence, now: i64) -> Result<(), RescueError> {
    if value.schema != "crowsi://rescue/lifeline-evidence/v1"
        || !valid_id(&value.interface_id)
        || !valid_id(&value.route_table_id)
        || !valid_id(&value.health_check_id)
        || value.tested_at_epoch_s > now
        || now
            .checked_sub(value.tested_at_epoch_s)
            .is_none_or(|age| age > 300)
        || value.expires_at_epoch_s <= now
    {
        return Err(RescueError::Lifeline);
    }
    Ok(())
}

pub(crate) fn emergency(
    request: &EmergencyRequestV1,
    authorization: &EmergencyAuthorizationV1,
    now: i64,
) -> Result<(), RescueError> {
    if request.schema != "crowsi://rescue/emergency-request/v1"
        || authorization.schema != "crowsi://rescue/emergency-authorization/v1"
        || authorization.audience != "crowsi-rescue-console"
        || authorization.assurance != "hardware-bound-step-up"
        || !authorization.user_verification
    {
        return Err(RescueError::Authentication);
    }
    if request.request_id != authorization.request_id
        || request.incident_id != authorization.incident_id
        || request.action != authorization.action
        || request.resource != authorization.resource
        || request.body_sha256 != authorization.body_sha256
    {
        return Err(RescueError::Binding);
    }
    if !valid_id(&request.request_id)
        || !valid_id(&request.incident_id)
        || !valid_id(&request.resource)
        || !valid_digest(&request.body_sha256)
        || !valid_id(&authorization.subject_id)
        || !valid_id(&authorization.nonce)
    {
        return Err(RescueError::Contract);
    }
    valid_window(
        authorization.issued_at_epoch_s,
        authorization.expires_at_epoch_s,
        now,
        60,
    )
}

pub(crate) fn recovery(
    request: &RecoveryRequestV1,
    approval: &RecoveryApproval,
    expected_digest: &str,
    now: i64,
) -> Result<(), RescueError> {
    if request.schema != "crowsi://rescue/recovery-request/v1"
        || approval.schema != "crowsi://rescue/recovery-approval/v1"
        || approval.assurance != "hardware-bound-recovery"
        || !approval.user_verification
    {
        return Err(RescueError::Authentication);
    }
    if approval.recovery_request_digest != expected_digest {
        return Err(RescueError::Binding);
    }
    if !valid_id(&request.request_id)
        || !valid_id(&request.incident_id)
        || !valid_id(&request.resource)
        || !valid_id(&request.nonce)
        || !valid_digest(&request.quarantine_receipt_digest)
        || !valid_digest(&request.independent_verification_digest)
        || !valid_id(&approval.key_id)
        || !valid_id(&approval.subject_id)
    {
        return Err(RescueError::Contract);
    }
    valid_window(
        request.issued_at_epoch_s,
        request.expires_at_epoch_s,
        now,
        300,
    )?;
    valid_window(
        approval.issued_at_epoch_s,
        approval.expires_at_epoch_s,
        now,
        300,
    )
}

pub(crate) fn signature(
    key: &VerifyingKey,
    message: &[u8],
    encoded: &str,
) -> Result<(), RescueError> {
    let bytes = hex::decode(encoded).map_err(|_| RescueError::Signature)?;
    let signature = Signature::try_from(bytes.as_slice()).map_err(|_| RescueError::Signature)?;
    key.verify_strict(message, &signature)
        .map_err(|_| RescueError::Signature)
}

pub(crate) fn valid_window(
    issued: i64,
    expires: i64,
    now: i64,
    maximum: i64,
) -> Result<(), RescueError> {
    if issued > now
        || expires <= now
        || expires
            .checked_sub(issued)
            .is_none_or(|lifetime| lifetime <= 0 || lifetime > maximum)
    {
        return Err(RescueError::Time);
    }
    Ok(())
}
