use crate::{
    EmergencyRequestV1, RecoveryApproval, RecoveryProofBundleV1, RecoveryRequestV1,
    canonical_recovery_approval, recovery_request_digest,
};
use ed25519_dalek::{Signer, SigningKey};

pub(super) fn recovery(
    now: i64,
    emergency: &EmergencyRequestV1,
    proof: &RecoveryProofBundleV1,
    first: &SigningKey,
    second: &SigningKey,
) -> (RecoveryRequestV1, Vec<RecoveryApproval>) {
    let request = RecoveryRequestV1 {
        schema: "crowsi://rescue/recovery-request/v1".into(),
        request_id: "recovery:001".into(),
        security_domain: proof.quarantine_receipt.security_domain.clone(),
        deployment_id: proof.quarantine_receipt.deployment_id.clone(),
        incident_id: emergency.incident_id.clone(),
        resource: emergency.resource.clone(),
        fence_epoch: proof.quarantine_receipt.fence_epoch,
        quarantine_receipt_digest: proof.quarantine_receipt.signed.digest.clone(),
        independent_verification_digest: proof.independent_readback.signed.digest.clone(),
        nonce: "nonce:recovery:001".into(),
        issued_at_epoch_s: now - 1,
        expires_at_epoch_s: now + 120,
    };
    let digest = recovery_request_digest(&request);
    let approvals = vec![
        approval("subject:director-a", "recovery-a", &digest, now, first),
        approval("subject:director-b", "recovery-b", &digest, now, second),
    ];
    (request, approvals)
}

fn approval(
    subject: &str,
    key_id: &str,
    digest: &str,
    now: i64,
    signer: &SigningKey,
) -> RecoveryApproval {
    let mut value = RecoveryApproval {
        schema: "crowsi://rescue/recovery-approval/v1".into(),
        key_id: key_id.into(),
        subject_id: subject.into(),
        assurance: "hardware-bound-recovery".into(),
        user_verification: true,
        recovery_request_digest: digest.into(),
        issued_at_epoch_s: now - 1,
        expires_at_epoch_s: now + 120,
        signature_hex: String::new(),
    };
    value.signature_hex = hex::encode(signer.sign(&canonical_recovery_approval(&value)).to_bytes());
    value
}
