use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{
    ActionBindingV1, CanonicalPayloadV1, ControlAction, ControlChannel, EnforcementOutcome,
    EnforcementReceiptV2, SignatureAlgorithm, SignedDigestV1,
};
use crowsi_independent_verifier::{
    IndependentReport, ObservedState, ReadbackState, ReportSignatureV1, SignedReadbackReportV1,
};
use ed25519_dalek::{Signer, SigningKey};

use crate::{EmergencyRequestV1, RecoveryProofBundleV1, sha256_digest};

pub(super) fn proof(
    now: i64,
    emergency: &EmergencyRequestV1,
    receipt_signer: &SigningKey,
    readback_signer: &SigningKey,
) -> RecoveryProofBundleV1 {
    let mut receipt = receipt(emergency);
    receipt.signed.digest = receipt.payload_digest();
    receipt.signed.signature = sign_digest(receipt_signer, &receipt.signed.digest);
    let mut report = report(now, &receipt);
    report.signed.digest = report.payload_digest();
    report.signed.signature = sign_digest(readback_signer, &report.signed.digest);
    RecoveryProofBundleV1 {
        quarantine_receipt: receipt,
        independent_readback: report,
    }
}

fn receipt(emergency: &EmergencyRequestV1) -> EnforcementReceiptV2 {
    EnforcementReceiptV2 {
        schema: "crowsi://control/enforcement-receipt/v2".into(),
        receipt_id: "receipt:quarantine:001".into(),
        command_jti: "command:quarantine:001".into(),
        command_digest: sha256_digest(b"quarantine command"),
        security_domain: "security-domain:crowsi".into(),
        deployment_id: "deployment:production-a".into(),
        incident_id: emergency.incident_id.clone(),
        target_id: emergency.resource.clone(),
        release_reservation_id: "reservation:quarantine:001".into(),
        fence_epoch: 42,
        binding: ActionBindingV1 {
            audience: "crowsi-enforcer-incus".into(),
            resource: emergency.resource.clone(),
            action: ControlAction::Quarantine,
            purpose: "incident-containment".into(),
            channel: ControlChannel::EmergencyConsole,
        },
        provider: "crowsi-enforcer-incus".into(),
        outcome: EnforcementOutcome::Applied,
        authorization_consumed: true,
        applied_at: "2027-01-15T08:00:00.000Z".into(),
        expected_resource_version: "version:connected:41".into(),
        resulting_resource_version: Some("version:isolated:42".into()),
        residual_exposures: Vec::new(),
        evidence_digest: sha256_digest(b"provider evidence"),
        signed: SignedDigestV1 {
            algorithm: SignatureAlgorithm::Ed25519,
            key_id: "pep-receipt-attestor".into(),
            digest: format!("sha256:{:064}", 0),
            signature: "a".repeat(86),
        },
    }
}

fn report(now: i64, receipt: &EnforcementReceiptV2) -> SignedReadbackReportV1 {
    let mut evidence = vec![sha256_digest(b"sensor-a"), sha256_digest(b"sensor-b")];
    evidence.sort();
    SignedReadbackReportV1 {
        schema: "crowsi.signed-readback-report.v1".into(),
        command_id: receipt.command_jti.clone(),
        security_domain: receipt.security_domain.clone(),
        deployment_id: receipt.deployment_id.clone(),
        resource_uri: receipt.target_id.clone(),
        expected_state: ObservedState::Isolated,
        expected_resource_version: receipt
            .resulting_resource_version
            .clone()
            .expect("applied receipt version"),
        minimum_fence: receipt.fence_epoch,
        required_quorum: 2,
        report: IndependentReport {
            schema: "crowsi.readback-report.v1".into(),
            state: ReadbackState::Verified,
            reason_code: "independent-quorum".into(),
            accepted_evidence: 2,
            accepted_evidence_digests: evidence,
            rejected_evidence: 0,
            independent_groups: 2,
            evaluated_at_ms: now * 1_000 - 1_000,
        },
        expires_at_ms: now * 1_000 + 30_000,
        signed: ReportSignatureV1 {
            algorithm: "Ed25519".into(),
            key_id: "independent-readback-attestor".into(),
            digest: format!("sha256:{:064}", 0),
            signature: "a".repeat(86),
        },
    }
}

fn sign_digest(key: &SigningKey, value: &str) -> String {
    let bytes = hex::decode(value.trim_start_matches("sha256:")).expect("digest");
    URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes())
}
