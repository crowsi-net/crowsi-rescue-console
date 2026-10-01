use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::EnforcementReceiptV2;
use crowsi_independent_verifier::SignedReadbackReportV1;
use ed25519_dalek::SigningKey;

use crate::{RecoveryProofTrust, RescueTrust};

#[test]
fn producer_conformance_artifacts_verify_without_rescue_wrappers() {
    let receipt: EnforcementReceiptV2 = serde_json::from_str(include_str!(
        "../../../../crowsi-enforcement-point/fixtures/conformance/v1/enforcement-receipt-v2.json"
    ))
    .expect("PEP receipt fixture");
    let readback: SignedReadbackReportV1 = serde_json::from_str(include_str!(
        "../../../../crowsi-independent-verifier/fixtures/conformance/v1/signed-readback-report-v1.json"
    ))
    .expect("verifier report fixture");
    let trust = trust(&receipt, &readback);

    trust.verify_receipt(&receipt).expect("direct PEP receipt");
    trust
        .verify_readback(&readback)
        .expect("direct verifier report");
}

fn trust(receipt: &EnforcementReceiptV2, report: &SignedReadbackReportV1) -> RescueTrust {
    let receipt_key = manifest_key(include_str!(
        "../../../../crowsi-enforcement-point/fixtures/conformance/v1/pep-receipt-trust-manifest-v1.json"
    ));
    let report_key = manifest_key(include_str!(
        "../../../../crowsi-independent-verifier/fixtures/conformance/v1/readback-report-trust-manifest-v1.json"
    ));
    RescueTrust::new(
        "rescue",
        SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes(),
        "lifeline",
        SigningKey::from_bytes(&[32; 32]).verifying_key().to_bytes(),
        RecoveryProofTrust {
            receipt_key_id: receipt.signed.key_id.clone(),
            receipt_public_key: receipt_key,
            readback_key_id: report.signed.key_id.clone(),
            readback_public_key: report_key,
        },
        BTreeMap::from([
            (
                "recovery-a".into(),
                SigningKey::from_bytes(&[33; 32]).verifying_key().to_bytes(),
            ),
            (
                "recovery-b".into(),
                SigningKey::from_bytes(&[34; 32]).verifying_key().to_bytes(),
            ),
        ]),
    )
    .expect("separate producer trust")
}

fn manifest_key(document: &str) -> [u8; 32] {
    let value: serde_json::Value = serde_json::from_str(document).expect("manifest");
    let encoded = value
        .pointer("/receipt_verifier/public_key")
        .or_else(|| value.pointer("/report_verifier/public_key"))
        .and_then(serde_json::Value::as_str)
        .expect("public key");
    URL_SAFE_NO_PAD
        .decode(encoded)
        .expect("base64url public key")
        .try_into()
        .expect("32-byte public key")
}
