use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crowsi_control_contracts::{EnforcementReceiptV2, SignatureAlgorithm};
use crowsi_independent_verifier::SignedReadbackReportV1;
use ed25519_dalek::Signature;

use crate::{RescueError, RescueTrust};

impl RescueTrust {
    pub(crate) fn verify_receipt(&self, receipt: &EnforcementReceiptV2) -> Result<(), RescueError> {
        if receipt.signed.algorithm != SignatureAlgorithm::Ed25519
            || receipt.signed.key_id != self.receipt_key_id
        {
            return Err(RescueError::Authentication);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(&receipt.signed.signature)
            .map_err(|_| RescueError::Signature)?;
        let signature = Signature::from_slice(&signature).map_err(|_| RescueError::Signature)?;
        self.receipt_key
            .verify_strict(&digest_bytes(&receipt.signed.digest)?, &signature)
            .map_err(|_| RescueError::Signature)
    }

    pub(crate) fn verify_readback(
        &self,
        report: &SignedReadbackReportV1,
    ) -> Result<(), RescueError> {
        if report.signed.key_id != self.readback_key_id {
            return Err(RescueError::Authentication);
        }
        self.readback_key
            .verify_signature(report)
            .map_err(|_| RescueError::Signature)
    }
}

fn digest_bytes(value: &str) -> Result<[u8; 32], RescueError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or(RescueError::Signature)?;
    if hex.len() != 64 {
        return Err(RescueError::Signature);
    }
    let mut bytes = [0_u8; 32];
    for (index, target) in bytes.iter_mut().enumerate() {
        *target = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| RescueError::Signature)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
