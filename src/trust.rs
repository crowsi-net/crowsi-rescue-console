use std::collections::{BTreeMap, BTreeSet};

use crowsi_independent_verifier::TrustedReportKey;
use ed25519_dalek::VerifyingKey;

use crate::{RescueError, boundary::valid_id};

mod proof;

#[derive(Clone, Debug)]
pub struct RecoveryProofTrust {
    pub receipt_key_id: String,
    pub receipt_public_key: [u8; 32],
    pub readback_key_id: String,
    pub readback_public_key: [u8; 32],
}

pub struct RescueTrust {
    pub(crate) rescue_key_id: String,
    pub(crate) rescue_key: VerifyingKey,
    pub(crate) lifeline_key_id: String,
    pub(crate) lifeline_key: VerifyingKey,
    pub(crate) receipt_key_id: String,
    pub(crate) receipt_key: VerifyingKey,
    pub(crate) readback_key_id: String,
    pub(crate) readback_key: TrustedReportKey,
    pub(crate) recovery_keys: BTreeMap<String, VerifyingKey>,
}

impl RescueTrust {
    /// Builds cryptographically separate rescue, lifeline, and recovery trust.
    ///
    /// # Errors
    ///
    /// Rejects weak, duplicate, malformed, or insufficient authority keys.
    pub fn new(
        rescue_key_id: &str,
        rescue_public_key: [u8; 32],
        lifeline_key_id: &str,
        lifeline_public_key: [u8; 32],
        evidence: RecoveryProofTrust,
        recovery_public_keys: BTreeMap<String, [u8; 32]>,
    ) -> Result<Self, RescueError> {
        let receipt_key_id = evidence.receipt_key_id;
        let receipt_public_key = evidence.receipt_public_key;
        let readback_key_id = evidence.readback_key_id;
        let readback_public_key = evidence.readback_public_key;
        if !valid_id(rescue_key_id)
            || !valid_id(lifeline_key_id)
            || !valid_id(&receipt_key_id)
            || !valid_id(&readback_key_id)
            || recovery_public_keys.len() < 2
        {
            return Err(RescueError::Contract);
        }
        let mut ids = BTreeSet::from([
            rescue_key_id.to_owned(),
            lifeline_key_id.to_owned(),
            receipt_key_id.clone(),
            readback_key_id.clone(),
        ]);
        if ids.len() != 4 {
            return Err(RescueError::BoundaryOverlap);
        }
        let rescue_key =
            VerifyingKey::from_bytes(&rescue_public_key).map_err(|_| RescueError::Contract)?;
        let lifeline_key =
            VerifyingKey::from_bytes(&lifeline_public_key).map_err(|_| RescueError::Contract)?;
        let receipt_key =
            VerifyingKey::from_bytes(&receipt_public_key).map_err(|_| RescueError::Contract)?;
        let readback_verifying =
            VerifyingKey::from_bytes(&readback_public_key).map_err(|_| RescueError::Contract)?;
        if [rescue_key, lifeline_key, receipt_key, readback_verifying]
            .iter()
            .any(VerifyingKey::is_weak)
        {
            return Err(RescueError::Contract);
        }
        let mut seen = BTreeSet::from([
            rescue_public_key,
            lifeline_public_key,
            receipt_public_key,
            readback_public_key,
        ]);
        if seen.len() != 4 {
            return Err(RescueError::BoundaryOverlap);
        }
        let mut recovery_keys = BTreeMap::new();
        for (key_id, key) in recovery_public_keys {
            if !valid_id(&key_id) || !ids.insert(key_id.clone()) || !seen.insert(key) {
                return Err(RescueError::BoundaryOverlap);
            }
            let verifying = VerifyingKey::from_bytes(&key).map_err(|_| RescueError::Contract)?;
            if verifying.is_weak() {
                return Err(RescueError::Contract);
            }
            recovery_keys.insert(key_id, verifying);
        }
        let readback_key = TrustedReportKey::new(&readback_key_id, readback_public_key)
            .map_err(|_| RescueError::Contract)?;
        Ok(Self {
            rescue_key_id: rescue_key_id.into(),
            rescue_key,
            lifeline_key_id: lifeline_key_id.into(),
            lifeline_key,
            receipt_key_id,
            receipt_key,
            readback_key_id,
            readback_key,
            recovery_keys,
        })
    }
}

impl std::fmt::Debug for RescueTrust {
    fn fmt(&self, value: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        value
            .debug_struct("RescueTrust")
            .field("rescue_key_id", &self.rescue_key_id)
            .field("lifeline_key_id", &self.lifeline_key_id)
            .field("receipt_key_id", &self.receipt_key_id)
            .field("readback_key_id", &self.readback_key_id)
            .field("recovery_key_count", &self.recovery_keys.len())
            .finish_non_exhaustive()
    }
}
