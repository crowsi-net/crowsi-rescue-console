use crowsi_control_contracts::EnforcementReceiptV2;
use crowsi_independent_verifier::SignedReadbackReportV1;
use serde::{Deserialize, Serialize};

/// Original signed producer artifacts required before containment can be lifted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryProofBundleV1 {
    pub quarantine_receipt: EnforcementReceiptV2,
    pub independent_readback: SignedReadbackReportV1,
}
