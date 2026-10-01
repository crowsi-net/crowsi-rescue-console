use crowsi_control_contracts::{ControlAction, EnforcementOutcome, Validate};
use crowsi_independent_verifier::{ObservedState, ReadbackState};

use crate::{RecoveryProofBundleV1, RecoveryRequestV1, RescueError};

pub(crate) fn validate(
    request: &RecoveryRequestV1,
    proof: &RecoveryProofBundleV1,
    now: i64,
) -> Result<(), RescueError> {
    let receipt = &proof.quarantine_receipt;
    receipt.validate().map_err(|_| RescueError::Contract)?;
    let resulting_version = receipt
        .resulting_resource_version
        .as_deref()
        .ok_or(RescueError::Binding)?;
    if receipt.signed.digest != request.quarantine_receipt_digest
        || receipt.security_domain != request.security_domain
        || receipt.deployment_id != request.deployment_id
        || receipt.incident_id != request.incident_id
        || receipt.target_id != request.resource
        || receipt.fence_epoch != request.fence_epoch
        || receipt.binding.action != ControlAction::Quarantine
        || receipt.outcome != EnforcementOutcome::Applied
        || !receipt.authorization_consumed
        || !receipt.residual_exposures.is_empty()
    {
        return Err(RescueError::Binding);
    }

    let report = &proof.independent_readback;
    report
        .validate_contract()
        .map_err(|_| RescueError::Contract)?;
    if report.signed.digest != request.independent_verification_digest
        || report.command_id != receipt.command_jti
        || report.security_domain != request.security_domain
        || report.deployment_id != request.deployment_id
        || report.resource_uri != request.resource
        || report.expected_state != ObservedState::Isolated
        || report.expected_resource_version != resulting_version
        || report.minimum_fence != request.fence_epoch
        || report.required_quorum < 2
        || report.report.state != ReadbackState::Verified
        || report.report.independent_groups < 2
        || report.report.accepted_evidence < 2
    {
        return Err(RescueError::Binding);
    }
    fresh_report(report.report.evaluated_at_ms, report.expires_at_ms, now)
}

fn fresh_report(evaluated_at_ms: i64, expires_at_ms: i64, now: i64) -> Result<(), RescueError> {
    let now_ms = now.checked_mul(1_000).ok_or(RescueError::Time)?;
    if evaluated_at_ms <= now_ms && now_ms < expires_at_ms {
        Ok(())
    } else {
        Err(RescueError::Time)
    }
}
