use super::support::fixture;
use crate::RescueError;

#[test]
fn forged_or_context_spliced_recovery_evidence_fails_closed() {
    let mut forged = fixture();
    forged.recovery_evidence.quarantine_receipt.signed.signature = "a".repeat(86);
    assert_eq!(
        forged
            .console
            .authorize_restore_attested(
                &forged.recovery,
                &forged.recovery_evidence,
                &forged.approvals,
                &forged.recovery_peer,
                &forged.lifeline,
            )
            .expect_err("forged receipt evidence"),
        RescueError::Signature
    );

    let mut fixture = fixture();
    fixture
        .recovery_evidence
        .independent_readback
        .security_domain = "security-domain:other".into();
    assert_eq!(
        fixture
            .console
            .authorize_restore_attested(
                &fixture.recovery,
                &fixture.recovery_evidence,
                &fixture.approvals,
                &fixture.recovery_peer,
                &fixture.lifeline,
            )
            .expect_err("spliced readback"),
        RescueError::Contract
    );
}

#[test]
fn stale_recovery_evidence_fails_closed() {
    let mut fixture = fixture();
    fixture.console.clock_mut().set(1_800_000_031);
    assert_eq!(
        fixture
            .console
            .authorize_restore_attested(
                &fixture.recovery,
                &fixture.recovery_evidence,
                &fixture.approvals,
                &fixture.recovery_peer,
                &fixture.lifeline,
            )
            .expect_err("stale readback"),
        RescueError::Time
    );
}

#[test]
fn readback_is_expired_at_its_exact_expiry_instant() {
    let mut fixture = fixture();
    fixture.console.clock_mut().set(1_800_000_030);
    assert_eq!(
        fixture
            .console
            .authorize_restore_attested(
                &fixture.recovery,
                &fixture.recovery_evidence,
                &fixture.approvals,
                &fixture.recovery_peer,
                &fixture.lifeline,
            )
            .expect_err("exclusive expiry"),
        RescueError::Time
    );
}

#[test]
fn non_applied_receipt_or_single_group_readback_cannot_restore() {
    let mut partial = fixture();
    partial.recovery_evidence.quarantine_receipt.outcome =
        crowsi_control_contracts::EnforcementOutcome::Partial;
    partial
        .recovery_evidence
        .quarantine_receipt
        .residual_exposures
        .push("provider-path-unknown".into());
    assert_eq!(
        partial
            .console
            .authorize_restore_attested(
                &partial.recovery,
                &partial.recovery_evidence,
                &partial.approvals,
                &partial.recovery_peer,
                &partial.lifeline,
            )
            .expect_err("partial receipt"),
        RescueError::Contract
    );

    let mut single = fixture();
    single
        .recovery_evidence
        .independent_readback
        .required_quorum = 1;
    single
        .recovery_evidence
        .independent_readback
        .report
        .independent_groups = 1;
    assert_eq!(
        single
            .console
            .authorize_restore_attested(
                &single.recovery,
                &single.recovery_evidence,
                &single.approvals,
                &single.recovery_peer,
                &single.lifeline,
            )
            .expect_err("single failure domain"),
        RescueError::Contract
    );
}
