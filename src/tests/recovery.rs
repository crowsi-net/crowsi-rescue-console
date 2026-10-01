use super::support::fixture;
use crate::RescueError;

#[test]
fn restore_requires_two_distinct_hardware_bound_approvers() {
    let mut fixture = fixture();
    let ticket = fixture
        .console
        .authorize_restore_attested(
            &fixture.recovery,
            &fixture.recovery_evidence,
            &fixture.approvals,
            &fixture.recovery_peer,
            &fixture.lifeline,
        )
        .expect("two-person recovery");
    assert_eq!(ticket.approver_count, 2);
    assert_eq!(ticket.resource, fixture.recovery.resource);
}

#[test]
fn same_subject_or_key_cannot_satisfy_two_person_control() {
    let mut fixture = fixture();
    fixture.approvals[1].subject_id = fixture.approvals[0].subject_id.clone();
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
            .expect_err("same subject"),
        RescueError::TwoPersonControl
    );
}

#[test]
fn recovery_nonce_is_consumed_once() {
    let mut fixture = fixture();
    fixture
        .console
        .authorize_restore_attested(
            &fixture.recovery,
            &fixture.recovery_evidence,
            &fixture.approvals,
            &fixture.recovery_peer,
            &fixture.lifeline,
        )
        .expect("first recovery");
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
            .expect_err("replay"),
        RescueError::Replay
    );
}
