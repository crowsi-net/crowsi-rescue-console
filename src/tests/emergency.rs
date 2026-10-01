use super::support::fixture;
use crate::{EmergencyAction, RescueError};
use std::os::unix::net::UnixStream;

#[test]
fn emergency_console_allows_only_exact_contain_or_revoke() {
    let mut fixture = fixture();
    let ticket = fixture
        .console
        .authorize_emergency_attested(
            &fixture.emergency,
            &fixture.emergency_authorization,
            &fixture.rescue_peer,
            &fixture.lifeline,
        )
        .expect("emergency authorization");
    assert_eq!(ticket.action, EmergencyAction::ContainAsset);
    assert_eq!(ticket.resource, fixture.emergency.resource);
}

#[test]
fn normal_os_identity_cannot_enter_rescue_socket() {
    let mut fixture = fixture();
    fixture.rescue_peer.uid = 2001;
    assert_eq!(
        fixture
            .console
            .authorize_emergency_attested(
                &fixture.emergency,
                &fixture.emergency_authorization,
                &fixture.rescue_peer,
                &fixture.lifeline,
            )
            .expect_err("wrong identity"),
        RescueError::PeerAttestation
    );
}

#[test]
fn invalid_or_stale_lifeline_fails_closed() {
    let mut fixture = fixture();
    fixture.lifeline.signature_hex = "00".repeat(64);
    assert_eq!(
        fixture
            .console
            .authorize_emergency_attested(
                &fixture.emergency,
                &fixture.emergency_authorization,
                &fixture.rescue_peer,
                &fixture.lifeline,
            )
            .expect_err("lifeline"),
        RescueError::Lifeline
    );
}

#[test]
fn extreme_lifeline_and_authorization_times_fail_without_overflow() {
    let mut lifeline = fixture();
    lifeline.lifeline.document.tested_at_epoch_s = i64::MIN;
    assert_eq!(
        lifeline
            .console
            .authorize_emergency_attested(
                &lifeline.emergency,
                &lifeline.emergency_authorization,
                &lifeline.rescue_peer,
                &lifeline.lifeline,
            )
            .expect_err("unbounded lifeline age"),
        RescueError::Lifeline
    );

    let mut fixture = fixture();
    fixture.emergency_authorization.document.issued_at_epoch_s = i64::MIN;
    fixture.emergency_authorization.document.expires_at_epoch_s = i64::MAX;
    assert_eq!(
        fixture
            .console
            .authorize_emergency_attested(
                &fixture.emergency,
                &fixture.emergency_authorization,
                &fixture.rescue_peer,
                &fixture.lifeline,
            )
            .expect_err("unbounded authorization"),
        RescueError::Time
    );
}

#[test]
fn denied_kernel_peer_credentials_never_become_rescue_trust() {
    let (client, _server) = UnixStream::pair().expect("socket pair");
    match crate::peer::attest_unix_peer(&client) {
        Ok(_) => {}
        Err(error) => assert_eq!(error, RescueError::PeerAttestation),
    }
}
