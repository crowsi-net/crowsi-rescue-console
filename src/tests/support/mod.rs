#![allow(dead_code)]

mod factory;
mod proof_factory;
mod recovery_factory;

use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt};

use crate::{
    EmergencyRequestV1, RecoveryApproval, RecoveryProofBundleV1, RecoveryProofTrust,
    RecoveryRequestV1, RescueConsole, RescueLedger, RescueTrust, SeparationConfig,
    SignedEmergencyAuthorization, SignedLifelineEvidence, clock::TestClock, model::PeerIdentity,
};
use ed25519_dalek::SigningKey;
use tempfile::TempDir;

pub use factory::boundary;
use factory::{emergency, lifeline, peer};
use proof_factory::proof;
use recovery_factory::recovery;

pub struct Fixture {
    pub console: RescueConsole<TestClock>,
    pub emergency: EmergencyRequestV1,
    pub emergency_authorization: SignedEmergencyAuthorization,
    pub recovery: RecoveryRequestV1,
    pub recovery_evidence: RecoveryProofBundleV1,
    pub approvals: Vec<RecoveryApproval>,
    pub rescue_peer: PeerIdentity,
    pub recovery_peer: PeerIdentity,
    pub lifeline: SignedLifelineEvidence,
    pub _root: TempDir,
}

pub fn fixture() -> Fixture {
    let root = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("private state directory");
    let normal = boundary(2001, "normal", "normal-key", "normal-exe");
    let rescue = boundary(3001, "rescue", "rescue-key", "rescue-exe");
    let recovery_boundary = boundary(4001, "recovery", "recovery-key", "recovery-exe");
    let config = SeparationConfig::new(&normal, rescue.clone(), recovery_boundary.clone())
        .expect("separated boundaries");
    let rescue_signer = SigningKey::from_bytes(&[11; 32]);
    let recovery_a = SigningKey::from_bytes(&[12; 32]);
    let recovery_b = SigningKey::from_bytes(&[13; 32]);
    let lifeline_signer = SigningKey::from_bytes(&[14; 32]);
    let receipt_attestor = SigningKey::from_bytes(&[15; 32]);
    let readback_attestor = SigningKey::from_bytes(&[16; 32]);
    let recovery_keys = BTreeMap::from([
        ("recovery-a".into(), recovery_a.verifying_key().to_bytes()),
        ("recovery-b".into(), recovery_b.verifying_key().to_bytes()),
    ]);
    let trust = RescueTrust::new(
        "rescue-authority",
        rescue_signer.verifying_key().to_bytes(),
        "lifeline-monitor",
        lifeline_signer.verifying_key().to_bytes(),
        RecoveryProofTrust {
            receipt_key_id: "pep-receipt-attestor".into(),
            receipt_public_key: receipt_attestor.verifying_key().to_bytes(),
            readback_key_id: "independent-readback-attestor".into(),
            readback_public_key: readback_attestor.verifying_key().to_bytes(),
        },
        recovery_keys,
    )
    .expect("separate trust roots");
    let now = 1_800_000_000;
    let (emergency, emergency_authorization) = emergency(now, &rescue_signer);
    let recovery_evidence = proof(now, &emergency, &receipt_attestor, &readback_attestor);
    let (recovery, approvals) = recovery(
        now,
        &emergency,
        &recovery_evidence,
        &recovery_a,
        &recovery_b,
    );
    let ledger = RescueLedger::open(root.path().join("rescue.sqlite3")).expect("ledger");
    let console = RescueConsole::new(config, trust, ledger, TestClock::new(now));
    let rescue_peer = peer(&rescue);
    let recovery_peer = peer(&recovery_boundary);
    let lifeline = lifeline(now, &lifeline_signer);
    Fixture {
        console,
        emergency,
        emergency_authorization,
        recovery,
        recovery_evidence,
        approvals,
        rescue_peer,
        recovery_peer,
        lifeline,
        _root: root,
    }
}
