use crate::{
    BoundaryIdentity, EmergencyAction, EmergencyAuthorizationV1, EmergencyRequestV1,
    LifelineEvidence, SignedEmergencyAuthorization, SignedLifelineEvidence,
    canonical_emergency_authorization, canonical_lifeline_evidence, model::PeerIdentity,
    sha256_digest,
};
use ed25519_dalek::{Signer, SigningKey};

pub fn boundary(uid: u32, name: &str, key: &str, executable: &str) -> BoundaryIdentity {
    BoundaryIdentity {
        uid,
        gid: uid,
        socket_path: format!("/run/crowsi/{name}.sock"),
        signing_key_id: key.into(),
        executable_sha256: sha256_digest(executable.as_bytes()),
        network_namespace_id: format!("netns:{name}"),
        ipc_namespace_id: format!("ipcns:{name}"),
    }
}

pub(super) fn lifeline(now: i64, signer: &SigningKey) -> SignedLifelineEvidence {
    let document = LifelineEvidence {
        schema: "crowsi://rescue/lifeline-evidence/v1".into(),
        issuer_key_id: "lifeline-monitor".into(),
        interface_id: "lifeline:physical-nic-1".into(),
        route_table_id: "route-table:rescue-only".into(),
        health_check_id: "health:001".into(),
        tested_at_epoch_s: now - 10,
        expires_at_epoch_s: now + 50,
    };
    SignedLifelineEvidence {
        signature_hex: hex::encode(
            signer
                .sign(&canonical_lifeline_evidence(&document))
                .to_bytes(),
        ),
        document,
    }
}

pub(super) fn peer(boundary: &BoundaryIdentity) -> PeerIdentity {
    PeerIdentity {
        uid: boundary.uid,
        gid: boundary.gid,
        executable_sha256: boundary.executable_sha256.clone(),
        network_namespace_id: boundary.network_namespace_id.clone(),
        ipc_namespace_id: boundary.ipc_namespace_id.clone(),
    }
}

pub(super) fn emergency(
    now: i64,
    signer: &SigningKey,
) -> (EmergencyRequestV1, SignedEmergencyAuthorization) {
    let request = EmergencyRequestV1 {
        schema: "crowsi://rescue/emergency-request/v1".into(),
        request_id: "emergency:001".into(),
        incident_id: "incident:001".into(),
        action: EmergencyAction::ContainAsset,
        resource: "crowsi://assets/server-01".into(),
        body_sha256: sha256_digest(b"contain"),
    };
    let document = EmergencyAuthorizationV1 {
        schema: "crowsi://rescue/emergency-authorization/v1".into(),
        issuer_key_id: "rescue-authority".into(),
        audience: "crowsi-rescue-console".into(),
        subject_id: "subject:on-call".into(),
        assurance: "hardware-bound-step-up".into(),
        user_verification: true,
        request_id: request.request_id.clone(),
        incident_id: request.incident_id.clone(),
        action: request.action,
        resource: request.resource.clone(),
        body_sha256: request.body_sha256.clone(),
        nonce: "nonce:emergency:001".into(),
        issued_at_epoch_s: now - 1,
        expires_at_epoch_s: now + 30,
    };
    let authorization = SignedEmergencyAuthorization {
        signature_hex: hex::encode(
            signer
                .sign(&canonical_emergency_authorization(&document))
                .to_bytes(),
        ),
        document,
    };
    (request, authorization)
}
